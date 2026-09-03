"""
Tests for stubsmith.replay - hermetic, no network calls permitted.

Covers:
- Full round trip: hand-built bundle, matching requests call, status/headers/body/.json()
- params= fingerprints identically to the capture path (PreparedRequest URL)
- Collision: two endpoints sharing the same fingerprint hash each serve their own body
- Miss raises StubNotFound; no network call is attempted
- Session.send is restored after normal context exit and after exception inside with
- Deterministic variant selection with a multi-variant stub
- Hop-by-hop headers are stripped from the stub response
- Bundle loading: explicit path, $STUBSMITH_BUNDLE, default .stubsmith/bundle.json,
  and clear errors when absent or malformed
- on_miss validation: non-"strict" values raise ValueError immediately
"""

from __future__ import annotations

import json
import os
import pathlib
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest
import requests
import requests.sessions

import stubsmith
from stubsmith.privacy.fingerprint import fingerprint as _fp
from stubsmith.replay import (
    ReplayContext,
    StubNotFound,
    _build_index,
    _find_bundle_upward,
    _resolve_bundle,
    _select_variant,
    replay,
)


# ---------------------------------------------------------------------------
# Bundle construction helpers
# ---------------------------------------------------------------------------

_DOMAIN = "api.example.com"
_BASE_URL = f"http://{_DOMAIN}"


def _variant(
    status: int,
    body: str,
    *,
    count: int = 1,
    duration_ms: int = 5,
    headers: Dict[str, str] = None,
) -> Dict[str, Any]:
    return {
        "status": status,
        "count": count,
        "duration_ms": duration_ms,
        "headers": headers or {"content-type": "application/json"},
        "body": body,
    }


def _stub(fingerprint: str, variants: List[Dict], *, key_paths: List[str] = None) -> Dict[str, Any]:
    return {
        "fingerprint": fingerprint,
        "key_paths": key_paths or [],
        "field_rules": [],
        "degraded": False,
        "variants": variants,
    }


def _endpoint(
    method: str,
    path_template: str,
    stubs: List[Dict],
    *,
    domain: str = _DOMAIN,
    fingerprint_value_paths: List[str] = None,
    is_dynamic: bool = False,
) -> Dict[str, Any]:
    return {
        "domain": domain,
        "method": method,
        "path_template": path_template,
        "is_dynamic": is_dynamic,
        "fingerprint_value_paths": fingerprint_value_paths or [],
        "stubs": stubs,
    }


def _bundle(*endpoints: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "ok": True,
        "version": 1,
        "cursor": "0",
        "generated_at": "2024-01-01T00:00:00Z",
        "endpoints": list(endpoints),
    }


# Pre-computed fingerprints (verified against the capture path's fingerprint()).
# body-less GET: _fp("", "", "") == "fc552c95a0bb0d3e"
_FP_EMPTY_GET = _fp("", "", "")
# GET with ?status=shipped query param
_FP_GET_WITH_PARAM = _fp("", "status=shipped", "")
# POST with JSON body {"action": "pay", "amount": 100}
_FP_POST_JSON = _fp('{"action":"pay","amount":100}', "", "application/json")


# ---------------------------------------------------------------------------
# Full round trip
# ---------------------------------------------------------------------------

class TestRoundTrip:

    def test_status_headers_body_json(self):
        """Happy path: matching GET returns recorded status, headers, body, .json()."""
        bundle = _bundle(
            _endpoint(
                "GET",
                "/api/users/{id}",
                [_stub(_FP_EMPTY_GET, [_variant(200, '{"id": 42, "name": "Alice"}',
                                               headers={"content-type": "application/json"})])],
                is_dynamic=True,
            )
        )
        with replay(bundle=bundle):
            resp = requests.get(f"{_BASE_URL}/api/users/42")

        assert resp.status_code == 200
        assert resp.json() == {"id": 42, "name": "Alice"}
        assert resp.headers["content-type"] == "application/json"

    def test_elapsed_comes_from_bundle(self):
        """response.elapsed is populated from the variant's duration_ms."""
        bundle = _bundle(
            _endpoint(
                "GET",
                "/api/users/{id}",
                [_stub(_FP_EMPTY_GET, [_variant(200, '{}', duration_ms=123)])],
                is_dynamic=True,
            )
        )
        with replay(bundle=bundle):
            resp = requests.get(f"{_BASE_URL}/api/users/1")

        assert resp.elapsed.total_seconds() == pytest.approx(0.123, abs=1e-6)

    def test_request_is_set_on_response(self):
        """response.request points to the PreparedRequest, enabling raise_for_status."""
        bundle = _bundle(
            _endpoint(
                "GET",
                "/api/users/{id}",
                [_stub(_FP_EMPTY_GET, [_variant(200, "{}")])],
                is_dynamic=True,
            )
        )
        with replay(bundle=bundle):
            resp = requests.get(f"{_BASE_URL}/api/users/7")

        assert resp.request is not None
        assert "api.example.com" in resp.request.url

    def test_raise_for_status_works_on_4xx(self):
        """raise_for_status() message must include the URL and reason phrase."""
        fp_404 = _fp("", "", "")
        bundle = _bundle(
            _endpoint(
                "GET",
                "/api/items/{id}",
                [_stub(fp_404, [_variant(404, '{"error":"not found"}',
                                         headers={"content-type": "application/json"})])],
                is_dynamic=True,
            )
        )
        with replay(bundle=bundle):
            resp = requests.get(f"{_BASE_URL}/api/items/99")

        assert resp.status_code == 404
        with pytest.raises(requests.exceptions.HTTPError) as exc_info:
            resp.raise_for_status()
        msg = str(exc_info.value)
        # Without response.url the message renders "None for url: None".
        assert "api.example.com" in msg, (
            f"URL missing from raise_for_status() message: {msg!r}"
        )
        # Without response.reason the message renders "404 None for url: …".
        assert "Not Found" in msg, (
            f"Reason phrase missing from raise_for_status() message: {msg!r}"
        )

    def test_post_with_json_body(self):
        """POST with a JSON body is matched by its structural fingerprint."""
        body_str = '{"action":"pay","amount":100}'
        bundle = _bundle(
            _endpoint(
                "POST",
                "/api/payments",
                [_stub(_FP_POST_JSON, [_variant(201, '{"id":"pay-001"}',
                                                headers={"content-type": "application/json"})])],
            )
        )
        with replay(bundle=bundle):
            resp = requests.post(
                f"{_BASE_URL}/api/payments",
                json={"action": "pay", "amount": 100},
            )

        assert resp.status_code == 201
        assert resp.json() == {"id": "pay-001"}


# ---------------------------------------------------------------------------
# params= fingerprint identity with the capture path
# ---------------------------------------------------------------------------

class TestParamsFingerprint:
    """params= are merged into the PreparedRequest URL before fingerprinting.

    The capture path had a bug (fixed in 0.6.0) where it read the pre-prepare
    URL and missed query names entirely.  Replay patches Session.send which
    receives the PreparedRequest - the final URL is already there.  These tests
    prove the fingerprints match.
    """

    def test_params_dict_matches_same_as_querystring_in_url(self):
        """requests.get(url, params={"status": "shipped"}) must match a stub
        keyed on fingerprint("", "status=shipped", "")."""
        bundle = _bundle(
            _endpoint(
                "GET",
                "/api/orders",
                [_stub(_FP_GET_WITH_PARAM, [_variant(200, '{"orders": []}',
                                                      headers={"content-type": "application/json"})])],
            )
        )
        with replay(bundle=bundle):
            # params= form - requests merges into URL during PreparedRequest.prepare()
            resp = requests.get(f"{_BASE_URL}/api/orders", params={"status": "shipped"})

        assert resp.status_code == 200

    def test_params_in_url_string_matches(self):
        """The same stub must match when params are embedded in the URL string."""
        bundle = _bundle(
            _endpoint(
                "GET",
                "/api/orders",
                [_stub(_FP_GET_WITH_PARAM, [_variant(200, '{"orders": []}',
                                                      headers={"content-type": "application/json"})])],
            )
        )
        with replay(bundle=bundle):
            resp = requests.get(f"{_BASE_URL}/api/orders?status=shipped")

        assert resp.status_code == 200

    def test_params_dict_and_url_string_produce_same_prepared_url(self):
        """params={"status": "shipped"} and ?status=shipped must produce the same
        prepared URL - and therefore the same fingerprint - in the replay hook.

        Checks the actual PreparedRequest.url from each form, not a static
        fingerprint comparison, so a regression in requests' params merging
        or the replay hook's URL parsing would be caught.
        """
        from urllib.parse import urlparse, parse_qs

        req_params = requests.Request(
            "GET", f"{_BASE_URL}/api/orders", params={"status": "shipped"}
        ).prepare()
        req_url = requests.Request(
            "GET", f"{_BASE_URL}/api/orders?status=shipped"
        ).prepare()

        qs_params = urlparse(req_params.url).query
        qs_url = urlparse(req_url.url).query

        # Both must carry the same query parameter name so the fingerprint matches.
        assert parse_qs(qs_params) == parse_qs(qs_url), (
            f"params= form produced {qs_params!r}, URL form produced {qs_url!r}"
        )
        # Fingerprints must also agree.
        fp_from_params = _fp("", qs_params, "")
        fp_from_url = _fp("", qs_url, "")
        assert fp_from_params == fp_from_url == _FP_GET_WITH_PARAM

    def test_no_params_stub_does_not_match_params_request(self):
        """A stub keyed on the no-params fingerprint must NOT match a request with params."""
        bundle = _bundle(
            _endpoint(
                "GET",
                "/api/orders",
                # Stub for the no-params version (different fingerprint)
                [_stub(_FP_EMPTY_GET, [_variant(200, "{}")])],
            )
        )
        with pytest.raises(StubNotFound) as exc_info:
            with replay(bundle=bundle):
                requests.get(f"{_BASE_URL}/api/orders", params={"status": "shipped"})

        # The fingerprint in the error must be the with-params one
        assert exc_info.value.fingerprint == _FP_GET_WITH_PARAM


# ---------------------------------------------------------------------------
# Collision: two endpoints share the same hash, each serves its own body
# ---------------------------------------------------------------------------

class TestFingerprintCollision:
    """Proves that keying on (domain, method, path_template, fingerprint) prevents
    hash collisions across endpoints.

    Every body-less GET produces the same structural fingerprint
    (fc552c95a0bb0d3e, verified empirically).  Keying on the hash alone
    would serve the first endpoint's body for all subsequent callers - this
    test would fail if the key were collapsed to just the fingerprint.
    """

    def test_two_endpoints_same_hash_each_serves_own_body(self):
        """GET /api/users/{id} and GET /api/products both hash to fc552c95a0bb0d3e.
        Each must return its own recorded body."""
        assert _FP_EMPTY_GET == "fc552c95a0bb0d3e", (
            "Pre-condition: both body-less GETs must share this hash"
        )

        bundle = _bundle(
            _endpoint(
                "GET",
                "/api/users/{id}",
                [_stub(_FP_EMPTY_GET, [_variant(200, '{"type":"user"}',
                                               headers={"content-type": "application/json"})])],
                is_dynamic=True,
            ),
            _endpoint(
                "GET",
                "/api/products",
                [_stub(_FP_EMPTY_GET, [_variant(200, '{"type":"product"}',
                                                headers={"content-type": "application/json"})])],
            ),
        )

        with replay(bundle=bundle):
            resp_user = requests.get(f"{_BASE_URL}/api/users/1")
            resp_product = requests.get(f"{_BASE_URL}/api/products")

        assert resp_user.json() == {"type": "user"}
        assert resp_product.json() == {"type": "product"}

    def test_index_contains_both_endpoints_under_same_hash(self):
        """_build_index must not collapse entries with the same fingerprint."""
        bundle = _bundle(
            _endpoint(
                "GET",
                "/api/users/{id}",
                [_stub(_FP_EMPTY_GET, [_variant(200, '{"type":"user"}')])]
            ),
            _endpoint(
                "GET",
                "/api/products",
                [_stub(_FP_EMPTY_GET, [_variant(200, '{"type":"product"}')])]
            ),
        )
        index, _, _, _ = _build_index(bundle)
        key_user = (_DOMAIN, "GET", "/api/users/{id}", _FP_EMPTY_GET)
        key_prod = (_DOMAIN, "GET", "/api/products", _FP_EMPTY_GET)
        assert key_user in index
        assert key_prod in index
        # Distinct entries - not the same dict object
        assert index[key_user] is not index[key_prod]


# ---------------------------------------------------------------------------
# Miss raises StubNotFound; no network call attempted
# ---------------------------------------------------------------------------

class TestMissStrict:

    def test_miss_raises_stub_not_found(self):
        """A request that matches no stub must raise StubNotFound."""
        bundle = _bundle(
            _endpoint(
                "GET",
                "/api/users/{id}",
                [_stub(_FP_EMPTY_GET, [_variant(200, "{}")])],
                is_dynamic=True,
            )
        )
        with pytest.raises(StubNotFound) as exc_info:
            with replay(bundle=bundle):
                # This POST fingerprint is not in the bundle
                requests.post(f"{_BASE_URL}/api/users/1", json={"x": 1})

        err = exc_info.value
        assert err.method == "POST"
        assert "/api/users" in err.path_template
        assert err.fingerprint  # non-empty

    def test_miss_error_message_contains_method_and_path(self):
        """StubNotFound message must name the method and path template."""
        bundle = _bundle()   # empty bundle - everything misses
        with pytest.raises(StubNotFound) as exc_info:
            with replay(bundle=bundle):
                requests.get(f"{_BASE_URL}/api/things/123")

        msg = str(exc_info.value)
        assert "GET" in msg
        assert "/api/things" in msg

    def test_no_network_call_on_miss(self):
        """A miss must raise StubNotFound; the real Session.send must never be called.

        Proves the absolute no-network guarantee: the underlying transport
        is replaced, so even if replay raises, the original send (which
        would open a socket) is never invoked.
        """
        import requests.sessions as _rs

        original_send = _rs.Session.send
        network_send_called = []

        def _spy_send(session, request, **kwargs):
            network_send_called.append(request.url)
            return original_send(session, request, **kwargs)

        # Install the spy BEFORE starting replay, so replay wraps the spy.
        # After replay.start(), Session.send == replay's stub, not the spy.
        # The spy is only reachable if replay's stub falls through - which it
        # must never do.
        bundle = _bundle()   # nothing matches

        ctx = ReplayContext(bundle)
        # Manually save original and set the spy to verify it's never reached.
        _rs.Session.send = _spy_send
        try:
            ctx._original_send = _spy_send
            ctx._active = True

            with pytest.raises(StubNotFound):
                ctx._handle(
                    _make_prepared_request("GET", f"{_BASE_URL}/api/missing")
                )
        finally:
            _rs.Session.send = original_send

        assert network_send_called == [], (
            "Session.send (and therefore the network) must never be called on a miss"
        )

    def test_no_network_call_on_match_either(self):
        """Even on a successful match, the original Session.send is never called."""
        network_send_called = []

        bundle = _bundle(
            _endpoint("GET", "/api/ping", [_stub(_FP_EMPTY_GET, [_variant(200, "{}")])]),
        )

        ctx = replay(bundle=bundle)
        original = ctx._original_send  # saved at start() time

        original_send_ref = requests.sessions.Session.send

        # Capture whether the original_send that replay saved is ever invoked.
        call_log: list = []
        original_send = ctx._original_send  # None until start() called

        with ctx:
            # After entering, ctx._original_send holds the pre-replay send.
            captured_original = ctx._original_send

            patched_original = MagicMock(side_effect=AssertionError("real send called"))
            ctx._original_send = patched_original

            resp = requests.get(f"{_BASE_URL}/api/ping")
            assert resp.status_code == 200

            patched_original.assert_not_called()
            # Restore so stop() works cleanly
            ctx._original_send = captured_original


# ---------------------------------------------------------------------------
# Session.send restoration
# ---------------------------------------------------------------------------

class TestRestoration:

    def test_send_restored_after_normal_exit(self):
        """After the with block, Session.send must be the same object as before."""
        import requests.sessions as _rs
        original = _rs.Session.send

        bundle = _bundle(
            _endpoint("GET", "/api/ping", [_stub(_FP_EMPTY_GET, [_variant(200, "{}")])]),
        )
        with replay(bundle=bundle):
            pass

        assert _rs.Session.send is original

    def test_send_restored_after_exception_in_body(self):
        """Session.send must be restored even when the with body raises an exception."""
        import requests.sessions as _rs
        original = _rs.Session.send

        bundle = _bundle(
            _endpoint("GET", "/api/ping", [_stub(_FP_EMPTY_GET, [_variant(200, "{}")])]),
        )
        with pytest.raises(RuntimeError, match="test body error"):
            with replay(bundle=bundle):
                raise RuntimeError("test body error")

        assert _rs.Session.send is original

    def test_explicit_start_stop_restores(self):
        """Explicit start() / stop() must restore Session.send."""
        import requests.sessions as _rs
        original = _rs.Session.send

        ctx = replay(bundle=_bundle())
        ctx.start()
        assert _rs.Session.send is not original
        ctx.stop()
        assert _rs.Session.send is original

    def test_stop_idempotent(self):
        """Calling stop() twice must not raise."""
        import requests.sessions as _rs
        original = _rs.Session.send

        ctx = replay(bundle=_bundle())
        ctx.start()
        ctx.stop()
        ctx.stop()   # second call must be a no-op
        assert _rs.Session.send is original


# ---------------------------------------------------------------------------
# Variant selection
# ---------------------------------------------------------------------------

class TestVariantSelection:

    def test_highest_count_wins(self):
        """When two variants differ in count, the one with the higher count is served."""
        variants = [
            _variant(500, '{"error":"oops"}', count=5),
            _variant(200, '{"ok":true}', count=42),
        ]
        selected = _select_variant(variants)
        assert selected["status"] == 200

    def test_tie_broken_by_lowest_status(self):
        """When counts are equal, the lowest status code wins (stable, happy-path bias)."""
        variants = [
            _variant(404, '{"error":"not found"}', count=10),
            _variant(200, '{"ok":true}', count=10),
            _variant(422, '{"error":"bad input"}', count=10),
        ]
        selected = _select_variant(variants)
        assert selected["status"] == 200

    def test_empty_variants_returns_none(self):
        assert _select_variant([]) is None

    def test_single_variant_is_always_selected(self):
        v = _variant(201, '{"created":true}', count=1)
        assert _select_variant([v]) is v

    def test_multi_variant_stub_returns_deterministically(self):
        """Calling _select_variant twice must return the same object."""
        variants = [
            _variant(200, '{"ok":true}', count=7),
            _variant(400, '{"error":"bad"}', count=3),
        ]
        a = _select_variant(variants)
        b = _select_variant(variants)
        assert a["status"] == b["status"] == 200

    def test_multi_variant_bundle_round_trip(self):
        """A stub with two status variants serves the highest-count one by default."""
        fp = _FP_EMPTY_GET
        bundle = _bundle(
            _endpoint(
                "GET",
                "/api/items",
                [_stub(fp, [
                    _variant(200, '{"items":[]}', count=100),
                    _variant(503, '{"error":"down"}', count=2),
                ])],
            )
        )
        with replay(bundle=bundle):
            resp = requests.get(f"{_BASE_URL}/api/items")

        assert resp.status_code == 200
        assert resp.json() == {"items": []}


# ---------------------------------------------------------------------------
# Hop-by-hop header stripping
# ---------------------------------------------------------------------------

class TestHopByHopStripping:

    def test_content_length_stripped(self):
        """content-length must not appear in the stub response headers."""
        bundle = _bundle(
            _endpoint(
                "GET",
                "/api/data",
                [_stub(_FP_EMPTY_GET, [_variant(
                    200,
                    '{"x":1}',
                    headers={
                        "content-type": "application/json",
                        "content-length": "7",
                        "transfer-encoding": "chunked",
                        "x-custom": "keep-me",
                    },
                )])],
            )
        )
        with replay(bundle=bundle):
            resp = requests.get(f"{_BASE_URL}/api/data")

        assert "content-length" not in {k.lower() for k in resp.headers}
        assert "transfer-encoding" not in {k.lower() for k in resp.headers}

    def test_non_hop_headers_are_kept(self):
        """Custom application headers must pass through unchanged."""
        bundle = _bundle(
            _endpoint(
                "GET",
                "/api/data",
                [_stub(_FP_EMPTY_GET, [_variant(
                    200,
                    "{}",
                    headers={
                        "content-type": "application/json",
                        "x-request-id": "abc-123",
                        "content-length": "2",
                    },
                )])],
            )
        )
        with replay(bundle=bundle):
            resp = requests.get(f"{_BASE_URL}/api/data")

        assert resp.headers["x-request-id"] == "abc-123"
        assert "content-length" not in {k.lower() for k in resp.headers}


# ---------------------------------------------------------------------------
# Bundle loading
# ---------------------------------------------------------------------------

class TestBundleLoading:

    def test_explicit_path(self, tmp_path):
        """Passing an explicit filesystem path must load and parse the bundle."""
        data = _bundle(
            _endpoint("GET", "/api/ping", [_stub(_FP_EMPTY_GET, [_variant(200, '{"ok":true}')])])
        )
        p = tmp_path / "my_bundle.json"
        p.write_text(json.dumps(data))

        with replay(bundle=str(p)):
            resp = requests.get(f"{_BASE_URL}/api/ping")

        assert resp.status_code == 200

    def test_explicit_pathlib_path(self, tmp_path):
        """pathlib.Path is accepted as the bundle argument."""
        data = _bundle(
            _endpoint("GET", "/api/ping", [_stub(_FP_EMPTY_GET, [_variant(200, '{"ok":true}')])])
        )
        p = tmp_path / "bundle.json"
        p.write_text(json.dumps(data))

        with replay(bundle=p):
            resp = requests.get(f"{_BASE_URL}/api/ping")

        assert resp.status_code == 200

    def test_explicit_dict(self):
        """Passing a pre-parsed dict must work without touching the filesystem."""
        data = _bundle(
            _endpoint("GET", "/api/ping", [_stub(_FP_EMPTY_GET, [_variant(200, '{"ok":true}')])])
        )
        with replay(bundle=data):
            resp = requests.get(f"{_BASE_URL}/api/ping")

        assert resp.status_code == 200

    def test_env_var_stubsmith_bundle(self, tmp_path, monkeypatch):
        """$STUBSMITH_BUNDLE overrides the default path when bundle=None."""
        data = _bundle(
            _endpoint("GET", "/api/ping", [_stub(_FP_EMPTY_GET, [_variant(200, '{"ok":true}')])])
        )
        p = tmp_path / "env_bundle.json"
        p.write_text(json.dumps(data))
        monkeypatch.setenv("STUBSMITH_BUNDLE", str(p))

        with replay():   # no explicit bundle
            resp = requests.get(f"{_BASE_URL}/api/ping")

        assert resp.status_code == 200

    def test_default_path_stubsmith_bundle_json(self, tmp_path, monkeypatch):
        """With no argument and no env var, .stubsmith/bundle.json is used."""
        data = _bundle(
            _endpoint("GET", "/api/ping", [_stub(_FP_EMPTY_GET, [_variant(200, '{"ok":true}')])])
        )
        bundle_dir = tmp_path / ".stubsmith"
        bundle_dir.mkdir()
        (bundle_dir / "bundle.json").write_text(json.dumps(data))

        monkeypatch.delenv("STUBSMITH_BUNDLE", raising=False)
        monkeypatch.chdir(tmp_path)

        with replay():
            resp = requests.get(f"{_BASE_URL}/api/ping")

        assert resp.status_code == 200

    def test_absent_bundle_raises_file_not_found(self, tmp_path, monkeypatch):
        """When no bundle can be found, FileNotFoundError must be raised clearly."""
        monkeypatch.delenv("STUBSMITH_BUNDLE", raising=False)
        monkeypatch.chdir(tmp_path)   # tmp_path has no .stubsmith/bundle.json

        with pytest.raises(FileNotFoundError, match="stubsmith pull"):
            replay()

    def test_malformed_json_raises_value_error(self, tmp_path):
        """A file that is not valid JSON must raise ValueError with a clear message."""
        p = tmp_path / "bad.json"
        p.write_text("this is not json {{{")

        with pytest.raises(ValueError, match="not valid JSON"):
            replay(bundle=str(p))

    def test_non_object_json_raises_value_error(self, tmp_path):
        """A JSON file whose root is an array (not an object) must raise ValueError."""
        p = tmp_path / "array.json"
        p.write_text("[1, 2, 3]")

        with pytest.raises(ValueError, match="JSON object"):
            replay(bundle=str(p))

    def test_env_var_takes_precedence_over_default(self, tmp_path, monkeypatch):
        """$STUBSMITH_BUNDLE must be used even when .stubsmith/bundle.json exists."""
        env_bundle = _bundle(
            _endpoint("GET", "/api/env", [_stub(_FP_EMPTY_GET, [_variant(200, '{"source":"env"}')])])
        )
        default_bundle = _bundle(
            _endpoint("GET", "/api/default", [_stub(_FP_EMPTY_GET, [_variant(200, '{"source":"default"}')])])
        )

        env_path = tmp_path / "env.json"
        env_path.write_text(json.dumps(env_bundle))

        bundle_dir = tmp_path / ".stubsmith"
        bundle_dir.mkdir()
        (bundle_dir / "bundle.json").write_text(json.dumps(default_bundle))

        monkeypatch.setenv("STUBSMITH_BUNDLE", str(env_path))
        monkeypatch.chdir(tmp_path)

        with replay():
            resp = requests.get(f"{_BASE_URL}/api/env")

        assert resp.json() == {"source": "env"}


# ---------------------------------------------------------------------------
# Bundle upward search (_find_bundle_upward / step-3 resolution)
# ---------------------------------------------------------------------------

class TestBundleUpwardSearch:
    """Tests for the upward-directory-walk bundle discovery (step 3)."""

    def _write_bundle(self, directory: pathlib.Path) -> pathlib.Path:
        """Write a minimal valid bundle under *directory*/.stubsmith/bundle.json."""
        bundle_dir = directory / ".stubsmith"
        bundle_dir.mkdir(parents=True, exist_ok=True)
        data = _bundle(
            _endpoint("GET", "/api/ping", [_stub(_FP_EMPTY_GET, [_variant(200, '{"ok":true}')])])
        )
        p = bundle_dir / "bundle.json"
        p.write_text(json.dumps(data))
        return p

    # --- _find_bundle_upward unit tests ---

    def test_found_in_current_directory(self, tmp_path):
        """Bundle located in the start directory itself is found immediately."""
        self._write_bundle(tmp_path)
        result = _find_bundle_upward(tmp_path)
        assert result is not None
        assert result == tmp_path / ".stubsmith" / "bundle.json"

    def test_found_several_levels_up(self, tmp_path):
        """Bundle located two levels above the start directory is found."""
        self._write_bundle(tmp_path)
        deep = tmp_path / "a" / "b"
        deep.mkdir(parents=True)
        result = _find_bundle_upward(deep)
        assert result is not None
        assert result == tmp_path / ".stubsmith" / "bundle.json"

    def test_returns_none_when_not_found(self, tmp_path):
        """Returns None when no .stubsmith/bundle.json exists within the project boundary.

        Creates an isolated directory tree with a pyproject.toml at its root
        (acting as the project boundary) and no bundle anywhere inside.  The
        walk must stop at the boundary and return None unconditionally.
        """
        # tmp_path acts as the project root - boundary marker stops the walk here.
        (tmp_path / "pyproject.toml").touch()
        deep = tmp_path / "src" / "pkg"
        deep.mkdir(parents=True)

        result = _find_bundle_upward(deep)

        # The walk stopped at tmp_path (pyproject.toml boundary) without finding
        # a bundle.  None is the only correct answer.
        assert result is None

    def test_stops_at_project_boundary(self, tmp_path):
        """The walk stops at the first .git / pyproject.toml directory.

        A bundle placed *above* the project boundary must not be found; the
        walk must terminate at the boundary and return None rather than
        continuing up to a stray bundle outside the project.
        """
        # Layout (each is an ancestor of the next):
        #   tmp_path/.stubsmith/bundle.json   ← bundle above the boundary
        #   tmp_path/project/                  ← project root (.git = boundary)
        #   tmp_path/project/sub/              ← start directory
        #
        # The bundle at tmp_path is a direct ancestor of start, so the walk
        # WOULD reach it if the boundary check were absent.
        outer_bundle_dir = tmp_path / ".stubsmith"
        outer_bundle_dir.mkdir(parents=True)
        (outer_bundle_dir / "bundle.json").write_text('{"endpoints": []}')

        project = tmp_path / "project"
        (project / ".git").mkdir(parents=True)   # boundary marker
        start = project / "sub"
        start.mkdir(parents=True)

        result = _find_bundle_upward(start)

        # The walk stopped at project/ (.git boundary) without finding a bundle there.
        # It must NOT continue into tmp_path where the bundle lives.
        assert result is None

    def test_found_at_boundary_directory(self, tmp_path):
        """A bundle located in the boundary directory itself is still found.

        The boundary check happens AFTER the bundle check for each directory,
        so a project that places bundle.json at its own root is not penalised.
        """
        # tmp_path is the project root with both a boundary marker and a bundle.
        (tmp_path / ".git").mkdir()
        self._write_bundle(tmp_path)
        start = tmp_path / "nested"
        start.mkdir()

        result = _find_bundle_upward(start)

        assert result is not None
        assert result == tmp_path / ".stubsmith" / "bundle.json"

    def test_resolved_path_exposed_on_replay_context(self, tmp_path, monkeypatch):
        """replay() sets bundle_path on the returned context to the resolved file."""
        self._write_bundle(tmp_path)
        monkeypatch.delenv("STUBSMITH_BUNDLE", raising=False)
        monkeypatch.chdir(tmp_path)

        ctx = replay()
        assert ctx.bundle_path == tmp_path / ".stubsmith" / "bundle.json"

    # --- _resolve_bundle integration ---

    def test_resolve_finds_bundle_in_cwd(self, tmp_path, monkeypatch):
        """_resolve_bundle() finds a bundle when cwd is the bundle's directory."""
        self._write_bundle(tmp_path)
        monkeypatch.delenv("STUBSMITH_BUNDLE", raising=False)
        monkeypatch.chdir(tmp_path)

        with replay():
            resp = requests.get(f"{_BASE_URL}/api/ping")
        assert resp.status_code == 200

    def test_resolve_finds_bundle_several_levels_up(self, tmp_path, monkeypatch):
        """_resolve_bundle() finds a bundle two directories above cwd.

        This is the new behaviour that was missing before: running pytest from
        a subdirectory while the bundle lives at the project root.
        """
        self._write_bundle(tmp_path)
        deep = tmp_path / "sub" / "pkg"
        deep.mkdir(parents=True)
        monkeypatch.delenv("STUBSMITH_BUNDLE", raising=False)
        monkeypatch.chdir(deep)

        with replay():
            resp = requests.get(f"{_BASE_URL}/api/ping")
        assert resp.status_code == 200

    def test_resolve_not_found_raises_actionable_error(self, tmp_path, monkeypatch):
        """FileNotFoundError must name the start directory, the walk, and 'stubsmith pull'.

        A bare "file not found" naming a literal path that was never expected
        to exist is unhelpful.  The message must explain where the search
        started and how to fix it.
        """
        # Use a deep subdirectory so the cwd string appears in the error.
        start = tmp_path / "deep" / "subdir"
        start.mkdir(parents=True)
        monkeypatch.delenv("STUBSMITH_BUNDLE", raising=False)
        monkeypatch.chdir(start)

        with pytest.raises(FileNotFoundError) as exc_info:
            _resolve_bundle(None)

        msg = str(exc_info.value)
        assert str(start) in msg, "Error must name the directory the search started from"
        assert "stubsmith pull" in msg, "Error must mention 'stubsmith pull'"

    def test_env_var_wins_over_upward_search(self, tmp_path, monkeypatch):
        """$STUBSMITH_BUNDLE is used even when a bundle exists up the tree."""
        env_data = _bundle(
            _endpoint("GET", "/api/env", [_stub(_FP_EMPTY_GET, [_variant(200, '{"source":"env"}')])])
        )
        env_path = tmp_path / "env.json"
        env_path.write_text(json.dumps(env_data))

        # Also place a bundle that would be found by the upward walk.
        self._write_bundle(tmp_path)

        monkeypatch.setenv("STUBSMITH_BUNDLE", str(env_path))
        monkeypatch.chdir(tmp_path)

        with replay():
            resp = requests.get(f"{_BASE_URL}/api/env")
        assert resp.json() == {"source": "env"}

    def test_explicit_arg_wins_over_upward_search(self, tmp_path, monkeypatch):
        """An explicit bundle argument is used even when a bundle exists up the tree."""
        explicit_data = _bundle(
            _endpoint("GET", "/api/explicit", [_stub(_FP_EMPTY_GET, [_variant(200, '{"source":"explicit"}')])])
        )
        explicit_path = tmp_path / "explicit.json"
        explicit_path.write_text(json.dumps(explicit_data))

        # Also place a bundle that would be found by the upward walk.
        self._write_bundle(tmp_path)

        monkeypatch.delenv("STUBSMITH_BUNDLE", raising=False)
        monkeypatch.chdir(tmp_path)

        with replay(bundle=explicit_path):
            resp = requests.get(f"{_BASE_URL}/api/explicit")
        assert resp.json() == {"source": "explicit"}


# ---------------------------------------------------------------------------
# on_miss validation
# ---------------------------------------------------------------------------

class TestOnMissValidation:

    def test_strict_is_accepted(self):
        """on_miss='strict' must not raise at construction time."""
        data = _bundle()
        ctx = replay(bundle=data, on_miss="strict")
        assert ctx._on_miss == "strict"

    def test_non_strict_raises_value_error(self):
        """Any value other than 'strict' must raise ValueError immediately."""
        with pytest.raises(ValueError, match="on_miss="):
            replay(bundle=_bundle(), on_miss="record")

    def test_passthrough_raises_value_error(self):
        with pytest.raises(ValueError, match="on_miss="):
            replay(bundle=_bundle(), on_miss="passthrough")


# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------

class TestPublicExports:

    def test_replay_exported_from_stubsmith(self):
        assert hasattr(stubsmith, "replay")
        assert stubsmith.replay is replay

    def test_stub_not_found_exported_from_stubsmith(self):
        assert hasattr(stubsmith, "StubNotFound")
        assert stubsmith.StubNotFound is StubNotFound

    def test_replay_context_exported_from_stubsmith(self):
        assert hasattr(stubsmith, "ReplayContext")
        assert stubsmith.ReplayContext is ReplayContext

    def test_all_contains_new_names(self):
        assert "replay" in stubsmith.__all__
        assert "StubNotFound" in stubsmith.__all__
        assert "ReplayContext" in stubsmith.__all__


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _make_prepared_request(method: str, url: str, body: str = None) -> requests.PreparedRequest:
    """Build a PreparedRequest as requests would produce it."""
    req = requests.Request(method=method, url=url)
    if body is not None:
        req.data = body
        req.headers = {"Content-Type": "application/json"}
    prepared = req.prepare()
    return prepared


# ---------------------------------------------------------------------------
# install() interaction - capture suppression while replay is active
# ---------------------------------------------------------------------------

class TestInstallInteraction:
    """While replay() is active, install()'s capture must be suppressed entirely.

    An application commonly calls install() at startup and its test suite
    uses replay().  Without suppression, install's Session.request wrapper
    would receive the stub response and enqueue it as though it were
    production traffic, polluting the project with synthetic fingerprints.
    """

    def _make_client_with_capture_log(self):
        """Return a StubSmith client that records enqueued payloads in a list."""
        from stubsmith.client import StubSmith
        captured = []
        client = StubSmith(url="http://unused", api_key="sk-test")
        client.enqueue = lambda p: captured.append(p)
        return client, captured

    def _install_requests(self, client):
        """Instrument requests with the given client."""
        client.instrument_requests()
        return client

    def test_no_capture_enqueued_during_replay(self):
        """install() active + replay() active → zero captures enqueued."""
        client, captured = self._make_client_with_capture_log()
        self._install_requests(client)

        bundle = _bundle(
            _endpoint("GET", "/api/ping", [_stub(_FP_EMPTY_GET, [_variant(200, '{"ok":true}')])])
        )
        try:
            with replay(bundle=bundle):
                requests.get(f"{_BASE_URL}/api/ping")
        finally:
            # Always restore the requests patch so other tests are unaffected.
            import requests.sessions as _rs
            orig = getattr(_rs.Session, "_stubsmith_original_request", None)
            if orig is not None:
                _rs.Session.request = orig
                del _rs.Session._stubsmith_original_request

        assert captured == [], (
            f"Expected zero captures while replay is active, got {len(captured)}: {captured}"
        )

    def test_capture_resumes_after_replay_exits(self):
        """After replay() exits, install() must capture normally again.

        A fix that suppresses capture permanently would pass the above test
        while silently disabling instrumentation for the rest of the process.
        This test proves suppression is temporary.
        """
        from stubsmith.client import StubSmith
        from stubsmith._replay_state import is_replay_active

        captured = []
        client = StubSmith(url="http://unused", api_key="sk-test")
        client.enqueue = lambda p: captured.append(p)

        bundle = _bundle(
            _endpoint("GET", "/api/ping", [_stub(_FP_EMPTY_GET, [_variant(200, '{"ok":true}')])])
        )

        # Enter and exit replay
        with replay(bundle=bundle):
            pass

        assert not is_replay_active(), "replay flag must be cleared after exit"

        # Directly call _capture_requests - no real HTTP needed.
        from unittest.mock import MagicMock
        mock_response = MagicMock()
        mock_response.headers = {"content-type": "application/json"}
        mock_response.status_code = 200
        mock_response.content = b'{"ok":true}'
        mock_response.text = '{"ok":true}'

        client._capture_requests(
            "GET",
            "http://api.example.com/api/after-replay",
            {},
            "",
            mock_response,
            5,
        )

        assert len(captured) == 1, (
            "Capture must resume after replay exits; "
            f"got {len(captured)} capture(s)"
        )

    def test_exception_in_with_still_restores_capture(self):
        """An exception inside the with block must not leave capture suppressed."""
        from stubsmith._replay_state import is_replay_active

        bundle = _bundle()

        with pytest.raises(RuntimeError, match="body error"):
            with replay(bundle=bundle):
                raise RuntimeError("body error")

        assert not is_replay_active(), (
            "is_replay_active() must be False after an exception exits the with block"
        )

    def test_nested_replay_suppresses_until_outer_exits(self):
        """Nested replay() blocks: capture suppressed until the outermost exits."""
        from stubsmith._replay_state import is_replay_active, _depth

        bundle = _bundle()

        with replay(bundle=bundle):
            assert is_replay_active()
            with replay(bundle=bundle):
                assert is_replay_active()
            # Inner exited - outer still active
            assert is_replay_active()

        assert not is_replay_active()


# ---------------------------------------------------------------------------
# Near-miss diagnostics
# ---------------------------------------------------------------------------

# Helper: build a stub dict with optional query_names / content_type stored
# (simulating a bundle produced by a server that includes them).
def _stub_with_extras(
    fingerprint: str,
    variants: List[Dict],
    *,
    key_paths: List[str] = None,
    query_names: List[str] = None,
    content_type: str = None,
) -> Dict[str, Any]:
    s = {
        "fingerprint": fingerprint,
        "key_paths": key_paths or [],
        "field_rules": [],
        "degraded": False,
        "variants": variants,
    }
    if query_names is not None:
        s["query_names"] = query_names
    if content_type is not None:
        s["content_type"] = content_type
    return s


class TestNearMissDiagnostics:
    """StubNotFound message content for fingerprint-miss cases."""

    # ------------------------------------------------------------------
    # Task A regression: reason phrase in raise_for_status
    # ------------------------------------------------------------------

    def test_reason_phrase_set_for_200(self):
        """response.reason must be 'OK' for a 200 stub (not None or empty)."""
        bundle = _bundle(
            _endpoint("GET", "/api/ping", [_stub(_FP_EMPTY_GET, [_variant(200, "{}")])])
        )
        with replay(bundle=bundle):
            resp = requests.get(f"{_BASE_URL}/api/ping")
        assert resp.reason == "OK"

    def test_reason_phrase_set_for_500(self):
        """response.reason must be 'Internal Server Error' for a 500 stub."""
        fp = _fp("", "", "")
        bundle = _bundle(
            _endpoint("GET", "/api/ping", [_stub(fp, [_variant(500, "{}")])])
        )
        with replay(bundle=bundle):
            resp = requests.get(f"{_BASE_URL}/api/ping")
        assert resp.reason == "Internal Server Error"

    # ------------------------------------------------------------------
    # Extra field sent → '+' line naming it
    # ------------------------------------------------------------------

    def test_extra_field_sent_shows_plus_line(self):
        """Sending an extra body field not in the recording must show a '+' line."""
        # Recording has only {"action": "pay"} → key_paths = ["action"]
        rec_body = '{"action": "pay"}'
        rec_fp = _fp(rec_body, "", "application/json")

        bundle = _bundle(
            _endpoint(
                "POST",
                "/v1/charges",
                [_stub_with_extras(
                    rec_fp,
                    [_variant(200, '{"id":"ch_1"}', count=10)],
                    key_paths=["action"],
                )],
            )
        )

        # Sent: {"action": "pay", "metadata": {"coupon_code": "SAVE10"}}
        sent_body = '{"action": "pay", "metadata": {"coupon_code": "SAVE10"}}'
        sent_fp = _fp(sent_body, "", "application/json")

        # Fingerprints must differ - confirms this is actually a miss test.
        assert sent_fp != rec_fp

        with pytest.raises(StubNotFound) as exc_info:
            with replay(bundle=bundle):
                requests.post(
                    f"{_BASE_URL}/v1/charges",
                    data=sent_body,
                    headers={"Content-Type": "application/json"},
                )

        msg = str(exc_info.value)
        assert "+ metadata" in msg or "+ metadata.coupon_code" in msg, (
            f"Expected a '+' line for the extra field, got:\n{msg}"
        )
        assert "sent, not in the recording" in msg, (
            f"Expected 'sent, not in the recording' text, got:\n{msg}"
        )

    # ------------------------------------------------------------------
    # Field missing → '-' line naming it
    # ------------------------------------------------------------------

    def test_missing_field_shows_minus_line(self):
        """Omitting a field that was in the recording must show a '-' line."""
        # Recording has {"action": "pay", "customer": {"tax_id": "DE123"}}
        rec_body = '{"action": "pay", "customer": {"tax_id": "DE123"}}'
        rec_fp = _fp(rec_body, "", "application/json")

        bundle = _bundle(
            _endpoint(
                "POST",
                "/v1/charges",
                [_stub_with_extras(
                    rec_fp,
                    [_variant(200, '{"id":"ch_1"}', count=5)],
                    key_paths=["action", "customer", "customer.tax_id"],
                )],
            )
        )

        # Sent: only {"action": "pay"} - missing customer and customer.tax_id
        sent_body = '{"action": "pay"}'
        sent_fp = _fp(sent_body, "", "application/json")
        assert sent_fp != rec_fp

        with pytest.raises(StubNotFound) as exc_info:
            with replay(bundle=bundle):
                requests.post(
                    f"{_BASE_URL}/v1/charges",
                    data=sent_body,
                    headers={"Content-Type": "application/json"},
                )

        msg = str(exc_info.value)
        assert "customer.tax_id" in msg, (
            f"Expected 'customer.tax_id' in diagnostic, got:\n{msg}"
        )
        assert "in the recording, not sent" in msg, (
            f"Expected 'in the recording, not sent', got:\n{msg}"
        )
        # The '-' prefix must appear
        assert "- customer.tax_id" in msg, (
            f"Expected '- customer.tax_id' line, got:\n{msg}"
        )

    # ------------------------------------------------------------------
    # Content-type differs, key-paths identical → content-type line present
    # ------------------------------------------------------------------

    def test_content_type_diff_shown_when_key_paths_match(self):
        """When key-paths match but Content-Type differs, the diff must say so."""
        # Recording is application/json with body {"action": "pay"}
        rec_body = '{"action": "pay"}'
        rec_fp = _fp(rec_body, "", "application/json")

        bundle = _bundle(
            _endpoint(
                "POST",
                "/v1/charges",
                [_stub_with_extras(
                    rec_fp,
                    [_variant(200, '{"id":"ch_1"}', count=8)],
                    key_paths=["action"],
                    content_type="application/json",
                )],
            )
        )

        # Sent: same key structure but as form-encoded (different content-type).
        # extract_keypaths returns ["action"] for form-encoded "action=pay" too.
        sent_body = "action=pay"
        sent_fp = _fp(sent_body, "", "application/x-www-form-urlencoded")
        # These should differ because content-type is part of the hash.
        assert sent_fp != rec_fp

        with pytest.raises(StubNotFound) as exc_info:
            with replay(bundle=bundle):
                requests.post(
                    f"{_BASE_URL}/v1/charges",
                    data=sent_body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )

        msg = str(exc_info.value)
        assert "Content-Type" in msg, (
            f"Expected 'Content-Type' diff section, got:\n{msg}"
        )
        assert "application/json" in msg, (
            f"Expected recorded content-type in message, got:\n{msg}"
        )
        assert "application/x-www-form-urlencoded" in msg, (
            f"Expected sent content-type in message, got:\n{msg}"
        )

    # ------------------------------------------------------------------
    # Query-name difference reported
    # ------------------------------------------------------------------

    def test_query_name_diff_shown(self):
        """A query parameter sent but not in the recording must appear as '+?name'."""
        # Recording: GET /api/orders with no query params (query_names=[])
        rec_fp = _fp("", "", "")

        bundle = _bundle(
            _endpoint(
                "GET",
                "/api/orders",
                [_stub_with_extras(
                    rec_fp,
                    [_variant(200, '{"orders":[]}', count=3)],
                    key_paths=[],
                    query_names=[],
                )],
            )
        )

        # Sent: GET /api/orders?status=shipped (extra query param)
        sent_fp = _fp("", "status=shipped", "")
        assert sent_fp != rec_fp

        with pytest.raises(StubNotFound) as exc_info:
            with replay(bundle=bundle):
                requests.get(f"{_BASE_URL}/api/orders?status=shipped")

        msg = str(exc_info.value)
        assert "?status" in msg, (
            f"Expected '?status' query-param diff, got:\n{msg}"
        )
        assert "sent, not in the recording" in msg, (
            f"Expected 'sent, not in the recording', got:\n{msg}"
        )

    # ------------------------------------------------------------------
    # Value-discriminated path difference - shows both values
    # ------------------------------------------------------------------

    def test_value_discriminated_endpoint_miss_falls_through_to_cannot_compare(self):
        """Value-discriminated fingerprint miss falls through to the honest
        "cannot compare" message.

        The bundle carries the *response* body per variant, not the request
        body.  fingerprint_value_paths are paths into the *request* body.
        Reading the response body for those paths is wrong, so the vp_diff
        block does not exist.  The miss is reported as a key-paths-identical /
        cannot-compare case instead.

        The variant here uses a realistic response body distinct from the
        request so any future regression that reads the response body looking
        for request-field values would find nothing and still fall through
        correctly.
        """
        # Recording: request body {"action": "charge"}, value_paths=["action"]
        rec_req_body = '{"action": "charge"}'
        rec_fp = _fp(rec_req_body, "", "application/json", value_paths=["action"])
        # Realistic response - does NOT echo the request field.
        rec_resp_body = '{"id": "ch_1", "status": "succeeded"}'

        bundle = _bundle(
            _endpoint(
                "POST",
                "/v1/charges",
                [_stub_with_extras(
                    rec_fp,
                    [_variant(200, rec_resp_body, count=50)],
                    key_paths=["action"],
                )],
                fingerprint_value_paths=["action"],
            )
        )

        # Sent: same key-paths, different discriminator value → different fp.
        sent_body = '{"action": "refund"}'
        sent_fp = _fp(sent_body, "", "application/json", value_paths=["action"])
        assert sent_fp != rec_fp, "pre-condition: value discrimination must produce different fps"

        with pytest.raises(StubNotFound) as exc_info:
            with replay(bundle=bundle):
                requests.post(
                    f"{_BASE_URL}/v1/charges",
                    data=sent_body,
                    headers={"Content-Type": "application/json"},
                )

        msg = str(exc_info.value)
        # Must reach the "cannot compare" path, not claim an SDK bug.
        assert "does not record" in msg, (
            f"Expected 'does not record' in value-discriminated miss message, got:\n{msg}"
        )
        assert "symmetry bug" not in msg, (
            f"Must not claim SDK bug for a value-discriminated miss, got:\n{msg}"
        )

    # ------------------------------------------------------------------
    # No endpoint match → other message, naming domain, listing alternatives
    # ------------------------------------------------------------------

    def test_no_endpoint_match_names_domain(self):
        """When no endpoint exists for the domain+method, the message names the domain."""
        bundle = _bundle(
            _endpoint(
                "POST",
                "/v1/payments",
                [_stub(_FP_POST_JSON, [_variant(200, "{}")])],
            )
        )

        with pytest.raises(StubNotFound) as exc_info:
            with replay(bundle=bundle):
                # Completely different path - no endpoint recorded for it
                requests.post(
                    f"{_BASE_URL}/v1/charges",
                    json={"action": "pay", "amount": 100},
                )

        msg = str(exc_info.value)
        assert _DOMAIN in msg, (
            f"Expected domain '{_DOMAIN}' in no-endpoint-match message, got:\n{msg}"
        )

    def test_no_endpoint_match_lists_same_method_alternatives(self):
        """When endpoint is missing, same-method recorded endpoints must be listed."""
        bundle = _bundle(
            _endpoint(
                "POST",
                "/v1/payments",
                [_stub(_FP_POST_JSON, [_variant(200, "{}")])],
            ),
            _endpoint(
                "POST",
                "/v1/subscriptions",
                [_stub(_FP_EMPTY_GET, [_variant(200, "{}")])],
            ),
            _endpoint(
                "GET",
                "/v1/status",
                [_stub(_FP_EMPTY_GET, [_variant(200, "{}")])],
            ),
        )

        with pytest.raises(StubNotFound) as exc_info:
            with replay(bundle=bundle):
                requests.post(
                    f"{_BASE_URL}/v1/charges",
                    json={"action": "pay", "amount": 100},
                )

        msg = str(exc_info.value)
        # Both POST alternatives should appear
        assert "/v1/payments" in msg, (
            f"Expected '/v1/payments' in alternatives list, got:\n{msg}"
        )
        assert "/v1/subscriptions" in msg, (
            f"Expected '/v1/subscriptions' in alternatives list, got:\n{msg}"
        )
        # The GET endpoint should NOT appear (different method)
        assert "/v1/status" not in msg, (
            f"GET endpoint '/v1/status' should not appear in POST alternatives, got:\n{msg}"
        )

    # ------------------------------------------------------------------
    # Structurally identical but different hash → SDK-bug message
    # ------------------------------------------------------------------

    def test_sdk_bug_message_when_hash_differs_for_identical_structure(self):
        """When a stub's fingerprint is hand-corrupted, the SDK-bug branch fires."""
        real_body = '{"action": "pay"}'
        real_fp = _fp(real_body, "", "application/json")

        # Corrupt the fingerprint so it cannot match, but key_paths are identical
        # to what the sent request would produce - triggering the self-check.
        corrupted_fp = "deadbeef" + real_fp[8:]
        assert corrupted_fp != real_fp

        bundle = _bundle(
            _endpoint(
                "POST",
                "/v1/charges",
                [_stub_with_extras(
                    corrupted_fp,
                    [_variant(200, '{"id":"ch_1"}', count=1)],
                    key_paths=["action"],
                    query_names=[],
                    content_type="application/json",
                )],
            )
        )

        with pytest.raises(StubNotFound) as exc_info:
            with replay(bundle=bundle):
                requests.post(
                    f"{_BASE_URL}/v1/charges",
                    data=real_body,
                    headers={"Content-Type": "application/json"},
                )

        msg = str(exc_info.value)
        assert "structurally identical" in msg or "symmetry bug" in msg, (
            f"Expected SDK-bug diagnostic, got:\n{msg}"
        )

    # ------------------------------------------------------------------
    # Many candidates → output bounded, count reported
    # ------------------------------------------------------------------

    def test_many_candidates_bounded_output(self):
        """With more than 2 stubs for an endpoint, only 2 are shown and count is stated."""
        # Build 5 distinct stubs for the same endpoint, each with a different
        # set of key_paths so they all produce different fingerprints.
        stubs = []
        for i in range(5):
            body = json.dumps({"action": "pay", f"field_{i}": "x"})
            fp = _fp(body, "", "application/json")
            stubs.append(
                _stub_with_extras(
                    fp,
                    [_variant(200, "{}", count=i + 1)],
                    key_paths=["action", f"field_{i}"],
                )
            )

        bundle = _bundle(
            _endpoint("POST", "/v1/charges", stubs)
        )

        # Sent: no extra field → won't match any of the 5 stubs
        sent_body = '{"action": "pay"}'
        assert _fp(sent_body, "", "application/json") not in [s["fingerprint"] for s in stubs]

        with pytest.raises(StubNotFound) as exc_info:
            with replay(bundle=bundle):
                requests.post(
                    f"{_BASE_URL}/v1/charges",
                    data=sent_body,
                    headers={"Content-Type": "application/json"},
                )

        msg = str(exc_info.value)
        # The message must say how many candidates were considered
        assert "5" in msg, (
            f"Expected total candidate count (5) in message, got:\n{msg}"
        )
        # Should not show all 5 diffs - only 2
        plus_minus_count = msg.count("sent, not in the recording")
        assert plus_minus_count <= 2, (
            f"Expected at most 2 diff blocks, found {plus_minus_count} in:\n{msg}"
        )

    # ------------------------------------------------------------------
    # Leaf-path filtering
    # ------------------------------------------------------------------

    def test_parent_path_suppressed_when_child_also_differs(self):
        """When parent and child are both in the diff, only the leaf is rendered.

        A body {"metadata": {"coupon_code": "X"}} produces key_paths
        ["metadata", "metadata.coupon_code"].  The recording has neither.
        Only "metadata.coupon_code" should appear in the diff line - the
        intermediate "metadata" node is noise and must be suppressed.
        """
        rec_body = '{"action": "pay"}'
        rec_fp = _fp(rec_body, "", "application/json")

        bundle = _bundle(
            _endpoint(
                "POST",
                "/v1/charges",
                [_stub_with_extras(
                    rec_fp,
                    [_variant(200, '{"id":"ch_1"}', count=10)],
                    key_paths=["action"],
                )],
            )
        )

        sent_body = '{"action": "pay", "metadata": {"coupon_code": "SAVE10"}}'

        with pytest.raises(StubNotFound) as exc_info:
            with replay(bundle=bundle):
                requests.post(
                    f"{_BASE_URL}/v1/charges",
                    data=sent_body,
                    headers={"Content-Type": "application/json"},
                )

        msg = str(exc_info.value)
        # Leaf must appear
        assert "metadata.coupon_code" in msg, (
            f"Expected leaf 'metadata.coupon_code' in diff, got:\n{msg}"
        )
        # Intermediate node must NOT appear as a standalone diff line
        lines = msg.splitlines()
        intermediate_lines = [
            ln for ln in lines
            if ("+ metadata" in ln or "- metadata" in ln)
            and "coupon_code" not in ln
        ]
        assert not intermediate_lines, (
            f"Intermediate node 'metadata' must be suppressed when leaf present; "
            f"found spurious lines: {intermediate_lines}\nFull message:\n{msg}"
        )

    def test_childless_object_not_suppressed(self):
        """An empty object with no children in the diff is itself the leaf and must render.

        Recording key_paths = ["action"].
        Sent body = {"action": "pay", "metadata": {}} → key_paths = ["action", "metadata"].
        "metadata" has no child paths in the diff set, so it must appear.
        """
        rec_body = '{"action": "pay"}'
        rec_fp = _fp(rec_body, "", "application/json")

        bundle = _bundle(
            _endpoint(
                "POST",
                "/v1/charges",
                [_stub_with_extras(
                    rec_fp,
                    [_variant(200, '{"id":"ch_1"}', count=5)],
                    key_paths=["action"],
                )],
            )
        )

        # Empty nested object - "metadata" appears in key_paths but has no children
        sent_body = '{"action": "pay", "metadata": {}}'

        with pytest.raises(StubNotFound) as exc_info:
            with replay(bundle=bundle):
                requests.post(
                    f"{_BASE_URL}/v1/charges",
                    data=sent_body,
                    headers={"Content-Type": "application/json"},
                )

        msg = str(exc_info.value)
        assert "metadata" in msg, (
            f"Childless 'metadata' must appear in diff (it is the leaf), got:\n{msg}"
        )

    # ------------------------------------------------------------------
    # SDK-bug claim: honest about what the bundle could/could not compare
    # ------------------------------------------------------------------

    def test_sdk_bug_wording_only_when_all_three_inputs_confirmed(self):
        """SDK-bug wording appears only when query_names AND content_type are both
        in the bundle and all inputs matched.

        When the bundle supplies both fields and all three fingerprint inputs
        (key-paths, query-parameter names, content-type) are identical, the
        hash difference is a genuine anomaly worth reporting.
        """
        real_body = '{"action": "pay"}'
        real_fp = _fp(real_body, "", "application/json")
        # Corrupt the fingerprint so it cannot match despite identical structure.
        corrupted_fp = "cafebabe" + real_fp[8:]
        assert corrupted_fp != real_fp

        bundle = _bundle(
            _endpoint(
                "POST",
                "/v1/charges",
                [_stub_with_extras(
                    corrupted_fp,
                    [_variant(200, '{"id":"ch_1"}', count=1)],
                    key_paths=["action"],
                    query_names=[],          # bundle supplies this
                    content_type="application/json",   # and this
                )],
            )
        )

        with pytest.raises(StubNotFound) as exc_info:
            with replay(bundle=bundle):
                requests.post(
                    f"{_BASE_URL}/v1/charges",
                    data=real_body,
                    headers={"Content-Type": "application/json"},
                )

        msg = str(exc_info.value)
        assert "symmetry bug" in msg, (
            f"Expected SDK-bug wording when all three inputs confirmed, got:\n{msg}"
        )
        # Must not fall back to the "cannot compare" message
        assert "does not record" not in msg, (
            f"Must not say 'does not record' when bundle supplied both fields, got:\n{msg}"
        )

    def test_cannot_compare_wording_when_bundle_fields_absent(self):
        """When query_names and content_type are absent from the bundle, the message
        must explain that - not accuse the SDK of a bug.

        A request that differs only in query-parameter names or content-type
        has identical key-paths to the recording.  Without those two fields in
        the bundle we cannot tell which input caused the fingerprint mismatch,
        so we must say so explicitly rather than emitting a false SDK-bug claim.
        """
        rec_body = '{"action": "pay"}'
        rec_fp = _fp(rec_body, "", "application/json")

        # Bundle stub lacks query_names and content_type (current server behaviour)
        bundle = _bundle(
            _endpoint(
                "POST",
                "/v1/charges",
                [_stub_with_extras(
                    rec_fp,
                    [_variant(200, '{"id":"ch_1"}', count=3)],
                    key_paths=["action"],
                    # deliberately omit query_names= and content_type=
                )],
            )
        )

        # Sent body matches key-paths but adds a query param → different fingerprint
        sent_fp = _fp(rec_body, "v=2", "application/json")
        assert sent_fp != rec_fp, "pre-condition: fingerprints must differ"

        with pytest.raises(StubNotFound) as exc_info:
            with replay(bundle=bundle):
                requests.post(
                    f"{_BASE_URL}/v1/charges?v=2",
                    data=rec_body,
                    headers={"Content-Type": "application/json"},
                )

        msg = str(exc_info.value)
        # Must name both fingerprint inputs the user should check
        assert "query-parameter names" in msg, (
            f"Expected 'query-parameter names' named in cannot-compare message, got:\n{msg}"
        )
        assert "content-type" in msg, (
            f"Expected 'content-type' named in cannot-compare message, got:\n{msg}"
        )
        # Must say the bundle does not record them
        assert "does not record" in msg, (
            f"Expected 'does not record' in cannot-compare message, got:\n{msg}"
        )
        # Must NOT falsely accuse the SDK
        assert "symmetry bug" not in msg, (
            f"Must not claim SDK bug when bundle fields are absent, got:\n{msg}"
        )


# ---------------------------------------------------------------------------
# Looping every recorded response
#
# replay() serves one recording per shape, so every other recording the server
# holds goes unexercised - including the 429 and 500 the API really returned.
# replay_all() runs the block once per recording.
# ---------------------------------------------------------------------------

def _sample(capture_id: str, body: str, *, captured_at: str = "2026-09-01T00:00:00Z",
            headers: Dict[str, str] = None, duration_ms: int = 5) -> Dict[str, Any]:
    return {
        "capture_id": capture_id,
        "captured_at": captured_at,
        "duration_ms": duration_ms,
        "headers": headers or {"content-type": "application/json"},
        "body": body,
    }


def _windowed_variant(status: int, count: int, samples: List[Dict[str, Any]]) -> Dict[str, Any]:
    """A variant as the server returns it for ?samples>1."""
    v = _variant(status, samples[0]["body"], count=count)
    v["samples"] = samples
    return v


def _windowed_bundle() -> Dict[str, Any]:
    return _bundle(_endpoint("GET", "/orders", [
        _stub(_FP_EMPTY_GET, [
            _windowed_variant(200, 90, [
                _sample("c200a", '{"n": 1}'),
                _sample("c200b", '{"n": 2}'),
                _sample("c200c", '{"n": 3}'),
            ]),
            _windowed_variant(429, 2, [_sample("c429a", '{"e": "rate"}')]),
            _windowed_variant(500, 1, [_sample("c500a", '{"e": "boom"}')]),
        ]),
    ]))


def _get_orders() -> Any:
    return requests.get(f"https://{_DOMAIN}/orders")


class TestReplayAll:
    def test_loops_every_recording_once(self):
        seen = []
        for attempt in stubsmith.replay_all(_windowed_bundle()):
            with attempt:
                resp = _get_orders()
            served = attempt.served()
            assert len(served) == 1
            seen.append((resp.status_code, resp.text, served[0].capture_id))

        assert seen == [
            (200, '{"n": 1}', "c200a"),
            (200, '{"n": 2}', "c200b"),
            (200, '{"n": 3}', "c200c"),
            (429, '{"e": "rate"}', "c429a"),
            (500, '{"e": "boom"}', "c500a"),
        ]

    def test_first_pass_matches_plain_replay(self):
        """A test that passes under replay() must pass on pass one, or moving to
        replay_all() would change the meaning of the existing assertions."""
        bundle = _windowed_bundle()
        with replay(bundle):
            baseline = _get_orders()
        first = next(iter(stubsmith.replay_all(bundle)))
        with first:
            got = _get_orders()
        assert (got.status_code, got.text) == (baseline.status_code, baseline.text)

    def test_a_bundle_without_samples_yields_one_pass_per_status(self):
        """stubsmith pull without --samples returns one recording per status.
        Looping must still work, just with fewer passes."""
        bundle = _bundle(_endpoint("GET", "/orders", [
            _stub(_FP_EMPTY_GET, [
                _variant(200, '{"a": 1}', count=5),
                _variant(500, '{"b": 2}', count=1),
            ]),
        ]))
        codes = []
        for attempt in stubsmith.replay_all(bundle):
            with attempt:
                codes.append(_get_orders().status_code)
        assert codes == [200, 500]

    def test_a_single_recording_yields_exactly_one_pass(self):
        bundle = _bundle(_endpoint("GET", "/orders", [
            _stub(_FP_EMPTY_GET, [_variant(200, '{"a": 1}')]),
        ]))
        passes = 0
        for attempt in stubsmith.replay_all(bundle):
            with attempt:
                _get_orders()
            passes += 1
        assert passes == 1

    def test_a_short_window_clamps_instead_of_raising(self):
        """Two shapes with different window lengths: the shorter one must keep
        serving its last recording rather than raise, or one endpoint's short
        history would truncate the loop for everything else."""
        bundle = _bundle(
            _endpoint("GET", "/orders", [
                _stub(_FP_EMPTY_GET, [_windowed_variant(200, 3, [
                    _sample("long-a", '{"i": 1}'),
                    _sample("long-b", '{"i": 2}'),
                    _sample("long-c", '{"i": 3}'),
                ])]),
            ]),
            _endpoint("GET", "/health", [
                _stub(_FP_EMPTY_GET, [_windowed_variant(200, 1, [
                    _sample("short-a", '{"ok": true}'),
                ])]),
            ]),
        )
        orders, health = [], []
        for attempt in stubsmith.replay_all(bundle):
            with attempt:
                orders.append(_get_orders().text)
                health.append(requests.get(f"https://{_DOMAIN}/health").text)
            by_ep = {s.path_template: s for s in attempt.served()}
            if attempt.pass_number > 1:
                assert by_ep["/health"].exhausted is True

        assert orders == ['{"i": 1}', '{"i": 2}', '{"i": 3}']
        assert health == ['{"ok": true}'] * 3

    def test_an_endpoint_first_reached_on_a_later_pass_is_still_looped(self):
        """The endpoint set is discovered by running the code, and code that
        branches on the response it got can reach different endpoints on
        different passes. The stopping condition must come from what has been
        served, not from a count computed up front."""
        bundle = _bundle(
            _endpoint("GET", "/orders", [
                _stub(_FP_EMPTY_GET, [
                    _windowed_variant(200, 5, [_sample("ok-a", '{"ok": true}')]),
                    _windowed_variant(500, 1, [_sample("err-a", '{"err": true}')]),
                ]),
            ]),
            _endpoint("GET", "/retry", [
                _stub(_FP_EMPTY_GET, [_windowed_variant(200, 2, [
                    _sample("retry-a", '{"r": 1}'),
                    _sample("retry-b", '{"r": 2}'),
                    _sample("retry-c", '{"r": 3}'),
                ])]),
            ]),
        )
        retries = []
        passes = 0
        for attempt in stubsmith.replay_all(bundle):
            with attempt:
                # /retry is only called after a 500, so it is untouched on pass 1.
                if _get_orders().status_code >= 500:
                    retries.append(requests.get(f"https://{_DOMAIN}/retry").text)
            passes += 1

        # Pass 1: 200. Pass 2: 500, which reaches /retry for the first time and
        # reveals a 3-long window, so the loop must continue to passes 3 and 4.
        assert retries == ['{"r": 1}', '{"r": 2}', '{"r": 3}']
        assert passes == 4

    def test_max_passes_caps_the_loop(self):
        passes = 0
        for attempt in stubsmith.replay_all(_windowed_bundle(), max_passes=2):
            with attempt:
                _get_orders()
            passes += 1
        assert passes == 2

    def test_max_passes_must_be_positive(self):
        with pytest.raises(ValueError, match="max_passes"):
            next(iter(stubsmith.replay_all(_windowed_bundle(), max_passes=0)))

    def test_on_miss_is_validated(self):
        with pytest.raises(ValueError, match="on_miss"):
            next(iter(stubsmith.replay_all(_windowed_bundle(), on_miss="passthrough")))

    def test_session_send_is_restored_after_the_loop(self):
        original = requests.sessions.Session.send
        for attempt in stubsmith.replay_all(_windowed_bundle()):
            with attempt:
                _get_orders()
        assert requests.sessions.Session.send is original

    def test_no_network_is_attempted(self):
        with patch("requests.adapters.HTTPAdapter.send") as adapter:
            for attempt in stubsmith.replay_all(_windowed_bundle()):
                with attempt:
                    _get_orders()
            adapter.assert_not_called()


class TestSelect:
    def test_by_status_serves_that_status(self):
        with replay(_windowed_bundle(), select=stubsmith.by_status(429)):
            resp = _get_orders()
        assert resp.status_code == 429
        assert resp.text == '{"e": "rate"}'

    def test_by_status_for_an_unrecorded_status_raises(self):
        """Serving a different status instead would let a rate-limit test pass
        while exercising the happy path."""
        with replay(_windowed_bundle(), select=stubsmith.by_status(418)):
            with pytest.raises(StubNotFound):
                _get_orders()

    def test_a_custom_select_receives_every_recording(self):
        seen: List[Dict[str, Any]] = []

        def _oldest(responses):
            seen.extend(responses)
            return responses[-1]

        with replay(_windowed_bundle(), select=_oldest):
            resp = _get_orders()

        assert len(seen) == 5, [r.get("capture_id") for r in seen]
        assert resp.text == '{"e": "boom"}'

    def test_served_reports_what_ran(self):
        with replay(_windowed_bundle()) as ctx:
            _get_orders()
            _get_orders()
        served = ctx.served()
        assert len(served) == 2
        assert served[0].endpoint == f"GET {_DOMAIN}/orders"
        assert served[0].status == 200
        assert served[0].capture_id == "c200a"
        assert served[0].total == 5
        assert served[0].exhausted is False
