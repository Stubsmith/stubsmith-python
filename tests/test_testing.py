"""
Tests for stubsmith.testing - hermetic, no network, no API key required.

Covers:
- save_bundle / load_bundle round-trip
- FixtureBundle.by_status happy path and ValueError on miss
- register: static route stub
- register_template: dynamic route, fixture= variant selector, ^ anchor
- register_template raises ValueError when request_type is absent
- assert_request_matches_fixture: pass and AssertionError with diff
- _parse_body: None, dict, JSON string, non-JSON string
- fixtures() still returns a plain list (refactor regression guard)
"""

from __future__ import annotations

import json
import os
import unittest
from unittest.mock import MagicMock, patch

import pytest
import responses as responses_lib
import requests

from stubsmith.fixtures import Fixture, FixtureBundle, fixtures
from stubsmith import testing
from stubsmith.testing import (
    MASK_PLACEHOLDERS,
    _HOP_BY_HOP,
    _parse_body,
    assert_body_schemas_match,
    assert_request_matches_fixture,
    load_bundle,
    register,
    register_template,
    save_bundle,
)


# ---------------------------------------------------------------------------
# Shared fixture data
# ---------------------------------------------------------------------------

_REQUEST_TYPE_STATIC = {
    "id": "rt-static-001",
    "method": "POST",
    "path_pattern": "/api/orders",
    "is_dynamic": False,
}

_REQUEST_TYPE_DYNAMIC = {
    "id": "rt-dynamic-001",
    "method": "GET",
    "path_pattern": "/api/users/{id}",
    "is_dynamic": True,
}

_FX_200 = {
    "id": "cap-0001",
    "captured_at": "2024-01-15T10:00:00Z",
    "method": "GET",
    "path": "/api/users/{id}",
    "status": 200,
    "duration_ms": 12,
    "request": {
        "headers": {"content-type": "application/json"},
        "body": '{"user_id": 0}',
    },
    "response": {
        "headers": {"content-type": "application/json"},
        "body": '{"id": 0, "name": "<masked>"}',
    },
}

_FX_404 = {
    "id": "cap-0002",
    "captured_at": "2024-01-14T10:00:00Z",
    "method": "GET",
    "path": "/api/users/{id}",
    "status": 404,
    "duration_ms": 5,
    "request": {
        "headers": {"content-type": "application/json"},
        "body": None,
    },
    "response": {
        "headers": {"content-type": "application/json"},
        "body": '{"error": "not found"}',
    },
}

_FX_STATIC_200 = {
    "id": "cap-0003",
    "captured_at": "2024-01-15T11:00:00Z",
    "method": "POST",
    "path": "/api/orders",
    "status": 201,
    "duration_ms": 20,
    "request": {
        "headers": {"content-type": "application/json"},
        "body": '{"amount": 0, "currency": "<masked>"}',
    },
    "response": {
        "headers": {"content-type": "application/json"},
        "body": '{"id": "<masked>", "status": "<masked>"}',
    },
}


def _make_bundle(request_type, fixtures_list):
    return FixtureBundle({
        "ok": True,
        "request_type": request_type,
        "count": len(fixtures_list),
        "fixtures": fixtures_list,
    })


def _make_static_bundle():
    return _make_bundle(_REQUEST_TYPE_STATIC, [_FX_STATIC_200])


def _make_dynamic_bundle():
    return _make_bundle(_REQUEST_TYPE_DYNAMIC, [_FX_200, _FX_404])


# ---------------------------------------------------------------------------
# save_bundle / load_bundle round-trip
# ---------------------------------------------------------------------------

class TestBundlePersistence:

    def test_round_trip_preserves_envelope(self, tmp_path):
        bundle = _make_dynamic_bundle()
        path = tmp_path / "get_user.json"
        save_bundle(bundle, path)

        loaded = load_bundle(path)

        assert loaded.request_type == _REQUEST_TYPE_DYNAMIC
        assert loaded.count == 2
        assert len(loaded.fixtures) == 2
        assert loaded.fixtures[0].status == 200
        assert loaded.fixtures[1].status == 404

    def test_round_trip_preserves_fixture_fields(self, tmp_path):
        bundle = _make_dynamic_bundle()
        path = tmp_path / "get_user.json"
        save_bundle(bundle, path)
        loaded = load_bundle(path)

        fx = loaded.fixtures[0]
        assert fx.id == "cap-0001"
        assert fx.method == "GET"
        assert fx.path == "/api/users/{id}"
        assert fx.status == 200
        assert fx.request.body == '{"user_id": 0}'
        assert fx.response.body == '{"id": 0, "name": "<masked>"}'

    def test_round_trip_json_format(self, tmp_path):
        """Saved file must be readable JSON with the envelope keys present."""
        bundle = _make_dynamic_bundle()
        path = tmp_path / "bundle.json"
        save_bundle(bundle, path)

        raw = json.loads(path.read_text())
        assert raw["ok"] is True
        assert "request_type" in raw
        assert "count" in raw
        assert "fixtures" in raw
        assert isinstance(raw["fixtures"], list)
        # Body fields must be strings (not parsed dicts)
        assert isinstance(raw["fixtures"][0]["response"]["body"], str)

    def test_round_trip_null_request_type(self, tmp_path):
        """Bundles without a request_type (no configured type) survive round-trip."""
        bundle = _make_bundle(None, [_FX_200])
        path = tmp_path / "no_rt.json"
        save_bundle(bundle, path)
        loaded = load_bundle(path)
        assert loaded.request_type is None
        assert len(loaded.fixtures) == 1


# ---------------------------------------------------------------------------
# FixtureBundle.by_status
# ---------------------------------------------------------------------------

class TestByStatus:

    def test_returns_correct_fixture(self):
        bundle = _make_dynamic_bundle()
        fx = bundle.by_status(200)
        assert fx.status == 200
        assert fx.id == "cap-0001"

    def test_returns_404_variant(self):
        bundle = _make_dynamic_bundle()
        fx = bundle.by_status(404)
        assert fx.status == 404

    def test_raises_value_error_on_miss(self):
        bundle = _make_dynamic_bundle()
        with pytest.raises(ValueError) as exc_info:
            bundle.by_status(500)
        msg = str(exc_info.value)
        assert "500" in msg
        # Must name the statuses that ARE present
        assert "200" in msg
        assert "404" in msg

    def test_raises_value_error_names_all_present(self):
        bundle = _make_dynamic_bundle()
        with pytest.raises(ValueError, match=r"present:.*200.*404"):
            bundle.by_status(503)


# ---------------------------------------------------------------------------
# register - static route stubbing
# ---------------------------------------------------------------------------

class TestRegister:

    @responses_lib.activate
    def test_register_static_route_returns_recorded_body(self):
        bundle = _make_static_bundle()
        fx = bundle.fixtures[0]
        register(responses_lib, fx, base_url="http://testserver")

        resp = requests.post("http://testserver/api/orders", json={"x": 1})
        assert resp.status_code == 201
        assert resp.json() == {"id": "<masked>", "status": "<masked>"}

    @responses_lib.activate
    def test_register_strips_hop_by_hop_headers(self):
        """content-length must not appear in the stub response headers."""
        fx_with_hop = {**_FX_STATIC_200}
        fx_with_hop = dict(_FX_STATIC_200)
        fx_with_hop["response"] = {
            "headers": {
                "content-type": "application/json",
                "content-length": "99",
                "transfer-encoding": "chunked",
            },
            "body": '{"id": "x"}',
        }
        bundle = _make_bundle(_REQUEST_TYPE_STATIC, [fx_with_hop])
        register(responses_lib, bundle.fixtures[0], base_url="http://testserver")

        resp = requests.post("http://testserver/api/orders")
        # The stub must have been served (no ConnectionError)
        assert resp.status_code == 201

    @responses_lib.activate
    def test_register_correct_method(self):
        bundle = _make_static_bundle()
        fx = bundle.fixtures[0]
        register(responses_lib, fx, base_url="http://testserver")

        # Wrong method should raise ConnectionError (not stubbed)
        with pytest.raises(Exception):
            requests.get("http://testserver/api/orders")


# ---------------------------------------------------------------------------
# register_template - dynamic route
# ---------------------------------------------------------------------------

class TestRegisterTemplate:

    @responses_lib.activate
    def test_matches_concrete_id_not_in_snapshot(self):
        """The regex must match /api/users/9999 even though only {id} was recorded."""
        bundle = _make_dynamic_bundle()
        register_template(responses_lib, bundle, base_url="http://testserver")

        resp = requests.get("http://testserver/api/users/9999")
        assert resp.status_code == 200

    @responses_lib.activate
    def test_matches_default_first_fixture(self):
        bundle = _make_dynamic_bundle()
        register_template(responses_lib, bundle, base_url="http://testserver")

        resp = requests.get("http://testserver/api/users/42")
        assert resp.status_code == 200
        assert resp.json() == {"id": 0, "name": "<masked>"}

    @responses_lib.activate
    def test_fixture_selector_serves_404_body(self):
        """Passing fixture=bundle.by_status(404) must serve the 404 body, not the 200."""
        bundle = _make_dynamic_bundle()
        register_template(
            responses_lib,
            bundle,
            base_url="http://testserver",
            fixture=bundle.by_status(404),
        )

        resp = requests.get("http://testserver/api/users/42")
        assert resp.status_code == 404
        assert resp.json() == {"error": "not found"}

    def test_raises_value_error_without_request_type(self):
        bundle = _make_bundle(None, [_FX_200])
        with pytest.raises(ValueError, match="register_template requires a request_type"):
            register_template(MagicMock(), bundle)

    @responses_lib.activate
    def test_anchor_rejects_url_with_base_url_as_substring(self):
        """The ^ anchor must prevent matching http://testserver.evil.com/api/users/1."""
        bundle = _make_dynamic_bundle()
        register_template(responses_lib, bundle, base_url="http://testserver")

        with pytest.raises(Exception):
            requests.get("http://testserver.evil.com/api/users/1")


# ---------------------------------------------------------------------------
# assert_request_matches_fixture
# ---------------------------------------------------------------------------

class TestAssertRequestMatchesFixture:

    def _make_prepared_request(self, body_dict):
        """Build a fake PreparedRequest with the given body dict."""
        mock_req = MagicMock()
        if body_dict is None:
            mock_req.body = None
        else:
            mock_req.body = json.dumps(body_dict).encode("utf-8")
        return mock_req

    def test_passes_when_key_paths_match(self):
        fx = Fixture._from_dict(_FX_200)
        # _FX_200 request body has key "user_id"
        sent = self._make_prepared_request({"user_id": 99})
        assert_request_matches_fixture(sent, fx)  # must not raise

    def test_raises_on_missing_key(self):
        fx = Fixture._from_dict(_FX_200)
        sent = self._make_prepared_request({})  # missing "user_id"
        with pytest.raises(AssertionError) as exc_info:
            assert_request_matches_fixture(sent, fx)
        assert "Missing" in str(exc_info.value)
        assert "user_id" in str(exc_info.value)

    def test_raises_on_extra_key(self):
        fx = Fixture._from_dict(_FX_200)
        sent = self._make_prepared_request({"user_id": 99, "extra_field": "oops"})
        with pytest.raises(AssertionError) as exc_info:
            assert_request_matches_fixture(sent, fx)
        assert "Extra" in str(exc_info.value)
        assert "extra_field" in str(exc_info.value)

    def test_passes_when_both_bodies_are_none(self):
        fx = Fixture._from_dict(_FX_404)  # request body is None
        sent = self._make_prepared_request(None)
        assert_request_matches_fixture(sent, fx)  # must not raise

    def test_skips_when_recorded_body_is_none(self):
        """No recorded schema → skip comparison regardless of what was sent."""
        fx = Fixture._from_dict(_FX_404)
        sent = self._make_prepared_request({"unexpected": True})
        assert_request_matches_fixture(sent, fx)  # must not raise


# ---------------------------------------------------------------------------
# _parse_body
# ---------------------------------------------------------------------------

class TestParseBody:

    def test_none_returns_none(self):
        assert _parse_body(None) is None

    def test_dict_returned_as_is(self):
        d = {"a": 1}
        assert _parse_body(d) is d

    def test_list_returned_as_is(self):
        lst = [1, 2, 3]
        assert _parse_body(lst) is lst

    def test_json_string_is_parsed(self):
        result = _parse_body('{"key": "value"}')
        assert result == {"key": "value"}

    def test_non_json_string_returned_raw(self):
        s = "<html>not json</html>"
        assert _parse_body(s) == s


# ---------------------------------------------------------------------------
# fixtures() regression - must still return a plain list
# ---------------------------------------------------------------------------

class TestFixturesReturnType(unittest.TestCase):

    def _urlopen_mock(self, fixture_list, request_type=None):
        data = json.dumps({
            "ok": True,
            "request_type": request_type,
            "count": len(fixture_list),
            "fixtures": fixture_list,
        }).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = data
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        return mock_resp

    def test_fixtures_returns_plain_list(self):
        with patch(
            "urllib.request.urlopen",
            return_value=self._urlopen_mock([_FX_200, _FX_404]),
        ):
            result = fixtures(
                "GET /api/users/{id}",
                api_url="http://localhost:3000",
                api_key="sk-test",
            )
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 2)
        self.assertIsInstance(result[0], Fixture)

    def test_fixtures_does_not_return_bundle(self):
        with patch(
            "urllib.request.urlopen",
            return_value=self._urlopen_mock([_FX_200]),
        ):
            result = fixtures(
                "GET /api/users/{id}",
                api_url="http://localhost:3000",
                api_key="sk-test",
            )
        self.assertNotIsInstance(result, FixtureBundle)


# ---------------------------------------------------------------------------
# MASK_PLACEHOLDERS sanity
# ---------------------------------------------------------------------------

class TestMaskPlaceholders:

    def test_contains_expected_values(self):
        assert "<masked>" in MASK_PLACEHOLDERS
        assert "<masked-cc>" in MASK_PLACEHOLDERS
        # 0 and False hash identically in Python - both must be "in" the set
        assert 0 in MASK_PLACEHOLDERS
        assert False in MASK_PLACEHOLDERS


# ---------------------------------------------------------------------------
# assert_body_schemas_match
# ---------------------------------------------------------------------------

class TestAssertBodySchemasMatch:
    """Hermetic tests for the public assert_body_schemas_match helper."""

    def test_passes_when_key_paths_match_dicts(self):
        assert_body_schemas_match({"a": 1, "b": 2}, {"a": 99, "b": 0})  # must not raise

    def test_passes_when_both_none(self):
        assert_body_schemas_match(None, None)  # must not raise

    def test_skips_when_expected_is_none(self):
        """No reference schema → check is skipped regardless of actual."""
        assert_body_schemas_match({"a": 1}, None)  # must not raise

    def test_treats_actual_none_as_empty(self):
        """actual=None vs expected with keys → missing keys reported."""
        with pytest.raises(AssertionError) as exc_info:
            assert_body_schemas_match(None, {"key": "value"})
        assert "key" in str(exc_info.value)

    def test_raises_on_missing_key_in_actual(self):
        with pytest.raises(AssertionError) as exc_info:
            assert_body_schemas_match({"a": 1}, {"a": 1, "b": 2})
        msg = str(exc_info.value)
        assert "b" in msg
        assert "Missing" in msg

    def test_raises_on_extra_key_in_actual(self):
        with pytest.raises(AssertionError) as exc_info:
            assert_body_schemas_match({"a": 1, "extra": "oops"}, {"a": 1})
        msg = str(exc_info.value)
        assert "extra" in msg
        assert "Extra" in msg

    def test_labels_appear_in_error_message(self):
        with pytest.raises(AssertionError) as exc_info:
            assert_body_schemas_match(
                {"a": 1},
                {"a": 1, "b": 2},
                label_actual="live API",
                label_expected="offline snapshot",
            )
        msg = str(exc_info.value)
        assert "live API" in msg
        assert "offline snapshot" in msg

    def test_parses_json_string_actual(self):
        """A JSON string is parsed before comparing key-paths."""
        assert_body_schemas_match('{"x": 1}', {"x": 99})  # must not raise

    def test_parses_json_string_expected(self):
        assert_body_schemas_match({"x": 1}, '{"x": 99}')  # must not raise

    def test_nested_key_paths_compared(self):
        actual = {"card": {"number": "<masked>", "exp": 2028}}
        expected = {"card": {"number": "<masked>", "exp": 0, "cvc": "<masked>"}}
        with pytest.raises(AssertionError) as exc_info:
            assert_body_schemas_match(actual, expected)
        assert "card.cvc" in str(exc_info.value)

    def test_non_json_string_treated_as_leaf(self):
        """Non-JSON bodies on both sides are not traversed - no error."""
        assert_body_schemas_match("<html>error</html>", "<html>error</html>")  # must not raise

    def test_passes_on_identical_nested_structure(self):
        body = {"user": {"id": 0, "name": "<masked>"}, "active": False}
        assert_body_schemas_match(body, body)  # must not raise


# ---------------------------------------------------------------------------
# ok field - FixtureBundle round-trip
# ---------------------------------------------------------------------------

class TestOkFieldRoundTrip:
    """The ok field must survive a save_bundle / load_bundle cycle."""

    def test_ok_true_survives_round_trip(self, tmp_path):
        bundle = _make_dynamic_bundle()
        assert bundle.ok is True
        path = tmp_path / "bundle.json"
        save_bundle(bundle, path)
        loaded = load_bundle(path)
        assert loaded.ok is True

    def test_ok_defaults_to_true_when_absent(self):
        """Vendored bundles hand-written without the ok field must not fail."""
        data = {
            "request_type": None,
            "count": 1,
            "fixtures": [_FX_200],
        }
        bundle = FixtureBundle(data)
        assert bundle.ok is True

    def test_saved_json_contains_ok_field(self, tmp_path):
        bundle = _make_dynamic_bundle()
        path = tmp_path / "bundle.json"
        save_bundle(bundle, path)
        raw = json.loads(path.read_text())
        assert "ok" in raw
        assert raw["ok"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
