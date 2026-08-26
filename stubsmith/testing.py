"""
StubSmith testing helpers - fixture-based HTTP stubbing for pytest/unittest.

This module turns vendored ``/v1/fixtures`` snapshots into ``responses``
stubs so your tests never hit the network.  Import it alongside the
``responses`` library::

    from stubsmith import testing
    import responses

    @responses.activate
    def test_get_user():
        bundle = testing.load_bundle("fixtures/get_user.json")
        testing.register_template(responses, bundle, base_url="http://api")

        result = client.get_user(99)   # real HTTP call → captured by responses
        assert result["id"] == 99

Public API summary:

* :data:`MASK_PLACEHOLDERS` - frozenset of placeholder values written by masking.
* :func:`save_bundle` / :func:`load_bundle` - persist and reload a bundle.
* :func:`register` - stub a **static** route (exact URL match).
* :func:`register_template` - stub a **dynamic** route (``{param}`` → regex).
* :func:`assert_request_matches_fixture` - key-path contract check (client vs
  production fixture request body).
* :func:`assert_body_schemas_match` - key-path schema comparison for any two body
  values (e.g. live API response vs vendored snapshot).

Route type determines which register helper to use:

* ``is_dynamic=False`` (static route, e.g. ``POST /api/orders``) →
  :func:`register`.
* ``is_dynamic=True`` (dynamic route, e.g. ``GET /api/users/{id}``) →
  :func:`register_template`.

**Why this distinction matters:** the SDK templates numeric, UUID, and
16+-hex path segments before storage (see ``stubsmith/privacy/templating.py``),
so a dynamic route's recorded ``fixture.path`` is literally
``/api/users/{id}`` (with real braces), not a concrete id like
``/api/users/4821``.  Calling :func:`register` on such a path builds an
exact URL with literal braces that will never match a real request.
:func:`register_template` converts ``{param}`` tokens to ``[^/?]+`` regex
wildcards so any concrete id is matched.

Optional dependency
-------------------
``responses`` is an optional dependency.  Importing :mod:`stubsmith.testing`
succeeds without it; only :func:`register` and :func:`register_template`
raise :exc:`ImportError` at call time when the package is absent.  Install
it with::

    pip install stubsmith[testing]
"""

from __future__ import annotations

import json
import pathlib
import re
from typing import Any, Optional

from .fixtures import Fixture, FixtureBundle

# Guard the optional `responses` import so that `import stubsmith.testing`
# succeeds on installs without it.  The individual helpers check
# _responses_available at call time.
try:
    import responses as _responses_lib

    _responses_available = True
except ImportError:
    _responses_lib = None  # type: ignore[assignment]
    _responses_available = False


# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

# Mask placeholder values written by Stubsmith's SDK masking pipeline.
#
# The SDK uses fail-closed, path-based masking: every scalar is replaced with
# a type-appropriate placeholder unless its namespaced path (body., query.,
# header., resp., resp_header.) carries an explicit "keep" rule in the
# per-fingerprint field rules delivered by GET /v1/sdk/sync.
#
# Placeholder values (SDK embedded):
#   strings  → "<masked>"
#   numbers  → 0          (indistinguishable from a real zero - note this)
#   booleans → False      (indistinguishable from a real False)
#   null     → None       (not in this set; None just stays None)
#
# "<masked-cc>" is NOT emitted by the embedded backstop.  It comes from a
# project's synced regex rule set (anonymizer/rules.json), which replaces
# 16-digit card numbers.  The embedded backstop uses "<masked>" for both
# emails and card numbers.
#
# Tests must NEVER assert that a field equals one of these values (e.g. that
# a name field equals "<masked>") unless you are explicitly verifying that
# masking occurred.  Use assert_request_matches_fixture() for structural
# comparison; use fixture.request.body in MASK_PLACEHOLDERS to verify a
# specific field is masked.
MASK_PLACEHOLDERS: frozenset = frozenset(
    {
        "<masked>",
        # Emitted by the project's synced regex rule for 16-digit card numbers,
        # not the embedded backstop.  Include here because it appears in the
        # card_number / card.number fixture fields.
        "<masked-cc>",
        # Non-string scalar placeholders.  In Python, 0 == False and they hash
        # identically, so frozenset({0, False}) has one element.  Both are
        # listed for documentation clarity; the "in" check works for either.
        False,
        0,
    }
)

# Hop-by-hop headers that must be stripped before replaying through the
# ``responses`` library.  urllib3 rejects a body whose Content-Length no longer
# matches the replayed bytes, and Transfer-Encoding has no meaning for an
# in-process stub.
_HOP_BY_HOP: frozenset = frozenset(
    {
        "content-length",
        "transfer-encoding",
        "connection",
        "content-encoding",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "upgrade",
    }
)


# ---------------------------------------------------------------------------
# Bundle persistence
# ---------------------------------------------------------------------------


def save_bundle(bundle: FixtureBundle, path: Any) -> None:
    """Vendor a :class:`FixtureBundle` to a JSON file on disk.

    The file format mirrors the exact ``/v1/fixtures`` response envelope
    (``ok``, ``request_type``, ``count``, ``fixtures[]`` with
    ``request``/``response`` sub-objects and body fields as JSON strings) so a
    vendored file is byte-comparable with a live API response.  Written with
    ``indent=2, sort_keys=True`` so a snapshot refresh produces a clean,
    reviewable git diff.

    Parameters
    ----------
    bundle:
        The :class:`FixtureBundle` to serialise.
    path:
        Destination file path (``str`` or :class:`pathlib.Path`).  Parent
        directories must exist.
    """
    data = {
        "ok": bundle.ok,
        "request_type": bundle.request_type,
        "count": bundle.count,
        "fixtures": [
            {
                "id": f.id,
                "captured_at": f.captured_at,
                "method": f.method,
                "path": f.path,
                "status": f.status,
                "duration_ms": f.duration_ms,
                "request": {"headers": f.request.headers, "body": f.request.body},
                "response": {"headers": f.response.headers, "body": f.response.body},
            }
            for f in bundle.fixtures
        ],
    }
    pathlib.Path(path).write_text(json.dumps(data, indent=2, sort_keys=True))


def load_bundle(path: Any) -> FixtureBundle:
    """Load a vendored :class:`FixtureBundle` from a JSON file.

    Reads a file previously written by :func:`save_bundle` (or a raw
    ``/v1/fixtures`` response saved to disk) and returns a
    :class:`FixtureBundle` ready for use with :func:`register` or
    :func:`register_template`.

    Parameters
    ----------
    path:
        Source file path (``str`` or :class:`pathlib.Path`).

    Returns
    -------
    FixtureBundle
        Parsed bundle with ``request_type`` metadata and fixture list.
    """
    data = json.loads(pathlib.Path(path).read_text())
    return FixtureBundle(data)


# ---------------------------------------------------------------------------
# responses stubs
# ---------------------------------------------------------------------------


def _require_responses() -> None:
    """Raise a clear ImportError when the ``responses`` package is missing."""
    if not _responses_available:
        raise ImportError(
            "The 'responses' package is required for HTTP stubbing. "
            "Install it with:  pip install 'stubsmith[testing]'  "
            "or:  pip install responses>=0.23"
        )


def register(
    responses_mock: Any,
    fixture: Fixture,
    base_url: str = "http://testserver",
) -> None:
    """Register a single fixture as a stub with the ``responses`` library.

    Use this for **static** (non-dynamic) routes - paths like ``/api/orders``
    or ``/api/auth/login`` that contain no ``{param}`` segments.

    For dynamic routes (``GET /api/users/{id}``, ``PUT /api/orders/{id}``) use
    :func:`register_template` instead.  The SDK templates numeric and UUID path
    segments before storage (see ``stubsmith/privacy/templating.py``), so the
    recorded ``fixture.path`` for a dynamic route is ``/api/users/{id}`` with
    **literal braces**, not a concrete id.  Registering that as an exact URL
    would never match a real request such as ``GET /api/users/4821``.

    The URL is ``base_url + fixture.path``, which includes any query string
    recorded in the capture (e.g. ``/api/orders?status=shipped&limit=20``).
    Hop-by-hop headers are stripped before replaying so urllib3 does not choke
    on a mismatched Content-Length or unexpected Transfer-Encoding.

    Requires the ``responses`` package (``pip install stubsmith[testing]``).

    Parameters
    ----------
    responses_mock:
        The active ``responses`` mock object (typically the ``responses``
        module itself when used as a decorator, or the ``rsps`` argument
        inside a ``with responses.RequestsMock() as rsps:`` block).
    fixture:
        The :class:`Fixture` to replay.
    base_url:
        Scheme and host to prepend to the recorded path.  Default:
        ``"http://testserver"``.
    """
    _require_responses()
    url = base_url.rstrip("/") + fixture.path
    safe_headers = {
        k: v
        for k, v in fixture.response.headers.items()
        if k.lower() not in _HOP_BY_HOP
    }
    raw_body = fixture.response.body
    if isinstance(raw_body, (dict, list)):
        raw_body = json.dumps(raw_body)
    responses_mock.add(
        method=fixture.method,
        url=url,
        status=fixture.status,
        body=raw_body,
        headers=safe_headers,
    )


def register_template(
    responses_mock: Any,
    bundle: FixtureBundle,
    base_url: str = "http://testserver",
    fixture: Optional[Fixture] = None,
) -> None:
    """Register a URL-regex stub for a dynamic route.

    This is the correct path for any route whose ``request_type.is_dynamic``
    is ``True``.  Converts ``{param}`` placeholders in the ``path_pattern``
    to ``[^/?]+`` so ``GET /api/users/{id}`` matches any user id, not just
    the one that happened to be recorded in the snapshot.

    The regex is anchored with ``^`` so ``responses`` (which uses
    ``re.search`` internally) cannot match a URL that merely contains the
    base URL as a substring.

    For static routes use :func:`register` instead.  A dynamic route's
    recorded ``fixture.path`` contains literal braces (e.g.
    ``/api/users/{id}``); calling :func:`register` on such a path would never
    match a real request.

    Requires the ``responses`` package (``pip install stubsmith[testing]``).

    Parameters
    ----------
    responses_mock:
        The active ``responses`` mock object.
    bundle:
        A :class:`FixtureBundle` whose ``request_type`` carries the
        ``path_pattern`` and ``method``.  Raises :exc:`ValueError` when
        ``bundle.request_type`` is ``None`` - in that case use
        :func:`register` with an explicit path.
    base_url:
        Scheme and host to prepend to the path pattern.  Default:
        ``"http://testserver"``.
    fixture:
        The status variant to serve.  Defaults to the first fixture in the
        bundle (usually the happy-path 200).  Pass
        ``bundle.by_status(404)`` to stub an error variant::

            register_template(rsps, bundle, BASE_URL, fixture=bundle.by_status(404))

    Raises
    ------
    ValueError
        When ``bundle.request_type`` is ``None``.
    ImportError
        When the ``responses`` package is not installed.
    """
    _require_responses()
    if not bundle.request_type:
        raise ValueError(
            "register_template requires a request_type "
            "(bundle.request_type is None - use register() for raw-path fixtures)"
        )

    _fixture = fixture if fixture is not None else bundle.fixtures[0]

    pattern = bundle.request_type["path_pattern"]
    # Split on {param} tokens, escape the literal parts, join with a wildcard.
    parts = re.split(r"\{[^}]+\}", pattern)
    path_regex = r"[^/?]+".join(re.escape(p) for p in parts)
    # Anchor with ^ so responses (which uses re.search) cannot match a URL
    # that merely contains the base URL as a substring.
    full_regex = r"^" + re.escape(base_url.rstrip("/")) + path_regex + r"(\?.*)?$"

    safe_headers = {
        k: v
        for k, v in _fixture.response.headers.items()
        if k.lower() not in _HOP_BY_HOP
    }
    raw_body = _fixture.response.body
    if isinstance(raw_body, (dict, list)):
        raw_body = json.dumps(raw_body)
    responses_mock.add(
        method=bundle.request_type["method"],
        url=re.compile(full_regex),
        status=_fixture.status,
        body=raw_body,
        headers=safe_headers,
    )


# ---------------------------------------------------------------------------
# Schema comparison helpers
# ---------------------------------------------------------------------------


def _raise_schema_diff(
    missing: list,
    extra: list,
    label_actual: str,
    label_expected: str,
) -> None:
    """Raise an AssertionError describing key-path mismatches between two bodies."""
    lines = [
        f"Body key-path schema mismatch ({label_actual} vs {label_expected})."
    ]
    if missing:
        lines.append(
            f"  Missing in {label_actual} (present in {label_expected}): {missing}"
        )
    if extra:
        lines.append(
            f"  Extra in {label_actual} (absent from {label_expected}): {extra}"
        )
    raise AssertionError("\n".join(lines))


def assert_body_schemas_match(
    actual: Any,
    expected: Any,
    *,
    label_actual: str = "actual",
    label_expected: str = "expected",
) -> None:
    """Assert that two body values share the same dot-notation key-path schema.

    Values are NOT compared - only the set of dot-notation key-paths is checked.
    This is the right tool when you want to verify that two independently captured
    bodies have the same structure, for example comparing a live API response
    against a vendored snapshot, or checking that a refreshed fixture has not
    added or dropped fields.

    Both *actual* and *expected* are run through the tolerant parser
    (:func:`_parse_body`), so you can pass:

    - ``None`` - if *expected* parses to ``None``, the check is skipped (no
      reference schema to compare against); if only *actual* is ``None`` it is
      treated as an empty object ``{}``.
    - A ``dict`` / ``list`` - used as-is.
    - A JSON string - parsed.
    - A non-JSON string (e.g. an HTML error page) - treated as a leaf value.

    Limitation: list elements are examined one level deep (first element only).
    Drift in the structure of array elements beyond the first is not detected.

    Parameters
    ----------
    actual:
        The body to check.  Typically the live response or the client's body.
    expected:
        The reference body.  Typically the vendored fixture's body.
    label_actual:
        Human-readable label for *actual* in failure messages.
        Default: ``"actual"``.
    label_expected:
        Human-readable label for *expected* in failure messages.
        Default: ``"expected"``.

    Raises
    ------
    AssertionError
        With a readable diff of missing / extra key-paths, using the supplied
        labels to make the message actionable.

    Examples
    --------
    Compare a live fixture response body against the vendored snapshot::

        from stubsmith import testing

        offline = testing.load_bundle("fixtures/get_user.json").by_status(200)
        live    = fetch_live_fixture()

        testing.assert_body_schemas_match(
            live.response.body,
            offline.response.body,
            label_actual="live API",
            label_expected="offline snapshot",
        )
    """
    expected_parsed = _parse_body(expected)
    actual_parsed = _parse_body(actual)

    if expected_parsed is None:
        return  # No reference schema to compare against.

    expected_keys = set(_key_paths(expected_parsed))
    actual_keys = set(_key_paths(actual_parsed or {}))

    missing = sorted(expected_keys - actual_keys)
    extra = sorted(actual_keys - expected_keys)

    if missing or extra:
        _raise_schema_diff(missing, extra, label_actual, label_expected)


def assert_request_matches_fixture(sent_request: Any, fixture: Fixture) -> None:
    """Contract assertion: the key-paths your client sends must match the fixture schema.

    Values are NOT compared - they are masked in the fixture and randomised in
    production.  Only the set of dot-notation key-paths is compared.  A
    mismatch means your client drifted from what production actually sends,
    which is the failure mode this approach is designed to catch early.

    Limitation: list elements are examined one level deep (first element only)
    via :func:`_key_paths`.  Drift in the structure of array elements beyond
    the first is not detected.

    Parameters
    ----------
    sent_request:
        A ``PreparedRequest`` from ``rsps.calls[-1].request``.
    fixture:
        The :class:`Fixture` whose recorded request body provides the schema.

    Raises
    ------
    AssertionError
        With a readable diff of missing / extra key-paths.
    """
    body_raw = sent_request.body
    if body_raw and isinstance(body_raw, bytes):
        body_raw = body_raw.decode("utf-8")

    assert_body_schemas_match(
        body_raw,
        fixture.request.body,
        label_actual="request",
        label_expected="fixture",
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_body(body: Any) -> Any:
    """Parse a body field from a /v1/fixtures record tolerantly.

    The API returns request/response bodies as Postgres ``text`` columns, so
    the fixture JSON has them as strings (or null).  Three cases:

    - ``null`` / ``None``                  → ``None``
    - Already a ``dict``/``list``          → returned as-is (defensive)
    - JSON string                          → parsed
    - Non-JSON string (e.g. HTML error)    → returned raw

    This is intentionally more permissive than :meth:`~stubsmith.fixtures._Side.json`,
    which raises on ``None`` and on non-JSON strings.
    """
    if body is None:
        return None
    if isinstance(body, (dict, list)):
        return body
    try:
        return json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return body


def _key_paths(obj: Any, prefix: str = "") -> Any:
    """Yield dot-notation key paths for every leaf in a nested structure.

    List elements are examined one level deep (first element only) to avoid
    exploding on long arrays - the goal is shape comparison, not value
    coverage.
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                yield from _key_paths(v, path)
            else:
                yield path
    elif isinstance(obj, list) and obj:
        yield from _key_paths(obj[0], f"{prefix}[0]")
