"""
Live fixture tests - opt-in, require STUBSMITH_API_KEY.

These tests call the real Stubsmith backend and verify that the live API
envelope is well-formed.  They do not assert on values (values are randomised
with each traffic run), only on shape.

Run them by setting STUBSMITH_API_KEY in your environment:

    STUBSMITH_API_KEY=<your-key> pytest -m live -v

They are skipped automatically in CI unless the key is present.

Environment variables::

    STUBSMITH_API_URL       Backend base URL (authoritative SDK name).
                            Default: https://app.stubsmith.dev/api
    STUBSMITH_BACKEND_URL   Fallback for STUBSMITH_API_URL (accepted for
                            compatibility with earlier versions).
    STUBSMITH_API_KEY       Required for live tests.
"""
import os

import pytest

from stubsmith import fixtures_bundle as _fetch_bundle
from stubsmith.fixtures import FixtureBundle

_API_KEY = os.environ.get("STUBSMITH_API_KEY", "")
_API_URL = (
    os.environ.get("STUBSMITH_API_URL")
    or os.environ.get("STUBSMITH_BACKEND_URL")
    or "https://app.stubsmith.dev/api"
).rstrip("/")

pytestmark = pytest.mark.skipif(
    not _API_KEY,
    reason="STUBSMITH_API_KEY not set - live fixture tests skipped",
)


def _fetch(method: str, path: str, limit: int = 10) -> FixtureBundle:
    return _fetch_bundle(
        f"{method} {path}",
        api_url=_API_URL,
        api_key=_API_KEY,
        distinct="status",
        limit=limit,
    )


# ---------------------------------------------------------------------------
# Envelope shape assertions
# ---------------------------------------------------------------------------


@pytest.mark.live
def test_live_get_user_fixture_envelope():
    """Live /v1/fixtures response has the expected envelope keys and ok=true."""
    bundle = _fetch("GET", "/api/users/1234")

    assert bundle.ok is True
    assert bundle.count == len(bundle.fixtures)
    assert isinstance(bundle.fixtures, list)


@pytest.mark.live
def test_live_fixture_has_required_record_keys():
    """Each fixture record in the live response has all required keys."""
    bundle = _fetch("GET", "/api/users/1234")

    for fixture in bundle.fixtures:
        assert fixture.id
        assert fixture.captured_at
        assert fixture.method
        assert fixture.path
        assert isinstance(fixture.status, int)
        assert isinstance(fixture.request.headers, dict)
        assert isinstance(fixture.response.headers, dict)


# ---------------------------------------------------------------------------
# Live status variant check
# ---------------------------------------------------------------------------


@pytest.mark.live
def test_live_login_has_at_least_one_variant():
    """Live login fixture bundle contains at least one of the expected status codes.

    The example sends both a 200 (correct password) and a 401 (wrong password)
    login request, but captures may not have been approved yet.  We check for
    at least one variant to avoid a flaky failure when only one status has been
    captured so far.
    """
    bundle = _fetch("POST", "/api/auth/login", limit=10)

    if not bundle.fixtures:
        pytest.skip("No live login fixtures - no approved captures yet for this route")

    statuses = {f.status for f in bundle.fixtures}
    assert 200 in statuses or 401 in statuses, (
        f"Expected at least one of 200/401 in the live login fixture; got: {sorted(statuses)}"
    )
