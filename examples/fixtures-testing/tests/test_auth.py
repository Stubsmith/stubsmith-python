"""
Offline tests for ShopClient auth operations using stubsmith.replay().

The bundle at .stubsmith/bundle.json was produced from a real capture run.
replay() intercepts requests.Session.send at the transport layer - no
network call is ever made, and the shop service does not need to be running.

The 401 (wrong-password) test uses an inline bundle dict rather than the
main bundle.  In the main bundle both the 200 and 401 variants share the
same fingerprint and each has count=2; _select_variant breaks the tie by
returning the lowest status code (200).  To test the error path we pass a
focused dict that contains only the 401 variant, which is the documented
pattern when you need to exercise a specific non-modal status code without
separating request fingerprints.
"""
import pytest

import stubsmith
from shopclient import InvalidCredentials, ShopClient

BASE_URL = "http://localhost:8081"

# Inline bundle for the 401 error-path test.  The fingerprint and key_paths
# must match what ShopClient.login() actually sends.
_LOGIN_401_BUNDLE = {
    "ok": True,
    "version": 1,
    "endpoints": [
        {
            "domain": "localhost:8081",
            "method": "POST",
            "path_template": "/api/auth/login",
            "is_dynamic": False,
            "fingerprint_value_paths": [],
            "stubs": [
                {
                    "fingerprint": "88a4c74a696c6e89",
                    "key_paths": ["email", "password"],
                    "degraded": False,
                    "variants": [
                        {
                            "status": 401,
                            "count": 1,
                            "duration_ms": 18,
                            "headers": {"content-type": "application/json; charset=utf-8"},
                            "body": '{"error": "invalid credentials"}',
                        }
                    ],
                }
            ],
        }
    ],
}


# ---------------------------------------------------------------------------
# POST /api/auth/login - 200 (happy path)
# ---------------------------------------------------------------------------


def test_login_returns_recorded_shape():
    """replay() serves the 200 response from the bundle; client parses it."""
    with stubsmith.replay():
        result = ShopClient(BASE_URL, "test-key").login(
            "test@example.invalid", "any-password"
        )

    # token and session_token are masked (no keep rule for auth tokens).
    assert "token" in result
    assert result["token"] == "<masked>"
    assert result["expires_in"] == 7200
    assert "user_id" in result
    assert "session_token" in result


def test_login_response_keys_present():
    """All expected top-level keys are present in the replayed response."""
    with stubsmith.replay():
        result = ShopClient(BASE_URL, "test-key").login("any@example.invalid", "pw")

    for key in ("token", "expires_in", "user_id", "session_token"):
        assert key in result, f"Expected key {key!r} missing from login response"


# ---------------------------------------------------------------------------
# POST /api/auth/login - 401 (wrong credentials, inline bundle)
# ---------------------------------------------------------------------------


def test_login_raises_invalid_credentials():
    """The 401 variant drives the InvalidCredentials error from the client.

    The inline bundle contains only the 401 variant so replay() serves it
    unconditionally, regardless of count-based variant selection.
    """
    with stubsmith.replay(_LOGIN_401_BUNDLE):
        with pytest.raises(InvalidCredentials) as exc_info:
            ShopClient(BASE_URL, "test-key").login(
                "wrong@example.invalid", "bad-password"
            )

    assert exc_info.value.status == 401


def test_login_401_body_has_error_key():
    """The 401 response body carries an 'error' key."""
    with stubsmith.replay(_LOGIN_401_BUNDLE):
        with pytest.raises(InvalidCredentials) as ei:
            ShopClient(BASE_URL, "test-key").login("x@example.invalid", "bad")

    assert "error" in ei.value.body
