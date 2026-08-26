"""
Offline tests for ShopClient user operations using stubsmith.replay().

The bundle at .stubsmith/bundle.json was produced from a real capture run.
replay() intercepts requests.Session.send at the transport layer - no network
call is ever made, and the shop service does not need to be running.

GET /api/users/{id} is a dynamic route.  The SDK templates the numeric id
segment before storage, so the bundle stub's path_template is "/api/users/{id}"
(literal braces).  replay() applies the same templating to incoming test
requests, so any integer id routes to the same stub.

Both the 200 and 404 variants share the same stub fingerprint (fc552c95a0bb0d3e)
with count: 2 each; _select_variant picks 200 (lowest status code when counts
are tied).  To exercise the 404 path, an inline bundle containing only the 404
variant is passed, following the same pattern as the 401 test in test_auth.py.

The email field is masked in both the request capture and the response body by
the SDK's regex backstop (email-shaped strings are always masked regardless of
keep rules).  Tests assert presence, not value, for masked fields.
"""
import pytest

import stubsmith
from shopclient import ShopClient, UserNotFound

BASE_URL = "http://localhost:8081"

# Inline bundle for the 404 error-path test.  Both 200 and 404 variants share
# fingerprint fc552c95a0bb0d3e with count: 2; _select_variant returns 200 by
# default (lowest status code wins the tie).  Passing a focused bundle that
# carries only the 404 variant makes replay() serve it unconditionally.
#
# The body uses the real "code" value ("USER_NOT_FOUND") rather than the
# masked "<masked>" that appears in the main bundle, because ShopClient.get_user
# inspects body["code"] to decide which typed error to raise.  An inline bundle
# is not constrained to use masked values - it is purpose-built for the test.
_GET_USER_404_BUNDLE = {
    "ok": True,
    "version": 1,
    "endpoints": [
        {
            "domain": "localhost:8081",
            "method": "GET",
            "path_template": "/api/users/{id}",
            "is_dynamic": True,
            "fingerprint_value_paths": [],
            "stubs": [
                {
                    "fingerprint": "fc552c95a0bb0d3e",
                    "key_paths": [],
                    "degraded": False,
                    "variants": [
                        {
                            "status": 404,
                            "count": 2,
                            "duration_ms": 1,
                            "headers": {"content-type": "application/json; charset=utf-8"},
                            "body": '{"error": "<masked>", "code": "USER_NOT_FOUND"}',
                        }
                    ],
                }
            ],
        }
    ],
}


# ---------------------------------------------------------------------------
# GET /api/users/{id} - 200 (happy path)
# ---------------------------------------------------------------------------


def test_get_user_returns_recorded_shape():
    """Client parses the recorded response body correctly.

    replay() templates /api/users/4821 → /api/users/{id} for the lookup.
    Fields without a keep rule are masked; id and plan are kept explicitly.
    """
    with stubsmith.replay():
        user = ShopClient(BASE_URL, "test-key").get_user(4821)

    assert user["id"] == 4821
    assert user["plan"] == "pro"
    assert user["active"] is True
    assert "name" in user
    assert "created_at" in user
    assert "last_login" in user
    # email is always masked by the regex backstop - assert presence, not value.
    assert "email" in user
    assert user["email"] == "<masked>"


def test_get_user_dynamic_template_matches_any_id():
    """The same stub is served regardless of which integer user id is passed.

    This is the payoff of dynamic path templating: one bundle stub covers all
    id variants in the test suite without a separate capture per id.
    """
    with stubsmith.replay():
        client = ShopClient(BASE_URL, "test-key")
        user_a = client.get_user(4821)
        user_b = client.get_user(1111)

    # Both calls hit /api/users/{id} and get the same recorded body.
    assert user_a["id"] == user_b["id"]
    assert "name" in user_a
    assert "name" in user_b


# ---------------------------------------------------------------------------
# GET /api/users/{id} - 404 (inline bundle)
# ---------------------------------------------------------------------------


def test_get_user_raises_user_not_found():
    """The 404 variant drives the UserNotFound error from the client.

    The inline bundle contains only the 404 variant so replay() serves it
    unconditionally, bypassing the default 200 (lowest-status) selection.
    """
    with stubsmith.replay(_GET_USER_404_BUNDLE):
        with pytest.raises(UserNotFound) as exc_info:
            ShopClient(BASE_URL, "test-key").get_user(9042)

    assert exc_info.value.status == 404


# ---------------------------------------------------------------------------
# POST /api/users - 201
# ---------------------------------------------------------------------------


def test_create_user_returns_recorded_shape():
    """Client parses the create-user response correctly.

    id is kept (integer); name and email are masked (no keep rule and email
    is also caught by the regex backstop).
    """
    with stubsmith.replay():
        result = ShopClient(BASE_URL, "test-key").create_user(
            name="Test User",
            email="test@example.invalid",
            password="s3cr3t",
            phone="+1 555 0000",
        )

    assert "id" in result
    assert result["created"] is True
    # email masked by the regex backstop - presence check only.
    assert "email" in result
    assert result["email"] == "<masked>"
