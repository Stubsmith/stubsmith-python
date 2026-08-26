"""
Unit tests for stubsmith.fixtures - no network required.

Run with:
    python3 -m unittest discover clients/python/tests -v
"""

from __future__ import annotations

import json
import os
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

from stubsmith.fixtures import Fixture, _Side, fixtures


# ---------------------------------------------------------------------------
# Sample fixture payload matching the /v1/fixtures response shape
# ---------------------------------------------------------------------------

SAMPLE_PAYLOAD = {
    "id": "cap-aabbccdd-0001",
    "captured_at": "2024-01-15T10:00:00Z",
    "method": "POST",
    "path": "/v1/charges/ch_abc123",
    "status": 201,
    "duration_ms": 42,
    "request": {
        "headers": {"content-type": "application/json", "x-idempotency-key": "k1"},
        "body": '{"amount": 100, "currency": "usd"}',
    },
    "response": {
        "headers": {"content-type": "application/json"},
        "body": '{"id": "ch_abc123", "status": "succeeded"}',
    },
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _urlopen_mock(fixture_list):
    """Return a mock suitable for patching urllib.request.urlopen."""
    data = json.dumps({"ok": True, "fixtures": fixture_list}).encode()
    mock_resp = MagicMock()
    mock_resp.read.return_value = data
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


# ---------------------------------------------------------------------------
# Fixture dataclass parsing
# ---------------------------------------------------------------------------

class TestFixtureParsing(unittest.TestCase):

    def _fx(self, **overrides):
        payload = dict(SAMPLE_PAYLOAD)
        payload.update(overrides)
        return Fixture._from_dict(payload)

    def test_basic_fields(self):
        fx = self._fx()
        self.assertEqual(fx.id, "cap-aabbccdd-0001")
        self.assertEqual(fx.captured_at, "2024-01-15T10:00:00Z")
        self.assertEqual(fx.method, "POST")
        self.assertEqual(fx.path, "/v1/charges/ch_abc123")
        self.assertEqual(fx.status, 201)
        self.assertEqual(fx.duration_ms, 42)

    def test_request_side(self):
        fx = self._fx()
        self.assertIsInstance(fx.request, _Side)
        self.assertEqual(fx.request.headers["content-type"], "application/json")
        self.assertEqual(fx.request.body, '{"amount": 100, "currency": "usd"}')

    def test_response_side(self):
        fx = self._fx()
        self.assertIsInstance(fx.response, _Side)
        self.assertEqual(fx.response.headers["content-type"], "application/json")
        self.assertIn("ch_abc123", fx.response.body)

    def test_response_json_parsing(self):
        fx = self._fx()
        parsed = fx.response.json()
        self.assertEqual(parsed["id"], "ch_abc123")
        self.assertEqual(parsed["status"], "succeeded")

    def test_request_json_parsing(self):
        fx = self._fx()
        parsed = fx.request.json()
        self.assertEqual(parsed["amount"], 100)
        self.assertEqual(parsed["currency"], "usd")

    def test_repr(self):
        fx = self._fx()
        r = repr(fx)
        self.assertIn("POST", r)
        self.assertIn("/v1/charges/ch_abc123", r)
        self.assertIn("201", r)

    def test_duration_ms_optional(self):
        payload = dict(SAMPLE_PAYLOAD)
        del payload["duration_ms"]
        fx = Fixture._from_dict(payload)
        self.assertIsNone(fx.duration_ms)

    def test_missing_request_key_tolerated(self):
        """None or missing request/response sub-dict should not raise."""
        payload = dict(SAMPLE_PAYLOAD, request=None, response={})
        fx = Fixture._from_dict(payload)
        self.assertEqual(fx.request.headers, {})
        self.assertIsNone(fx.request.body)
        self.assertEqual(fx.response.headers, {})
        self.assertIsNone(fx.response.body)


# ---------------------------------------------------------------------------
# _Side.json() edge cases
# ---------------------------------------------------------------------------

class TestSideJson(unittest.TestCase):

    def test_json_raises_on_none_body(self):
        side = _Side(headers={}, body=None)
        with self.assertRaises(ValueError):
            side.json()

    def test_json_raises_on_invalid_json(self):
        side = _Side(headers={}, body="not json {{{")
        with self.assertRaises(ValueError):
            side.json()

    def test_json_parses_array(self):
        side = _Side(headers={}, body='[1, 2, 3]')
        self.assertEqual(side.json(), [1, 2, 3])

    def test_json_parses_string_primitive(self):
        side = _Side(headers={}, body='"hello"')
        self.assertEqual(side.json(), "hello")


# ---------------------------------------------------------------------------
# fixtures() - pattern parsing and parameter forwarding
# ---------------------------------------------------------------------------

class TestFixturesFunction(unittest.TestCase):

    def test_method_and_path_forwarded(self):
        """fixtures() must split on first space and send method + path params."""
        with patch("urllib.request.urlopen", return_value=_urlopen_mock([SAMPLE_PAYLOAD])) as mopen:
            result = fixtures(
                "POST /v1/charges/{id}",
                api_url="http://localhost:3000",
                api_key="sk-test",
            )
        req = mopen.call_args[0][0]
        url = req.full_url
        self.assertIn("method=POST", url)
        # path=/v1/charges/{id} - braces are percent-encoded
        self.assertIn("path=", url)
        self.assertIn("%2Fv1%2Fcharges%2F", url)
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], Fixture)

    def test_method_uppercased(self):
        with patch("urllib.request.urlopen", return_value=_urlopen_mock([])) as mopen:
            fixtures("get /v1/users", api_url="http://localhost:3000", api_key="sk-test")
        url = mopen.call_args[0][0].full_url
        self.assertIn("method=GET", url)

    def test_distinct_param_forwarded(self):
        with patch("urllib.request.urlopen", return_value=_urlopen_mock([])) as mopen:
            fixtures(
                "GET /v1/users",
                api_url="http://localhost:3000",
                api_key="sk-test",
                distinct="status",
            )
        url = mopen.call_args[0][0].full_url
        self.assertIn("distinct=status", url)

    def test_limit_param_forwarded(self):
        with patch("urllib.request.urlopen", return_value=_urlopen_mock([])) as mopen:
            fixtures(
                "GET /v1/users",
                api_url="http://localhost:3000",
                api_key="sk-test",
                limit=5,
            )
        url = mopen.call_args[0][0].full_url
        self.assertIn("limit=5", url)

    def test_bearer_token_in_auth_header(self):
        with patch("urllib.request.urlopen", return_value=_urlopen_mock([])) as mopen:
            fixtures("GET /v1/health", api_url="http://localhost:3000", api_key="sk-mykey")
        req = mopen.call_args[0][0]
        self.assertIn("sk-mykey", req.get_header("Authorization"))

    def test_returns_list_of_fixture_objects(self):
        with patch("urllib.request.urlopen", return_value=_urlopen_mock([SAMPLE_PAYLOAD, SAMPLE_PAYLOAD])):
            result = fixtures("POST /v1/charges/{id}", api_url="http://localhost:3000", api_key="sk-t")
        self.assertEqual(len(result), 2)
        self.assertIsInstance(result[0], Fixture)
        self.assertIsInstance(result[1], Fixture)

    def test_empty_fixture_list_returns_empty_list(self):
        with patch("urllib.request.urlopen", return_value=_urlopen_mock([])):
            result = fixtures("GET /v1/nothing", api_url="http://localhost:3000", api_key="sk-t")
        self.assertEqual(result, [])


# ---------------------------------------------------------------------------
# fixtures() - error handling
# ---------------------------------------------------------------------------

class TestFixturesErrors(unittest.TestCase):

    def test_missing_api_key_raises_runtime_error(self):
        backup = os.environ.pop("STUBSMITH_API_KEY", None)
        try:
            with self.assertRaises(RuntimeError) as ctx:
                fixtures("POST /v1/charge", api_url="http://localhost:3000")
            self.assertIn("API key", str(ctx.exception))
        finally:
            if backup is not None:
                os.environ["STUBSMITH_API_KEY"] = backup

    def test_env_var_api_key_used_as_fallback(self):
        mock_resp = _urlopen_mock([])
        with patch.dict(
            os.environ,
            {"STUBSMITH_API_KEY": "sk-env-key", "STUBSMITH_API_URL": "http://localhost:3000"},
        ):
            with patch("urllib.request.urlopen", return_value=mock_resp) as mopen:
                fixtures("GET /v1/test")
        req = mopen.call_args[0][0]
        self.assertIn("sk-env-key", req.get_header("Authorization"))

    def test_env_var_api_url_used_as_fallback(self):
        mock_resp = _urlopen_mock([])
        with patch.dict(
            os.environ,
            {"STUBSMITH_API_KEY": "sk-x", "STUBSMITH_API_URL": "http://my-api:4000"},
        ):
            with patch("urllib.request.urlopen", return_value=mock_resp) as mopen:
                fixtures("GET /v1/test")
        url = mopen.call_args[0][0].full_url
        self.assertTrue(url.startswith("http://my-api:4000"))

    def test_invalid_pattern_no_space_raises_value_error(self):
        with self.assertRaises(ValueError):
            fixtures("NOSPACEATALL", api_key="sk-test")

    def test_invalid_pattern_empty_method_raises_value_error(self):
        with self.assertRaises(ValueError):
            fixtures(" /path", api_key="sk-test")

    def test_http_401_raises_runtime_error(self):
        err = urllib.error.HTTPError(
            url="http://localhost:3000/v1/fixtures",
            code=401,
            msg="Unauthorized",
            hdrs=None,
            fp=MagicMock(read=lambda: b'{"error":"invalid or missing auth"}'),
        )
        with patch("urllib.request.urlopen", side_effect=err):
            with self.assertRaises(RuntimeError) as ctx:
                fixtures("POST /v1/charges", api_url="http://localhost:3000", api_key="sk-bad")
        self.assertIn("401", str(ctx.exception))

    def test_http_404_raises_runtime_error(self):
        err = urllib.error.HTTPError(
            url="http://localhost:3000/v1/fixtures",
            code=404,
            msg="Not Found",
            hdrs=None,
            fp=MagicMock(read=lambda: b'{"error":"request type not found"}'),
        )
        with patch("urllib.request.urlopen", side_effect=err):
            with self.assertRaises(RuntimeError) as ctx:
                fixtures("GET /v1/charges/{id}", api_url="http://localhost:3000", api_key="sk-t", limit=1)
        self.assertIn("404", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
