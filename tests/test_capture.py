"""
Offline tests for the StubSmith Python SDK.

All outbound network calls are intercepted by `responses` (for requests) and
`respx` (for httpx).  The SDK's ingest POST is replaced by an in-process sink
so no real network is used.
"""

from __future__ import annotations

import gzip
import json
import logging
import os
import sys
import time
import threading
import urllib.error
from typing import Any, Dict, List
from unittest.mock import patch

import pytest
import responses as responses_lib
import respx
import httpx
import requests

import stubsmith
from stubsmith.client import StubSmith, _SDK_USER_AGENT, _safe_read_requests_body, _safe_read_httpx_response_body
from stubsmith.privacy.rules_cache import RulesCache


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class CaptureSink:
    """Collects payloads sent by the background worker."""

    def __init__(self, raise_on_send: bool = False):
        self._payloads: List[Dict[str, Any]] = []
        self._raise_on_send = raise_on_send
        self._lock = threading.Lock()

    def __call__(self, payload: Dict[str, Any]) -> None:
        if self._raise_on_send:
            raise RuntimeError("simulated send failure")
        with self._lock:
            self._payloads.append(payload)

    def wait_for(self, count: int = 1, timeout: float = 3.0) -> List[Dict[str, Any]]:
        """Wait until at least *count* payloads arrive, then return all."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if len(self._payloads) >= count:
                    return list(self._payloads)
            time.sleep(0.02)
        raise TimeoutError(f"Expected {count} capture(s) but got {len(self._payloads)} after {timeout}s")


def make_client(raise_on_send: bool = False, **kwargs) -> tuple[StubSmith, CaptureSink]:
    sink = CaptureSink(raise_on_send=raise_on_send)
    client = StubSmith(
        url="http://stubsmith.test/v1/captures",
        api_key="sk-test-key",
        _send_fn=sink,
        **kwargs,
    )
    return client, sink


# ---------------------------------------------------------------------------
# Test 1 - requests: full capture (request + response fields + duration)
# ---------------------------------------------------------------------------

@responses_lib.activate
def test_requests_captures_request_and_response():
    responses_lib.add(
        responses_lib.POST,
        "https://api.example.com/orders",
        json={"id": 42},
        status=201,
        headers={"X-Response-Id": "abc"},
    )

    client, sink = make_client()
    client.instrument_requests()

    resp = requests.post(
        "https://api.example.com/orders",
        json={"item": "widget"},
        headers={"X-Tenant": "acme"},
    )
    assert resp.status_code == 201

    payloads = sink.wait_for(1)
    p = payloads[0]

    # source
    assert p["source"] == "python-requests"

    # request fields
    assert p["method"] == "POST"
    assert "path" in p, "payload must use key 'path'"
    # With the privacy pipeline active, 'path' is the templated path component
    # (e.g. '/orders') and 'domain' carries the host separately.
    assert "/orders" in p["path"]
    assert "url" not in p, "payload must NOT send 'url' key (Go ingest ignores it)"
    assert "X-Tenant" in p["headers"] or "x-tenant" in {k.lower() for k in p["headers"]}
    # With the privacy pipeline active, req_body is masked (novel fingerprint → mask_all).
    # Verify the body was captured and is valid JSON with the original key preserved
    # and the original VALUE absent (regression guard against silent raw-payload fallback).
    import json as _json
    assert p["req_body"]
    req_obj = _json.loads(p["req_body"])
    assert "item" in req_obj, "key must be preserved after masking"
    assert req_obj["item"] == "<masked>", "value must be masked, not raw"
    assert "widget" not in p["req_body"], "raw value must not appear in masked payload"

    # response fields
    assert p["status"] == 201
    assert p["resp_body"]  # body was captured (value is masked)
    resp_obj = _json.loads(p["resp_body"])
    assert resp_obj.get("id") == 0, "numeric value must be masked to 0"
    assert "42" not in p["resp_body"], "raw value must not appear in masked payload"
    assert any(k.lower() == "x-response-id" for k in p["resp_headers"])

    # timing
    assert isinstance(p["duration"], int)
    assert p["duration"] >= 0

    client.uninstrument()


# ---------------------------------------------------------------------------
# Test 2 - httpx sync: full capture
# ---------------------------------------------------------------------------

def test_httpx_sync_captures_request_and_response():
    with respx.mock:
        respx.post("https://api.example.com/items").mock(
            return_value=httpx.Response(
                200,
                json={"ok": True},
                headers={"X-Srv": "httpx-test"},
            )
        )

        client, sink = make_client()
        client.instrument_httpx()

        with httpx.Client() as http:
            resp = http.post(
                "https://api.example.com/items",
                json={"name": "foo"},
                headers={"X-Auth": "tok"},
            )
        assert resp.status_code == 200

        payloads = sink.wait_for(1)
        p = payloads[0]

        assert p["source"] == "python-httpx"
        assert p["method"] == "POST"
        assert "path" in p, "payload must use key 'path', not 'url'"
        # With the privacy pipeline active, 'path' is the path component only.
        assert "/items" in p["path"]
        assert "url" not in p, "payload must NOT send 'url' key (Go ingest ignores it)"
        assert p["status"] == 200
        assert isinstance(p["duration"], int) and p["duration"] >= 0
        # Pipeline masks body values (novel fingerprint); key preserved, value masked.
        import json as _json
        assert p["req_body"]
        req_obj = _json.loads(p["req_body"])
        assert "name" in req_obj, "key must be preserved after masking"
        assert req_obj["name"] == "<masked>", "value must be masked, not raw"
        assert "foo" not in p["req_body"], "raw value must not appear in masked payload"
        assert p["resp_body"]  # body captured but masked
        assert "true" not in p["resp_body"].lower(), "raw bool must not appear in masked payload"
        assert any(k.lower() == "x-srv" for k in p["resp_headers"])

        client.uninstrument()


# ---------------------------------------------------------------------------
# Test 2b - httpx async: full capture (mirrors sync assertions)
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_httpx_async_captures_request_and_response():
    with respx.mock:
        respx.post("https://async.example.com/submit").mock(
            return_value=httpx.Response(
                201,
                json={"result": "done"},
                headers={"X-Async-Srv": "yes"},
            )
        )

        client, sink = make_client()
        client.instrument_httpx()

        async with httpx.AsyncClient() as http:
            resp = await http.post(
                "https://async.example.com/submit",
                json={"async_key": "async_val"},
                headers={"X-Async-Auth": "bearer-async"},
            )
        assert resp.status_code == 201

        payloads = sink.wait_for(1)
        p = payloads[0]

        assert p["source"] == "python-httpx-async"
        assert p["method"] == "POST"
        assert "path" in p, "async payload must use key 'path'"
        # With the privacy pipeline active, 'path' is the path component only.
        assert "/submit" in p["path"]
        assert "url" not in p, "async payload must NOT send 'url' key"
        assert p["status"] == 201
        assert isinstance(p["duration"], int) and p["duration"] >= 0
        # request body: key preserved, value masked (regression guard)
        import json as _json
        assert p["req_body"]
        req_obj = _json.loads(p["req_body"])
        assert "async_key" in req_obj, "key must be preserved after masking"
        assert req_obj["async_key"] == "<masked>", "value must be masked, not raw"
        assert "async_val" not in p["req_body"], "raw value must not appear in masked payload"
        assert any(k.lower() == "x-async-auth" for k in p["headers"])
        # response body and headers (masked but captured)
        assert p["resp_body"]
        assert "done" not in p["resp_body"], "raw resp value must not appear in masked payload"
        assert any(k.lower() == "x-async-srv" for k in p["resp_headers"])

        client.uninstrument()


# ---------------------------------------------------------------------------
# Test 3 - sender errors are swallowed; instrumented call still succeeds
# ---------------------------------------------------------------------------

@responses_lib.activate
def test_sender_error_is_swallowed():
    responses_lib.add(
        responses_lib.GET,
        "https://api.example.com/ping",
        json={"pong": True},
        status=200,
    )

    # Sink raises on every call
    client, sink = make_client(raise_on_send=True)
    client.instrument_requests()

    # Must NOT raise even though the sink raises
    resp = requests.get("https://api.example.com/ping")
    assert resp.status_code == 200
    assert resp.json() == {"pong": True}

    # Give the worker a moment to attempt the send
    time.sleep(0.3)
    # No payloads were successfully delivered (sink raised), but no exception
    assert len(sink._payloads) == 0

    client.uninstrument()


# ---------------------------------------------------------------------------
# Test 4 - disabled client (no api_key): no capture, calls pass through
# ---------------------------------------------------------------------------

@responses_lib.activate
def test_disabled_no_capture_when_no_api_key():
    responses_lib.add(
        responses_lib.GET,
        "https://api.example.com/health",
        json={"status": "ok"},
        status=200,
    )

    # No api_key → auto-disabled
    sink = CaptureSink()
    client = StubSmith(
        url="http://stubsmith.test/v1/captures",
        api_key="",   # empty → disabled
        _send_fn=sink,
    )
    assert client.enabled is False

    client.instrument_requests()

    resp = requests.get("https://api.example.com/health")
    assert resp.status_code == 200

    # Allow any async activity to settle
    time.sleep(0.3)
    assert len(sink._payloads) == 0, "No captures should be sent when disabled"

    client.uninstrument()


# ---------------------------------------------------------------------------
# Test 4b - enabled=False explicit flag
# ---------------------------------------------------------------------------

@responses_lib.activate
def test_disabled_explicit_flag():
    responses_lib.add(
        responses_lib.GET,
        "https://api.example.com/noop",
        body=b"",
        status=200,
    )

    sink = CaptureSink()
    client = StubSmith(
        url="http://stubsmith.test/v1/captures",
        api_key="sk-key",
        enabled=False,
        _send_fn=sink,
    )
    assert client.enabled is False

    client.instrument_requests()
    requests.get("https://api.example.com/noop")
    time.sleep(0.3)
    assert len(sink._payloads) == 0

    client.uninstrument()


# ---------------------------------------------------------------------------
# Test 5 - stream-safety: requests._content=False guard
# ---------------------------------------------------------------------------

def test_requests_stream_guard_skips_body():
    """
    When a requests.Response has _content=False (streaming, not yet consumed
    by caller) the SDK must return "" and must NOT consume the stream.
    """
    resp = requests.models.Response()
    resp._content = False      # the streaming sentinel set by requests internals
    resp.status_code = 200

    body = _safe_read_requests_body(resp)

    assert body == "", f"Expected empty string for unconsumed stream, got {body!r}"
    # Sentinel must still be False - SDK did not consume it
    assert resp._content is False, "SDK must not consume the streaming response body"


# ---------------------------------------------------------------------------
# Test 6 - stream-safety: httpx is_stream_consumed=False guard
# ---------------------------------------------------------------------------

def test_httpx_stream_guard_skips_body():
    """
    When an httpx response has is_stream_consumed=False (caller has not read
    the body yet) the SDK must return "" and must not attempt to read .text.
    """

    class _FakeStreamingResponse:
        is_stream_consumed = False
        is_closed = False

        @property
        def text(self):
            raise RuntimeError("SDK must not read .text on an unconsumed stream")

    body = _safe_read_httpx_response_body(_FakeStreamingResponse())
    assert body == "", f"Expected empty string for unconsumed httpx stream, got {body!r}"


# ---------------------------------------------------------------------------
# Test 7 - debug mode: send failure emits a WARNING log record
# ---------------------------------------------------------------------------

@responses_lib.activate
def test_debug_on_send_failure_logs_http_status(caplog):
    """
    When debug=True and the ingest POST returns an HTTP error, a WARNING
    record is emitted containing the exception class and status code.
    Payload content and the API key must never appear in the log.
    """
    responses_lib.add(
        responses_lib.GET,
        "https://api.example.com/debug-ping",
        json={"pong": True},
        status=200,
    )

    def _raise_http_error(payload):
        raise urllib.error.HTTPError(
            "http://stubsmith.test/v1/captures",
            401,
            "Unauthorized",
            {},
            None,
        )

    client = StubSmith(
        url="http://stubsmith.test/v1/captures",
        api_key="sk-test-debug-key",
        _send_fn=_raise_http_error,
        debug=True,
    )
    client.instrument_requests()

    with caplog.at_level(logging.WARNING, logger="stubsmith"):
        resp = requests.get("https://api.example.com/debug-ping")
        assert resp.status_code == 200
        # Give the background worker time to process the queued payload.
        time.sleep(0.5)

    client.uninstrument()
    client.close()

    warn_records = [
        r for r in caplog.records
        if r.levelno >= logging.WARNING and r.name == "stubsmith"
    ]
    assert warn_records, "Expected at least one WARNING log record from 'stubsmith'"
    combined = " ".join(r.getMessage() for r in warn_records)

    # Must contain the HTTP status code.
    assert "401" in combined, f"Expected '401' in log output; got: {combined!r}"

    # Must NEVER contain API key or payload content.
    assert "sk-test-debug-key" not in combined, "API key must not appear in logs"
    assert "pong" not in combined, "Response payload value must not appear in logs"


@responses_lib.activate
def test_debug_on_send_failure_generic_exception(caplog):
    """
    When debug=True and _send_fn raises a non-HTTP exception, a WARNING record
    is emitted with the exception class and target URL, never the payload.
    """
    responses_lib.add(
        responses_lib.GET,
        "https://api.example.com/debug-ping2",
        json={"value": "secret-data"},
        status=200,
    )

    client, sink = make_client(raise_on_send=True, debug=True)
    client.instrument_requests()

    with caplog.at_level(logging.WARNING, logger="stubsmith"):
        resp = requests.get("https://api.example.com/debug-ping2")
        assert resp.status_code == 200
        time.sleep(0.5)

    client.uninstrument()
    client.close()

    warn_records = [
        r for r in caplog.records
        if r.levelno >= logging.WARNING and r.name == "stubsmith"
    ]
    assert warn_records, "Expected at least one WARNING log record"
    combined = " ".join(r.getMessage() for r in warn_records)

    # Must contain exception class.
    assert "RuntimeError" in combined, f"Expected 'RuntimeError' in log; got: {combined!r}"
    # Payload content must not appear.
    assert "secret-data" not in combined, "Payload value must not appear in logs"
    # API key must not appear.
    assert "sk-test-key" not in combined, "API key must not appear in logs"


# ---------------------------------------------------------------------------
# Test 8 - debug mode OFF (default): send failures are silent
# ---------------------------------------------------------------------------

@responses_lib.activate
def test_debug_off_send_failure_is_silent(monkeypatch, caplog):
    """
    When debug is off (the default), send failures produce no WARNING records
    from the 'stubsmith' logger - existing silent-swallow behaviour is preserved.
    """
    # Ensure STUBSMITH_DEBUG is absent so a developer/CI env with it set to 1
    # cannot activate debug mode and break this assertion.
    monkeypatch.delenv("STUBSMITH_DEBUG", raising=False)

    responses_lib.add(
        responses_lib.GET,
        "https://api.example.com/debug-silent",
        json={"pong": True},
        status=200,
    )

    # No debug= argument → defaults to off (env var absent after monkeypatch).
    client, sink = make_client(raise_on_send=True)
    client.instrument_requests()

    with caplog.at_level(logging.WARNING, logger="stubsmith"):
        resp = requests.get("https://api.example.com/debug-silent")
        assert resp.status_code == 200
        time.sleep(0.5)

    client.uninstrument()
    client.close()

    # Scoped to the send path, which is what this test is about. The rules cache
    # runs on its own background thread and is not guaranteed to have stopped
    # when an earlier test's client was closed, so its records can land in this
    # test's caplog; they say nothing about whether a send failure was silent.
    warn_records = [
        r for r in caplog.records
        if r.levelno >= logging.WARNING
        and r.name == "stubsmith"
        and "rules_cache" not in r.pathname
    ]
    assert not warn_records, (
        f"Expected no WARNING records when debug is off, got: {warn_records}"
    )


# ---------------------------------------------------------------------------
# Test 9 - User-Agent header is sent on ingest POSTs
# ---------------------------------------------------------------------------

def test_do_send_sets_sdk_user_agent():
    """
    _do_send must include User-Agent: stubsmith-sdk/<version> on every POST.
    We patch urllib.request.urlopen to capture the Request object and inspect
    its headers without making a real network call.
    """
    from unittest.mock import patch, MagicMock

    captured: list = []

    def _fake_urlopen(req, timeout=None):
        captured.append(req)
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read = MagicMock(return_value=b"")
        return mock_resp

    client = StubSmith(
        url="http://stubsmith.test/v1/captures",
        api_key="sk-ua-test",
    )

    with patch("stubsmith.client.urllib.request.urlopen", side_effect=_fake_urlopen):
        client._do_send({"source": "test", "status": 200, "duration": 1})

    client.close()

    assert captured, "urlopen was not called"
    req = captured[0]
    # urllib stores explicitly-set headers with the first letter capitalised.
    ua = req.get_header("User-agent")
    assert ua == _SDK_USER_AGENT, (
        f"Expected User-Agent {_SDK_USER_AGENT!r}, got {ua!r}"
    )


# ---------------------------------------------------------------------------
# Test 10 - User-Agent header is sent on rules-cache GET requests
# ---------------------------------------------------------------------------

def test_rules_cache_sets_sdk_user_agent():
    """
    RulesCache._http_get must include User-Agent: stubsmith-sdk/<version>.
    """
    from unittest.mock import patch, MagicMock
    from stubsmith.privacy.rules_cache import _SDK_USER_AGENT as _RC_UA

    captured: list = []

    def _fake_urlopen(req, timeout=None):
        captured.append(req)
        raise urllib.error.HTTPError(
            req.full_url, 401, "Unauthorized", {}, None
        )

    cache = RulesCache(
        api_key="sk-ua-test",
        backend_url="http://fake.test",
    )

    with patch("stubsmith.privacy.rules_cache.urllib.request.urlopen",
               side_effect=_fake_urlopen):
        cache._http_get("http://fake.test/v1/sdk/sync?cursor=0")

    assert captured, "urlopen was not called"
    req = captured[0]
    ua = req.get_header("User-agent")
    assert ua == _RC_UA, (
        f"Expected User-Agent {_RC_UA!r}, got {ua!r}"
    )
    # Both constants must agree on the version string.
    assert _SDK_USER_AGENT == _RC_UA, "client and rules_cache UA strings must match"


# ---------------------------------------------------------------------------
# Request Content-Type inference
#
# requests derives the Content-Type header from the body kwargs while
# *preparing* the request, which happens inside the patched Session.request
# call - after the wrapper has already read the caller's headers.  Without
# inference a json= call was captured as a JSON body with no content-type:
# the fingerprint's content-type dimension was permanently empty, exported
# fixtures misrepresented the request, and the same endpoint fingerprinted
# differently via requests than via httpx (which reports prepared headers).
# ---------------------------------------------------------------------------

def _req_content_type(payload: Dict[str, Any]) -> str:
    for k, v in (payload.get("headers") or {}).items():
        if k.lower() == "content-type":
            return v
    return ""


@responses_lib.activate
def test_json_body_capture_records_json_content_type():
    responses_lib.add(responses_lib.POST, "https://api.example.com/orders",
                      json={"ok": True}, status=201)
    client, sink = make_client()
    client.instrument_requests()

    requests.post("https://api.example.com/orders", json={"item": "widget"})

    p = sink.wait_for(1)[0]
    assert _req_content_type(p) == "application/json"


@responses_lib.activate
def test_form_dict_body_is_form_encoded_not_json():
    """data={...} must be captured the way requests sends it: urlencoded.

    Serialising it as JSON while declaring a form content-type made the
    key-path extractor run parse_qs over a JSON string, so the payload's
    *values* became the key-path - a new fingerprint on every call.
    """
    responses_lib.add(responses_lib.POST, "https://api.example.com/webhook",
                      json={"ok": True}, status=200)
    client, sink = make_client()
    client.instrument_requests()

    requests.post("https://api.example.com/webhook",
                  data={"event": "payment.paid", "id": "ch_1"})

    p = sink.wait_for(1)[0]
    assert _req_content_type(p) == "application/x-www-form-urlencoded"
    assert not p["req_body"].startswith("{"), "form body must not be JSON-serialised"
    assert "event=" in p["req_body"]
    # Keys survive masking; values do not.
    assert "payment.paid" not in p["req_body"]


@responses_lib.activate
def test_form_dict_fingerprint_is_stable_across_values():
    responses_lib.add(responses_lib.POST, "https://api.example.com/webhook",
                      json={"ok": True}, status=200)
    client, sink = make_client()
    client.instrument_requests()

    requests.post("https://api.example.com/webhook",
                  data={"event": "payment.paid", "id": "ch_1"})
    requests.post("https://api.example.com/webhook",
                  data={"event": "payment.failed", "id": "ch_99999"})

    payloads = sink.wait_for(2)
    assert payloads[0]["req_fingerprint"] == payloads[1]["req_fingerprint"], (
        "form-encoded bodies must fingerprint on keys only, not values"
    )


@responses_lib.activate
def test_explicit_content_type_is_not_overridden():
    responses_lib.add(responses_lib.POST, "https://api.example.com/graphql",
                      json={"ok": True}, status=200)
    client, sink = make_client()
    client.instrument_requests()

    requests.post("https://api.example.com/graphql",
                  data='{"query":"{ me { id } }"}',
                  headers={"Content-Type": "application/graphql"})

    p = sink.wait_for(1)[0]
    assert _req_content_type(p) == "application/graphql"


@responses_lib.activate
def test_raw_string_body_gets_no_inferred_content_type():
    """requests sets no Content-Type for a str/bytes body, so neither do we."""
    responses_lib.add(responses_lib.POST, "https://api.example.com/raw",
                      json={"ok": True}, status=200)
    client, sink = make_client()
    client.instrument_requests()

    requests.post("https://api.example.com/raw", data="plain text payload")

    p = sink.wait_for(1)[0]
    assert _req_content_type(p) == ""


@responses_lib.activate
def test_bodyless_get_gets_no_content_type():
    responses_lib.add(responses_lib.GET, "https://api.example.com/products",
                      json={"ok": True}, status=200)
    client, sink = make_client()
    client.instrument_requests()

    requests.get("https://api.example.com/products")

    p = sink.wait_for(1)[0]
    assert _req_content_type(p) == ""


@responses_lib.activate
def test_requests_and_httpx_agree_on_json_fingerprint():
    """The same JSON call must fingerprint identically through either client."""
    responses_lib.add(responses_lib.POST, "https://api.example.com/orders",
                      json={"ok": True}, status=201)
    client, sink = make_client()
    client.instrument_requests()
    requests.post("https://api.example.com/orders", json={"item": "widget"})
    requests_fp = sink.wait_for(1)[0]["req_fingerprint"]
    client.uninstrument()

    with respx.mock:
        respx.post("https://api.example.com/orders").mock(
            return_value=httpx.Response(201, json={"ok": True})
        )
        client2, sink2 = make_client()
        client2.instrument_httpx()
        try:
            httpx.post("https://api.example.com/orders", json={"item": "widget"})
            httpx_fp = sink2.wait_for(1)[0]["req_fingerprint"]
        finally:
            client2.uninstrument()

    assert requests_fp == httpx_fp


def test_effective_content_type_helper_precedence():
    from stubsmith.client import _effective_request_content_type as ct

    assert ct({"json": {"a": 1}}, {}) == "application/json"
    assert ct({"data": {"a": 1}}, {}) == "application/x-www-form-urlencoded"
    assert ct({"data": [("a", 1), ("b", 2)]}, {}) == "application/x-www-form-urlencoded"
    assert ct({"files": {"f": b"x"}}, {}) == "multipart/form-data"
    # data= wins over json=, mirroring requests
    assert ct({"data": "raw", "json": {"a": 1}}, {}) == ""
    # explicit header wins, in any casing
    assert ct({"json": {"a": 1}}, {"content-type": "application/vnd.api+json"}) == ""
    assert ct({"json": {"a": 1}}, {"Content-Type": "application/vnd.api+json"}) == ""
    # nothing to infer
    assert ct({}, {}) == ""
    assert ct({"data": None, "json": None}, {}) == ""


@responses_lib.activate
def test_multipart_upload_records_type_but_no_fabricated_body():
    """files= sends a multipart body we cannot reconstruct.

    Recording the form fields instead would put a body in the capture (and in
    exported fixtures) that never went over the wire.
    """
    responses_lib.add(responses_lib.POST, "https://api.example.com/upload",
                      json={"ok": True}, status=201)
    client, sink = make_client()
    client.instrument_requests()

    requests.post("https://api.example.com/upload",
                  files={"file": ("a.txt", b"hello")},
                  data={"folder": "invoices"})

    p = sink.wait_for(1)[0]
    assert _req_content_type(p) == "multipart/form-data"
    # mask_all fail-closes an unrepresentable body to the placeholder, which is
    # honest - there WAS a body.  What must not happen is the form fields being
    # reported as though they were the wire payload.
    assert p["req_body"] == "<masked>"
    assert "folder" not in p["req_body"]
    assert "invoices" not in p["req_body"]
    # Extracted key-paths must not claim structure the request did not send.
    assert not p.get("key_paths")


# ---------------------------------------------------------------------------
# Tests - requests params= fingerprint (fix for query-param-blind bug)
#
# Before 0.6.0, params= was merged into the URL by PreparedRequest.prepare()
# inside Session.request, after the SDK had already captured the caller-supplied
# URL.  Query parameter names therefore never reached the fingerprinter when
# requests was used, while the httpx path captured them correctly.
# ---------------------------------------------------------------------------

@responses_lib.activate
def test_requests_params_included_in_fingerprint():
    """params= query parameter names must appear in the request fingerprint."""
    responses_lib.add(responses_lib.GET, "https://api.example.com/search",
                      json={"results": []}, status=200)

    client, sink = make_client()
    client.instrument_requests()

    requests.get("https://api.example.com/search", params={"q": "widgets", "page": "1"})

    p = sink.wait_for(1)[0]
    client.uninstrument()

    # The fingerprint must differ from a plain GET /search with no params -
    # derive the no-params fingerprint directly and compare.
    from stubsmith.privacy.fingerprint import fingerprint as _fp
    plain_fp = _fp("", "", "")
    assert p["req_fingerprint"] != plain_fp, (
        "params= names must affect the fingerprint; got same digest as no-params"
    )


@responses_lib.activate
def test_requests_params_fingerprint_stable_across_values_differs_across_names():
    """Different param names → different fingerprint; same names, different values → same."""
    responses_lib.add(responses_lib.GET, "https://api.example.com/items",
                      json={}, status=200)

    client, sink = make_client()
    client.instrument_requests()

    # Two calls with the same param names but different values.
    requests.get("https://api.example.com/items", params={"status": "active", "limit": "10"})
    requests.get("https://api.example.com/items", params={"status": "archived", "limit": "50"})
    # Third call with a different param name.
    requests.get("https://api.example.com/items", params={"filter": "active", "limit": "10"})

    payloads = sink.wait_for(3)
    client.uninstrument()

    fp_same_names_1 = payloads[0]["req_fingerprint"]
    fp_same_names_2 = payloads[1]["req_fingerprint"]
    fp_diff_names   = payloads[2]["req_fingerprint"]

    assert fp_same_names_1 == fp_same_names_2, (
        "same param names with different values must produce identical fingerprints"
    )
    assert fp_same_names_1 != fp_diff_names, (
        "different param names must produce different fingerprints"
    )


@responses_lib.activate
def test_requests_and_httpx_agree_on_params_fingerprint():
    """Parity regression guard: requests params= and httpx params= must fingerprint identically."""
    responses_lib.add(responses_lib.GET, "https://api.example.com/products",
                      json={"items": []}, status=200)

    client_req, sink_req = make_client()
    client_req.instrument_requests()

    requests.get("https://api.example.com/products", params={"category": "tools", "page": "2"})
    req_fp = sink_req.wait_for(1)[0]["req_fingerprint"]
    client_req.uninstrument()

    with respx.mock:
        respx.get("https://api.example.com/products").mock(
            return_value=httpx.Response(200, json={"items": []})
        )
        client_hx, sink_hx = make_client()
        client_hx.instrument_httpx()
        try:
            httpx.get("https://api.example.com/products",
                      params={"category": "tools", "page": "2"})
            hx_fp = sink_hx.wait_for(1)[0]["req_fingerprint"]
        finally:
            client_hx.uninstrument()

    assert req_fp == hx_fp, (
        f"requests and httpx must produce identical fingerprints for the same "
        f"logical request; got requests={req_fp!r} httpx={hx_fp!r}"
    )


@responses_lib.activate
def test_requests_no_params_fingerprint_unchanged():
    """A GET with no params= must fingerprint exactly as before (no regression)."""
    responses_lib.add(responses_lib.GET, "https://api.example.com/status",
                      json={"ok": True}, status=200)

    client, sink = make_client()
    client.instrument_requests()

    requests.get("https://api.example.com/status")

    p = sink.wait_for(1)[0]
    client.uninstrument()

    from stubsmith.privacy.fingerprint import fingerprint as _fp
    expected = _fp("", "", "")
    assert p["req_fingerprint"] == expected, (
        f"no-params GET must still fingerprint as empty body+query+ct; "
        f"got {p['req_fingerprint']!r}"
    )


@responses_lib.activate
def test_requests_params_redirect_uses_first_request_url():
    """When history is non-empty, the captured URL is from history[0] (the first request)."""
    # Simulate a redirect: the first response is 301 → the second is 200.
    responses_lib.add(
        responses_lib.GET,
        "https://api.example.com/old",
        status=301,
        headers={"Location": "https://api.example.com/new"},
    )
    responses_lib.add(
        responses_lib.GET,
        "https://api.example.com/new",
        json={"ok": True},
        status=200,
    )

    client, sink = make_client()
    client.instrument_requests()

    requests.get("https://api.example.com/old", params={"token": "abc"})

    p = sink.wait_for(1)[0]
    client.uninstrument()

    # The fingerprint must come from the first request (/old), not the redirect
    # target (/new).  The path in the payload reflects the pipeline-processed URL.
    assert "old" in p["path"], (
        f"expected first-request path '/old' in payload, got path={p['path']!r}"
    )
    # Critically, the query parameter name must have survived through the wire-URL
    # derivation - this is the assertion that distinguishes "used history[0]" from
    # "fell back to the caller-supplied url" (both have path /old, but only the
    # history-derived URL carries the merged query string).
    assert "token" in p.get("query_names", []), (
        f"query param name 'token' must appear in query_names after redirect; "
        f"got query_names={p.get('query_names')!r}"
    )


# ---------------------------------------------------------------------------
# Exit latency
#
# The at-exit flush runs on every process exit, including short-lived scripts,
# CI jobs and serverless invocations. Waiting the full explicit-flush budget
# because the ingest host is unreachable charges an outage to the application,
# so the at-exit budget is separate, small, configurable, and abandoned as soon
# as a send is known to have failed.
# ---------------------------------------------------------------------------

def test_flush_timeout_priority(monkeypatch):
    from stubsmith.client import _ATEXIT_FLUSH_TIMEOUT, _resolve_flush_timeout

    monkeypatch.delenv("STUBSMITH_FLUSH_TIMEOUT", raising=False)
    assert _resolve_flush_timeout(None) == _ATEXIT_FLUSH_TIMEOUT
    assert _resolve_flush_timeout(2.5) == 2.5

    monkeypatch.setenv("STUBSMITH_FLUSH_TIMEOUT", "0.25")
    assert _resolve_flush_timeout(None) == 0.25
    assert _resolve_flush_timeout(3.0) == 3.0, "explicit argument must win over env"


def test_flush_timeout_zero_is_honoured(monkeypatch):
    """0 must disable the wait, not fall through to the default.

    The env var is cleared for the argument case: with it set to "0" a falsy
    check on the argument returns 0.0 anyway, via the env, and the bug hides.
    """
    from stubsmith.client import _ATEXIT_FLUSH_TIMEOUT, _resolve_flush_timeout

    monkeypatch.setenv("STUBSMITH_FLUSH_TIMEOUT", "0")
    assert _resolve_flush_timeout(None) == 0.0

    monkeypatch.delenv("STUBSMITH_FLUSH_TIMEOUT", raising=False)
    assert _ATEXIT_FLUSH_TIMEOUT != 0.0, "default must differ or this proves nothing"
    assert _resolve_flush_timeout(0) == 0.0
    assert _resolve_flush_timeout(0.0) == 0.0


def test_flush_timeout_rejects_junk_without_raising(monkeypatch):
    """A malformed env var must not break the application being instrumented."""
    from stubsmith.client import _ATEXIT_FLUSH_TIMEOUT, _resolve_flush_timeout

    monkeypatch.setenv("STUBSMITH_FLUSH_TIMEOUT", "soon")
    assert _resolve_flush_timeout(None) == _ATEXIT_FLUSH_TIMEOUT
    monkeypatch.setenv("STUBSMITH_FLUSH_TIMEOUT", "-4")
    assert _resolve_flush_timeout(None) == 0.0


def test_atexit_budget_is_below_the_explicit_flush_budget():
    from stubsmith.client import _ATEXIT_FLUSH_TIMEOUT, _FLUSH_TIMEOUT

    assert _ATEXIT_FLUSH_TIMEOUT < _FLUSH_TIMEOUT


def test_flush_abandons_the_wait_once_a_send_fails():
    """With an unreachable endpoint the queue cannot drain, so flush must give
    up rather than spend its whole budget.

    The send has to fail *slowly* to model a real outage: a connection to a
    blackholed host blocks until the socket timeout. A send that fails instantly
    empties the queue faster than the wait, which hides whether the early exit
    works at all.
    """
    def slow_failing_send(payload):
        time.sleep(0.5)
        raise RuntimeError("simulated network timeout")

    client = StubSmith(
        url="http://stubsmith.test/v1/captures",
        api_key="sk-test-key",
        _send_fn=slow_failing_send,
    )
    for _ in range(20):
        client.enqueue({"payload": 1})

    t0 = time.monotonic()
    client.flush(timeout=5.0)
    elapsed = time.monotonic() - t0

    client.close()
    # 20 items at 0.5s each cannot drain inside the 5s budget, so a flush that
    # runs to its deadline takes the full 5s.
    assert elapsed < 2.0, f"flush waited {elapsed:.2f}s despite failing sends"


def test_flush_still_drains_a_healthy_queue():
    """The early exit must not stop delivery when sends are succeeding."""
    client, sink = make_client()
    for _ in range(20):
        client.enqueue({"payload": 1})

    client.flush(timeout=5.0)
    client.close()
    assert len(sink.wait_for(20)) == 20


# ---------------------------------------------------------------------------
# Session.send: a caller that prepares its own request
#
# Session.request routes through send(), and send() re-enters itself once per
# redirect hop, so the patch has to capture in the outermost frame only. A
# caller reaching send() directly bypasses request() entirely and was invisible
# before.
# ---------------------------------------------------------------------------

@responses_lib.activate
def test_prepared_request_sent_through_send_is_captured():
    responses_lib.add(
        responses_lib.POST,
        "https://api.example.com/orders",
        json={"id": 7},
        status=201,
    )

    client, sink = make_client()
    client.instrument_requests()
    try:
        session = requests.Session()
        prepared = session.prepare_request(
            requests.Request(
                "POST",
                "https://api.example.com/orders",
                json={"item": "widget"},
                headers={"X-Tenant": "acme"},
            )
        )
        resp = session.send(prepared)
        assert resp.status_code == 201

        payloads = sink.wait_for(1)
        assert len(payloads) == 1, payloads
        p = payloads[0]
        assert p["method"] == "POST"
        assert "/orders" in p["path"]
        assert "item" in p["req_body"], "the prepared body was not captured"
        assert "widget" not in p["req_body"], "the value must be masked"
        assert "X-Tenant" in p["headers"] or "x-tenant" in {k.lower() for k in p["headers"]}
    finally:
        client.uninstrument()
        client.close()


@responses_lib.activate
def test_a_single_call_is_captured_once_not_twice():
    """request() calls send(), and both are patched."""
    responses_lib.add(
        responses_lib.GET, "https://api.example.com/ping", json={"ok": True}, status=200,
    )

    client, sink = make_client()
    client.instrument_requests()
    try:
        requests.get("https://api.example.com/ping")
        payloads = sink.wait_for(1)
        time.sleep(0.15)  # give a duplicate time to arrive
        assert len(payloads) == 1, payloads
    finally:
        client.uninstrument()
        client.close()


@responses_lib.activate
def test_a_redirect_chain_is_captured_once():
    """resolve_redirects calls self.send() per hop; each hop must not capture."""
    responses_lib.add(
        responses_lib.GET,
        "https://api.example.com/old",
        status=302,
        headers={"Location": "https://api.example.com/new"},
    )
    responses_lib.add(
        responses_lib.GET, "https://api.example.com/new", json={"ok": True}, status=200,
    )

    client, sink = make_client()
    client.instrument_requests()
    try:
        resp = requests.get("https://api.example.com/old")
        assert resp.status_code == 200
        assert len(resp.history) == 1
        payloads = sink.wait_for(1)
        time.sleep(0.15)
        assert len(payloads) == 1, payloads
        # The capture describes the request the caller made, not the hop it
        # landed on, matching the httpx instrumentation.
        assert "/old" in payloads[0]["path"]
    finally:
        client.uninstrument()
        client.close()


@responses_lib.activate
def test_a_streaming_body_is_not_consumed_by_the_send_patch():
    """Reading a generator body in order to capture it would leave the real
    request with nothing to send. The invariant is that instrumenting changes
    nothing about how much of the body is pulled, so the uninstrumented call is
    the baseline rather than a hard-coded expectation about the transport."""
    responses_lib.add(
        responses_lib.POST, "https://api.example.com/upload", json={}, status=200,
    )
    responses_lib.add(
        responses_lib.POST, "https://api.example.com/upload", json={}, status=200,
    )

    def send_one():
        pulled: List[bytes] = []

        def chunks():
            for part in (b"part-one", b"part-two"):
                pulled.append(part)
                yield part

        session = requests.Session()
        prepared = session.prepare_request(
            requests.Request("POST", "https://api.example.com/upload", data=chunks())
        )
        session.send(prepared)
        return pulled, prepared

    baseline_pulled, _ = send_one()

    client, sink = make_client()
    client.instrument_requests()
    try:
        instrumented_pulled, prepared = send_one()
        payloads = sink.wait_for(1)
        assert payloads[0]["req_body"] in ("", "<masked>"), payloads[0]["req_body"]
        assert instrumented_pulled == baseline_pulled, (
            f"instrumentation changed body consumption: "
            f"{instrumented_pulled!r} vs baseline {baseline_pulled!r}"
        )
        # The body is still whatever requests put there, not a string the SDK
        # substituted while reading it.
        assert not isinstance(prepared.body, (str, bytes, bytearray))
    finally:
        client.uninstrument()
        client.close()


def test_uninstrument_restores_both_patch_points():
    original_request = requests.Session.request
    original_send = requests.Session.send

    client, _ = make_client()
    client.instrument_requests()
    assert requests.Session.request is not original_request
    assert requests.Session.send is not original_send
    client.uninstrument()
    try:
        assert requests.Session.request is original_request
        assert requests.Session.send is original_send
    finally:
        client.close()


# ---------------------------------------------------------------------------
# install() idempotency and fork safety
#
# install() is called from application startup, but plugin registries and
# framework hooks can fire it repeatedly in one process. Each call used to build
# another client with its own sender thread, rules-cache poller, atexit hook and
# 60-second backend poll; captures were never duplicated, but the threads
# accumulated and every client except the most recent was inert while still
# polling.
# ---------------------------------------------------------------------------

def test_repeated_install_returns_one_client():
    import stubsmith

    first = stubsmith.install(url="http://stubsmith.test/v1/captures", api_key="sk-test")
    try:
        for _ in range(4):
            assert stubsmith.install(url="http://other.test/v1/captures", api_key="sk-x") is first
    finally:
        first.close()


def test_repeated_install_does_not_accumulate_threads():
    import stubsmith

    def sdk_threads():
        return [t.name for t in threading.enumerate() if t.name.startswith("stubsmith-")]

    baseline = len(sdk_threads())
    client = stubsmith.install(url="http://stubsmith.test/v1/captures", api_key="sk-test")
    try:
        after_first = len(sdk_threads())
        for _ in range(4):
            stubsmith.install(url="http://stubsmith.test/v1/captures", api_key="sk-test")
        assert len(sdk_threads()) == after_first, sdk_threads()
        # Sanity: the first install really did start threads, so the assertion
        # above is not comparing zero with zero.
        assert after_first > baseline
    finally:
        client.close()


def test_install_after_close_builds_a_new_client():
    """A closed client must not be handed back inert."""
    import stubsmith

    first = stubsmith.install(url="http://stubsmith.test/v1/captures", api_key="sk-test")
    first.close()
    second = stubsmith.install(url="http://stubsmith.test/v1/captures", api_key="sk-test")
    try:
        assert second is not first
        assert second._worker.is_alive()
    finally:
        second.close()


def test_install_forwards_flush_timeout():
    """install() is the documented integration point, so every StubSmith
    setting has to be reachable through it. flush_timeout was reachable only by
    constructing StubSmith directly or by setting an environment variable, which
    a process that cannot control its own environment (an embedded plugin, a
    managed worker) has no way to do."""
    import stubsmith

    client = stubsmith.install(
        url="http://stubsmith.test/v1/captures", api_key="sk-test", flush_timeout=0,
    )
    try:
        assert client.flush_timeout == 0.0
    finally:
        client.close()


def test_is_installed_tracks_the_live_client():
    import stubsmith

    assert stubsmith.is_installed() is False
    client = stubsmith.install(url="http://stubsmith.test/v1/captures", api_key="sk-test")
    try:
        assert stubsmith.is_installed() is True
    finally:
        client.close()
    assert stubsmith.is_installed() is False


def test_is_installed_holds_where_the_module_level_helpers_do_not():
    """The obvious hand-rolled check - has requests.request been replaced? -
    reports a working install as broken, because only Session.request is
    patched and requests.request routes through a fresh Session. is_installed()
    exists so nobody has to know that."""
    import requests
    import stubsmith

    unpatched_helper = requests.request
    client = stubsmith.install(url="http://stubsmith.test/v1/captures", api_key="sk-test")
    try:
        assert requests.request is unpatched_helper
        assert requests.get.__module__ == "requests.api"
        assert hasattr(requests.Session, "_stubsmith_original_request")
        assert stubsmith.is_installed() is True
    finally:
        client.close()


@pytest.mark.skipif(
    not hasattr(os, "fork") or sys.platform == "darwin",
    reason=(
        "fork() in a multi-threaded process is unsupported on macOS: the "
        "Objective-C runtime aborts the child regardless of what the SDK does. "
        "Linux is where forking servers actually run, so that is where this is "
        "verified."
    ),
)
def test_captures_are_delivered_after_fork(tmp_path):
    """Threads do not survive fork(), so a child inherits a dead sender and a
    queue nothing drains. Under `gunicorn --preload`, uWSGI or Celery, install()
    runs in the master and every worker is forked, so without re-arming, every
    capture in every worker is enqueued and silently lost.
    """
    receipt = tmp_path / "sent.log"

    def send(payload):
        with open(receipt, "a") as fh:
            fh.write("sent\n")

    client = StubSmith(
        url="http://stubsmith.test/v1/captures", api_key="sk-test", _send_fn=send
    )
    try:
        pid = os.fork()
        if pid == 0:                                    # child
            try:
                client.enqueue({"probe": 1})
                client.flush(timeout=5.0)
            finally:
                os._exit(0)

        os.waitpid(pid, 0)
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and not receipt.exists():
            time.sleep(0.05)

        assert receipt.exists(), "the forked child delivered nothing"
        assert receipt.read_text().count("sent") == 1
    finally:
        client.close()


@pytest.mark.skipif(
    not hasattr(os, "fork") or sys.platform == "darwin",
    reason="see test_captures_are_delivered_after_fork",
)
def test_forked_child_starts_with_an_empty_queue(tmp_path):
    """The child inherits a copy of whatever was queued at fork time. The parent
    still holds those items and its own sender is running, so draining the
    child's copy would deliver each of them twice. The child therefore starts
    from an empty queue."""
    report = tmp_path / "qsize.txt"

    # A send that blocks keeps items in the parent's queue across the fork.
    gate = threading.Event()

    def blocking_send(payload):
        gate.wait(timeout=10)

    client = StubSmith(
        url="http://stubsmith.test/v1/captures",
        api_key="sk-test",
        _send_fn=blocking_send,
    )
    try:
        for i in range(5):
            client.enqueue({"probe": i})
        time.sleep(0.2)  # let the sender pick up the first and block on it
        queued_in_parent = client._queue.qsize()

        pid = os.fork()
        if pid == 0:
            try:
                report.write_text(str(client._queue.qsize()))
            finally:
                os._exit(0)

        os.waitpid(pid, 0)
        assert queued_in_parent > 0, "parent queue drained; the test proves nothing"
        assert report.read_text() == "0", (
            f"child inherited {report.read_text()} queued items and would resend them"
        )
    finally:
        gate.set()
        client.close()


# ---------------------------------------------------------------------------
# Bodies are never truncated
#
# Truncating to max_body_bytes sliced JSON mid-token and stored a document that
# cannot parse, with nothing in the payload to say so. A truncated capture was
# indistinguishable from an API that had genuinely returned malformed JSON, so
# a replayed sample raised JSONDecodeError and consumers attributed it upstream.
# ---------------------------------------------------------------------------

def _big_json(n: int = 3000) -> str:
    return json.dumps({"items": [{"sku": f"S{i:06d}", "qty": i} for i in range(n)]})


class TestBodiesAreNeverTruncated:
    @responses_lib.activate
    def test_a_body_far_over_the_old_cap_is_captured_whole_and_parses(self):
        body = _big_json()
        assert len(body) > 64 * 1024, "fixture must exceed the old 64 KiB cap"
        responses_lib.add(
            responses_lib.GET, "https://api.example.com/stock",
            body=body, status=200, content_type="application/json",
        )

        client, sink = make_client()
        client.instrument_requests()
        try:
            requests.get("https://api.example.com/stock")
            payload = sink.wait_for(1)[0]
        finally:
            client.uninstrument()
            client.close()

        # The decisive assertion: what we stored is a JSON document.
        json.loads(payload["resp_body"])
        assert not payload.get("bodies_omitted")

    @responses_lib.activate
    def test_max_body_bytes_no_longer_truncates(self):
        """The kwarg is still accepted for compatibility and must not cut."""
        body = _big_json()
        responses_lib.add(
            responses_lib.GET, "https://api.example.com/stock",
            body=body, status=200, content_type="application/json",
        )

        client, sink = make_client(max_body_bytes=1024)
        client.instrument_requests()
        try:
            requests.get("https://api.example.com/stock")
            payload = sink.wait_for(1)[0]
        finally:
            client.uninstrument()
            client.close()

        assert len(payload["resp_body"]) > 1024
        json.loads(payload["resp_body"])


class TestPayloadCeiling:
    def _payload(self, resp_body: str, path: str = "/huge") -> Dict[str, Any]:
        return {
            "method": "GET", "path_template": path, "sdk_masked": True,
            "req_body": "", "resp_body": resp_body,
        }

    def test_a_payload_over_the_ceiling_omits_both_bodies(self):
        """Both bodies, not just the larger, so the result does not depend on
        which side happened to be big and no consumer has to reason about a
        capture with one body present."""
        client, sink = make_client(max_payload_bytes=64 * 1024)
        try:
            client.enqueue(self._payload(_big_json(4000)))
            payload = sink.wait_for(1)[0]
        finally:
            client.close()

        assert payload["bodies_omitted"] is True
        assert payload["omitted_reason"] == "payload_too_large"
        assert payload["resp_body"] is None
        assert payload["req_body"] is None
        # Sizes travel with it so the dashboard can say how far over it is.
        assert payload["omitted_resp_body_bytes"] > 64 * 1024

    def test_the_capture_is_still_sent_so_the_shape_is_recorded(self):
        """Dropping the event would hide the endpoint entirely; ingest records
        the fingerprint and occurrence count from this metadata."""
        client, sink = make_client(max_payload_bytes=64 * 1024)
        try:
            client.enqueue(self._payload(_big_json(4000)))
            payload = sink.wait_for(1)[0]
        finally:
            client.close()
        assert payload["method"] == "GET"
        assert payload["path_template"] == "/huge"

    def test_a_payload_under_the_ceiling_is_untouched(self):
        client, sink = make_client(max_payload_bytes=10 * 1024 * 1024)
        try:
            client.enqueue(self._payload(json.dumps({"a": 1})))
            payload = sink.wait_for(1)[0]
        finally:
            client.close()
        assert "bodies_omitted" not in payload
        assert payload["resp_body"] == json.dumps({"a": 1})

    def test_the_warning_is_emitted_once_per_endpoint(self, caplog):
        """A hot loop must not flood stderr, but silence is what let the
        truncation bug live unnoticed, so it must be reported once."""
        client, sink = make_client(max_payload_bytes=64 * 1024)
        try:
            with caplog.at_level(logging.WARNING, logger="stubsmith"):
                for _ in range(5):
                    client.enqueue(self._payload(_big_json(4000)))
                client.enqueue(self._payload(_big_json(4000), path="/other"))
            sink.wait_for(6)
        finally:
            client.close()

        oversize = [r for r in caplog.records if "over the" in r.message]
        assert len(oversize) == 2, [r.message for r in oversize]
        assert any("/huge" in r.getMessage() for r in oversize)
        assert any("/other" in r.getMessage() for r in oversize)


class TestQueueByteBudget:
    """queue_maxsize bounds items, not bytes. With a megabyte-scale payload
    ceiling a full queue could hold gigabytes inside the host application."""

    def test_the_budget_blocks_a_capture_that_would_exceed_it(self):
        sink = CaptureSink()
        client = StubSmith(
            url="http://stubsmith.test/v1/captures", api_key="sk-test",
            _send_fn=sink, max_queue_bytes=4096, max_payload_bytes=10 * 1024 * 1024,
        )
        # Stop the worker so nothing drains and the budget stays committed.
        client._stop.set()
        client._worker.join(timeout=2)
        try:
            client.enqueue({"method": "GET", "path_template": "/a",
                            "resp_body": "x" * 8192})
            assert client._queue.qsize() == 0, "over-budget capture must not be queued"
            client.enqueue({"method": "GET", "path_template": "/b",
                            "resp_body": "y" * 16})
            assert client._queue.qsize() == 1, "a small capture must still fit"
        finally:
            client.close()

    def test_the_budget_is_released_after_a_send(self):
        client, sink = make_client(max_queue_bytes=1024 * 1024)
        try:
            for _ in range(5):
                client.enqueue({"method": "GET", "path_template": "/a",
                                "resp_body": "x" * 1000})
            sink.wait_for(5)
            client.flush(timeout=5)
            deadline = time.monotonic() + 2
            while client._queue_bytes != 0 and time.monotonic() < deadline:
                time.sleep(0.02)
            assert client._queue_bytes == 0, client._queue_bytes
        finally:
            client.close()

    def test_the_budget_is_released_even_when_every_send_fails(self):
        """A permanently failing endpoint must not leak the budget until
        nothing can be queued at all."""
        client, sink = make_client(raise_on_send=True, max_queue_bytes=1024 * 1024)
        try:
            for _ in range(5):
                client.enqueue({"method": "GET", "path_template": "/a",
                                "resp_body": "x" * 1000})
            deadline = time.monotonic() + 3
            while client._queue_bytes != 0 and time.monotonic() < deadline:
                time.sleep(0.02)
            assert client._queue_bytes == 0, client._queue_bytes
        finally:
            client.close()


# ---------------------------------------------------------------------------
# gzip on the capture POST
# ---------------------------------------------------------------------------

class TestSendCompression:
    def _post(self, client, payload):
        """Capture the urllib Request the client would send."""
        seen = {}

        class _Resp:
            def read(self):
                return b"{}"
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False

        def _urlopen(req, timeout=None):
            seen["headers"] = {k.lower(): v for k, v in req.headers.items()}
            seen["body"] = req.data
            return _Resp()

        with patch("urllib.request.urlopen", _urlopen):
            client._do_send(payload)
        return seen

    def test_a_large_payload_is_gzipped(self):
        client = StubSmith(url="http://stubsmith.test/v1/captures", api_key="sk-test")
        try:
            payload = {"resp_body": json.dumps({"items": [{"v": "<masked>"}] * 3000})}
            raw = json.dumps(payload).encode()
            seen = self._post(client, payload)

            assert seen["headers"].get("Content-encoding".lower()) == "gzip"
            assert gzip.decompress(seen["body"]) == raw
            # Masked bodies are near-pure redundancy; the point is the ratio.
            assert len(seen["body"]) < len(raw) / 10
        finally:
            client.close()

    def test_a_small_payload_is_not_gzipped(self):
        """Below the threshold gzip costs CPU and a header to save nothing."""
        client = StubSmith(url="http://stubsmith.test/v1/captures", api_key="sk-test")
        try:
            payload = {"resp_body": '{"a": 1}'}
            seen = self._post(client, payload)
            assert "content-encoding" not in seen["headers"]
            assert seen["body"] == json.dumps(payload).encode()
        finally:
            client.close()

    def test_a_compressible_payload_below_the_threshold_is_left_alone(self):
        """The distinguishing case for the threshold.

        A few hundred bytes of repeated text does compress, so the
        "only use it if smaller" guard would accept it. The threshold is what
        keeps the SDK from paying compression cost on payloads where the saving
        is a few hundred bytes and irrelevant.
        """
        client = StubSmith(url="http://stubsmith.test/v1/captures", api_key="sk-test")
        try:
            payload = {"resp_body": "<masked>" * 100}  # ~800 bytes, very compressible
            raw = json.dumps(payload).encode()
            assert len(raw) < 1024, len(raw)
            assert len(gzip.compress(raw)) < len(raw), "fixture must be compressible"

            seen = self._post(client, payload)
            assert "content-encoding" not in seen["headers"]
            assert seen["body"] == raw
        finally:
            client.close()

    def test_compression_can_be_disabled(self):
        client = StubSmith(url="http://stubsmith.test/v1/captures", api_key="sk-test",
                           compress=False)
        try:
            payload = {"resp_body": json.dumps({"items": [{"v": "<masked>"}] * 3000})}
            seen = self._post(client, payload)
            assert "content-encoding" not in seen["headers"]
            assert seen["body"] == json.dumps(payload).encode()
        finally:
            client.close()

    def test_the_ceiling_is_applied_before_compression(self):
        """Limiting compressed bytes would be a decompression bomb: masked data
        compresses ~200:1, so a payload under the limit compressed can expand to
        hundreds of megabytes on the server."""
        sink = CaptureSink()
        client = StubSmith(
            url="http://stubsmith.test/v1/captures", api_key="sk-test",
            _send_fn=sink, max_payload_bytes=64 * 1024,
        )
        try:
            # Compresses to far under the ceiling, but is over it uncompressed.
            body = json.dumps({"items": [{"v": "<masked>"} for _ in range(20000)]})
            assert len(gzip.compress(body.encode())) < 64 * 1024
            client.enqueue({"method": "GET", "path_template": "/x",
                            "req_body": "", "resp_body": body})
            payload = sink.wait_for(1)[0]
            assert payload["bodies_omitted"] is True, (
                "the ceiling must be judged on uncompressed bytes"
            )
        finally:
            client.close()
