"""The SDK sends its own traffic only over https, or plain http to this machine."""

from __future__ import annotations

import http.server
import logging
import threading
import urllib.error
import urllib.request

import pytest

from stubsmith import cli
from stubsmith._endpoint import InsecureEndpointError, check_endpoint
from stubsmith.client import StubSmith
from stubsmith.fixtures import fixtures
from stubsmith.privacy.rules_cache import RulesCache


@pytest.mark.parametrize(
    "url",
    [
        "https://ingest.stubsmith.dev/v1/captures",
        "HTTPS://app.stubsmith.dev/api",
        "http://localhost:3000",
        "http://LOCALHOST:3000/v1/captures",
        "http://127.0.0.1:8080",
        "http://[::1]:8080/api",
    ],
)
def test_https_and_local_http_are_accepted(url):
    check_endpoint(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://ingest.stubsmith.dev/v1/captures",
        "http://api.example.com:8080",
        "http://127.0.0.2",
        "http://localhost.example.com",
        "http://10.0.0.5:3000",
        "ftp://app.stubsmith.dev",
        "file:///etc/passwd",
        "app.stubsmith.dev/api",
        "https://",
        "",
    ],
)
def test_plaintext_and_other_schemes_are_refused(url):
    with pytest.raises(InsecureEndpointError):
        check_endpoint(url)


def test_refusal_message_does_not_echo_credentials():
    with pytest.raises(InsecureEndpointError) as info:
        check_endpoint("http://user:hunter2@api.example.com/v1")
    assert "hunter2" not in str(info.value)
    assert "http://api.example.com" in str(info.value)


@pytest.fixture
def no_network(monkeypatch):
    calls = []

    def open_(self, req, *args, **kwargs):
        calls.append(getattr(req, "full_url", req))
        raise AssertionError("the SDK opened a connection")

    monkeypatch.setattr(urllib.request, "urlopen", lambda req, *a, **k: open_(None, req))
    monkeypatch.setattr(urllib.request.OpenerDirector, "open", open_)
    return calls


@pytest.mark.parametrize(
    "kwargs",
    [
        {"url": "http://ingest.example.com/v1/captures"},
        {"url": "https://ingest.example.com/v1/captures", "backend_url": "http://api.example.com"},
    ],
)
def test_client_with_plaintext_url_turns_capture_off_and_warns(kwargs, caplog, no_network):
    with caplog.at_level(logging.WARNING, logger="stubsmith"):
        client = StubSmith(api_key="sk-test", **kwargs)
    try:
        assert client.enabled is False
        assert client._rules_cache is None
        assert any("Capture is off" in r.getMessage() for r in caplog.records)
        client.enqueue({"method": "GET", "path": "/"})
        assert client._queue.qsize() == 0
    finally:
        client.close()
    assert no_network == []


def test_send_refuses_plaintext_url_set_after_start(no_network):
    # enabled=False keeps the rules poller from starting; _do_send is the sender's own call.
    client = StubSmith(url="https://ingest.example.com/v1/captures", api_key="sk-test", enabled=False)
    try:
        client.url = "http://ingest.example.com/v1/captures"
        with pytest.raises(InsecureEndpointError):
            client._do_send({"method": "GET", "path": "/"})
    finally:
        client.close()
    assert no_network == []


def test_rules_sync_does_not_connect_to_plaintext_backend(no_network):
    cache = RulesCache(api_key="sk-test", backend_url="http://api.example.com")
    assert cache._http_get("http://api.example.com/v1/sdk/sync?cursor=0") == (0, None)
    assert no_network == []


def test_fixtures_refuses_plaintext_api_url(no_network):
    with pytest.raises(InsecureEndpointError):
        fixtures("GET /v1/test", api_key="sk-test", api_url="http://api.example.com")
    assert no_network == []


def test_pull_refuses_plaintext_api_url(no_network):
    with pytest.raises(InsecureEndpointError):
        cli._fetch_bundle("http://api.example.com", "sk-test")
    assert no_network == []


# ---------------------------------------------------------------------------
# Redirects: urllib would re-send the Authorization header to the target.
# ---------------------------------------------------------------------------


class _Server:
    """A local HTTP server that records each request and answers with *respond*."""

    def __init__(self, respond):
        self.seen = []
        seen = self.seen

        class Handler(http.server.BaseHTTPRequestHandler):
            def _handle(self):
                length = int(self.headers.get("content-length") or 0)
                if length:
                    self.rfile.read(length)
                seen.append((self.command, self.path, self.headers.get("authorization")))
                status, headers = respond()
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("content-length", "0")
                self.end_headers()

            do_GET = do_POST = _handle

            def log_message(self, *args):
                pass

        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def redirecting():
    # The target is an allowed local host on purpose: no redirect is followed at
    # all, so a plaintext or foreign target can never receive the key either.
    target = _Server(lambda: (200, {"content-type": "application/json"}))
    origin = _Server(lambda: (302, {"location": f"http://localhost:{target.port}/x"}))
    yield f"http://127.0.0.1:{origin.port}", origin, target
    origin.close()
    target.close()


def test_capture_send_does_not_follow_a_redirect(redirecting):
    base, origin, target = redirecting
    client = StubSmith(url=base + "/v1/captures", api_key="sk-secret", enabled=False)
    try:
        with pytest.raises(urllib.error.HTTPError) as info:
            client._do_send({"method": "GET", "path": "/"})
        assert info.value.code == 302
    finally:
        client.close()
    assert len(origin.seen) == 1
    assert target.seen == []


def test_rules_sync_does_not_follow_a_redirect(redirecting):
    base, origin, target = redirecting
    cache = RulesCache(api_key="sk-secret", backend_url=base)
    status, _ = cache._http_get(base + "/v1/sdk/sync?cursor=0")
    assert status == 302
    assert len(origin.seen) == 1
    assert target.seen == []


def test_fixtures_does_not_follow_a_redirect(redirecting):
    base, origin, target = redirecting
    with pytest.raises(RuntimeError):
        fixtures("GET /v1/test", api_key="sk-secret", api_url=base)
    assert len(origin.seen) == 1
    assert target.seen == []


def test_pull_does_not_follow_a_redirect(redirecting):
    base, origin, target = redirecting
    with pytest.raises(RuntimeError):
        cli._fetch_bundle(base, "sk-secret")
    assert len(origin.seen) == 1
    assert target.seen == []
