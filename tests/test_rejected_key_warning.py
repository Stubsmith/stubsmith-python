"""
A rejected API key (HTTP 401 or 403) logs one WARNING per process.

Ingest and the rules sync both answer a bad key with 401 and a body the SDK
must not depend on, so the warning is triggered on the status code alone and
the two paths share one flag.

The ingest tests go through the real sender (enqueue, worker thread, urllib)
against a local HTTP server, and the sync tests run the real RulesCache
``_poll_once`` and ``_http_get``. Nothing in stubsmith is mocked.
"""

from __future__ import annotations

import http.server
import json
import logging
import threading
import time

import pytest

from stubsmith.client import StubSmith
from stubsmith.privacy.rules_cache import RulesCache

# Distinctive on purpose: every 4-character window of it is searched for in the
# log output, so it must not share windows with ordinary log words.
_KEY = "sk-Zq7xW9vK3mTR8pLd"
_DOCS = "https://docs.stubsmith.dev/#capturing"
_PAYLOAD = {"method": "GET", "path": "/v1/things", "status": 200}


class _Server:
    """Local server: POST answers text/plain, GET answers JSON, both with *status*."""

    def __init__(self, status: int):
        self.seen = []
        seen = self.seen

        class Handler(http.server.BaseHTTPRequestHandler):
            def _answer(self):
                length = int(self.headers.get("content-length") or 0)
                if length:
                    self.rfile.read(length)
                seen.append(self.command)
                if status == 200:
                    body = json.dumps({"ok": True, "cursor": "1", "rules": []}).encode()
                    ctype = "application/json"
                elif self.command == "POST":
                    body, ctype = b"invalid project token", "text/plain"
                else:
                    body = json.dumps({"error": "project key required"}).encode()
                    ctype = "application/json"
                self.send_response(status)
                self.send_header("content-type", ctype)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = _answer

            def log_message(self, *args):
                pass

        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server_factory():
    servers = []

    def make(status):
        servers.append(_Server(status))
        return servers[-1]

    yield make
    for s in servers:
        s.close()


def _wait_for_worker(client, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while client._queue.unfinished_tasks:
        if time.monotonic() > deadline:
            raise AssertionError("worker did not finish queued sends in time")
        time.sleep(0.01)


def _ingest(server, caplog, count=1, debug=False):
    """Send *count* captures through the real sender at *server*."""
    client = StubSmith(url=server.base + "/v1/captures", api_key=_KEY, debug=debug)
    try:
        with caplog.at_level(logging.DEBUG, logger="stubsmith"):
            for _ in range(count):
                client.enqueue(dict(_PAYLOAD))
                client.flush()
                _wait_for_worker(client)
    finally:
        client.close()


def _sync(server, count=1):
    cache = RulesCache(api_key=_KEY, backend_url=server.base)
    for _ in range(count):
        cache._poll_once()


def _rejected(caplog):
    return [
        r for r in caplog.records
        if r.name == "stubsmith" and r.levelno == logging.WARNING
        and "API key was rejected" in r.getMessage()
    ]


def test_one_rejected_ingest_request_warns_once(server_factory, caplog):
    server = server_factory(401)
    _ingest(server, caplog, count=1)

    records = _rejected(caplog)
    assert len(records) == 1
    msg = records[0].getMessage()
    assert "HTTP 401" in msg
    assert "STUBSMITH_API_KEY" in msg
    assert "api_key" in msg
    assert "Nothing is recorded" in msg
    assert _DOCS in msg
    assert "—" not in msg


def test_three_rejected_ingest_requests_still_warn_once(server_factory, caplog):
    server = server_factory(401)
    _ingest(server, caplog, count=3)

    assert server.seen.count("POST") == 3
    assert len(_rejected(caplog)) == 1


def test_accepted_requests_do_not_warn(server_factory, caplog):
    server = server_factory(200)
    _ingest(server, caplog, count=2)
    _sync(server, count=2)

    assert server.seen.count("POST") == 2
    assert server.seen.count("GET") == 2
    assert _rejected(caplog) == []


def test_403_also_warns(server_factory, caplog):
    server = server_factory(403)
    _ingest(server, caplog, count=2)

    records = _rejected(caplog)
    assert len(records) == 1
    assert "HTTP 403" in records[0].getMessage()


def test_rejected_sync_warns_once_without_debug(server_factory, caplog):
    server = server_factory(401)
    with caplog.at_level(logging.DEBUG, logger="stubsmith"):
        _sync(server, count=3)

    assert server.seen.count("GET") == 3
    records = _rejected(caplog)
    assert len(records) == 1
    assert "HTTP 401" in records[0].getMessage()


def test_ingest_then_sync_rejection_warns_once_in_total(server_factory, caplog):
    server = server_factory(401)
    _ingest(server, caplog, count=1)
    with caplog.at_level(logging.DEBUG, logger="stubsmith"):
        _sync(server, count=1)

    assert server.seen == ["POST", "GET"]
    assert len(_rejected(caplog)) == 1


def test_sync_then_ingest_rejection_warns_once_in_total(server_factory, caplog):
    server = server_factory(403)
    with caplog.at_level(logging.DEBUG, logger="stubsmith"):
        _sync(server, count=1)
    _ingest(server, caplog, count=1)

    assert server.seen == ["GET", "POST"]
    assert len(_rejected(caplog)) == 1


def test_reset_allows_the_warning_again(server_factory, caplog):
    from stubsmith._rejected_key import _reset_rejected_key_warning

    server = server_factory(401)
    _ingest(server, caplog, count=1)
    _reset_rejected_key_warning()
    _ingest(server, caplog, count=1)

    assert len(_rejected(caplog)) == 2


@pytest.mark.parametrize("debug", [False, True])
def test_no_part_of_the_key_is_logged(server_factory, caplog, debug):
    server = server_factory(401)
    _ingest(server, caplog, count=2, debug=debug)
    with caplog.at_level(logging.DEBUG, logger="stubsmith"):
        _sync(server, count=2)

    assert len(_rejected(caplog)) == 1
    stub_records = [r for r in caplog.records if r.name == "stubsmith"]
    assert stub_records
    for record in stub_records:
        text = record.getMessage() + " " + str(record.args) + " " + str(record.msg)
        for size in range(4, len(_KEY) + 1):
            for i in range(len(_KEY) - size + 1):
                part = _KEY[i:i + size]
                assert part not in text, f"key fragment {part!r} in log: {text}"


def test_rejected_warning_names_no_url(server_factory, caplog):
    server = server_factory(401)
    _ingest(server, caplog, count=1)

    msg = _rejected(caplog)[0].getMessage()
    assert "127.0.0.1" not in msg
    assert "http://" not in msg
