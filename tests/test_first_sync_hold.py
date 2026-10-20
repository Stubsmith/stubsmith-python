"""
The sender holds a capture templated before the first rules sync.

Before that sync the "Group IDs in paths automatically" setting is unknown, so
the pipeline templates with grouping ON. The sender waits (bounded) for the
sync and templates the raw path again with the real setting.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, List

import pytest

from stubsmith import client as client_module
from stubsmith.client import StubSmith
from stubsmith.privacy.pipeline import PrivacyPipeline
from stubsmith.privacy.rules_cache import RulesCache


class _Cache(RulesCache):
    def __init__(self, group_ids: bool) -> None:
        super().__init__(api_key="sk-test", backend_url="http://fake")
        self._sync_body: Dict[str, Any] = {
            "ok": True,
            "cursor": "1",
            "rules": [],
            "path_templates": [],
            "project_settings": {"group_ids_in_paths": group_ids},
        }

    def sync_now(self) -> None:
        self._apply_sync_response(self._sync_body)


class _Sink:
    def __init__(self) -> None:
        self.payloads: List[Dict[str, Any]] = []
        self._event = threading.Event()

    def __call__(self, payload: Dict[str, Any]) -> None:
        self.payloads.append(payload)
        self._event.set()

    def wait(self, timeout: float = 5.0) -> Dict[str, Any]:
        assert self._event.wait(timeout), "nothing was sent"
        return self.payloads[0]


def _make(group_ids: bool):
    sink = _Sink()
    client = StubSmith(url="http://stubsmith.test/v1/captures", api_key="sk-test", _send_fn=sink)
    client._rules_cache.stop()
    cache = _Cache(group_ids)
    client._rules_cache = cache
    client._pipeline = PrivacyPipeline(rules_cache=cache)
    client._rules_started_at = time.monotonic()
    return client, cache, sink


def _capture(client: StubSmith) -> Dict[str, Any]:
    payload = client._build_payload(
        source="python-requests",
        method="GET",
        url="https://api.example.com/orders/123?page=2",
        req_headers={},
        req_body="",
        resp_status=200,
        resp_headers={"Content-Type": "application/json"},
        resp_body='{"ok": true}',
        duration_ms=1,
    )
    assert payload is not None
    return payload


@pytest.fixture
def hold(monkeypatch):
    monkeypatch.setattr(client_module, "FIRST_SYNC_HOLD", 2.0)


def test_grouping_off_sends_concrete_path_once_synced(hold):
    client, cache, sink = _make(group_ids=False)
    try:
        payload = _capture(client)
        assert payload["path_template"] == "/orders/{id}"
        client.enqueue(payload)
        time.sleep(0.3)
        assert sink.payloads == []  # held, not sent with the wrong template
        cache.sync_now()
        sent = sink.wait()
        assert sent["path_template"] == "/orders/123"
        assert sent["path"].startswith("/orders/123?page=")
    finally:
        client.close()


def test_grouping_on_sends_templated_path_once_synced(hold):
    client, cache, sink = _make(group_ids=True)
    try:
        client.enqueue(_capture(client))
        cache.sync_now()
        sent = sink.wait()
        assert sent["path_template"] == "/orders/{id}"
        assert sent["path"].startswith("/orders/{id}?page=")
    finally:
        client.close()


def test_sync_never_arrives_keeps_capture_time_template(monkeypatch):
    monkeypatch.setattr(client_module, "FIRST_SYNC_HOLD", 0.3)
    client, _cache, sink = _make(group_ids=False)
    try:
        started = time.monotonic()
        client.enqueue(_capture(client))
        sent = sink.wait(timeout=3.0)
        assert time.monotonic() - started >= 0.25  # held for the bound
        assert sent["path_template"] == "/orders/{id}"
        assert sent["path"].startswith("/orders/{id}?page=")
    finally:
        client.close()


def test_private_field_is_never_sent(hold):
    client, cache, sink = _make(group_ids=False)
    try:
        payload = _capture(client)
        assert "_raw_path" in payload
        client.enqueue(payload)
        cache.sync_now()
        assert "_raw_path" not in sink.wait()
    finally:
        client.close()

    client, _cache, sink = _make(group_ids=False)
    try:
        monkey = client_module.FIRST_SYNC_HOLD
        client_module.FIRST_SYNC_HOLD = 0.1
        client.enqueue(_capture(client))
        assert "_raw_path" not in sink.wait()
    finally:
        client_module.FIRST_SYNC_HOLD = monkey
        client.close()


def test_synced_capture_carries_no_private_field(hold):
    client, cache, sink = _make(group_ids=False)
    try:
        cache.sync_now()
        assert "_raw_path" not in _capture(client)
    finally:
        client.close()


def test_close_is_bounded_and_stops_the_worker(hold):
    """close() waits no longer than its flush timeout, then the worker exits."""
    client, _cache, sink = _make(group_ids=False)
    client.enqueue(_capture(client))
    time.sleep(0.2)
    started = time.monotonic()
    client.close()
    assert time.monotonic() - started < client_module._FLUSH_TIMEOUT + 1.0
    client._worker.join(timeout=2.0)
    assert not client._worker.is_alive()


def test_stopping_ends_the_hold_early(hold):
    client, _cache, sink = _make(group_ids=False)
    client.enqueue(_capture(client))
    time.sleep(0.2)
    client._stop.set()
    client._worker.join(timeout=2.0)
    assert not client._worker.is_alive()


def test_flush_sends_a_held_capture_instead_of_waiting(hold):
    """A short script's exit flush must not be spent waiting for a sync that
    may never come: flushing ends the hold, and the capture goes out with the
    capture-time template, as it did before the hold existed."""
    client, _cache, sink = _make(group_ids=False)
    try:
        client.enqueue(_capture(client))
        time.sleep(0.2)
        assert sink.payloads == []  # held
        started = time.monotonic()
        client.flush(timeout=1.0)
        assert time.monotonic() - started < 0.8
        assert len(sink.payloads) == 1
        assert sink.payloads[0]["path_template"] == "/orders/{id}"
    finally:
        client.close()
