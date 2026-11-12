"""
Tests for stubsmith.replay with httpx - hermetic, no network calls permitted.

httpx.Client and httpx.AsyncClient must be answered from the bundle with the
same matching and miss behaviour as requests.
"""

from __future__ import annotations

import base64
import socket

import httpx
import pytest
import requests

from stubsmith.replay import StubNotFound, replay, replay_all

from .test_replay import (
    _BASE_URL,
    _DOMAIN,
    _FP_EMPTY_GET,
    _FP_GET_WITH_PARAM,
    _FP_POST_JSON,
    _bundle,
    _endpoint,
    _stub,
    _variant,
)

_JSON = {"content-type": "application/json"}


@pytest.fixture(params=["sync", "async"])
def call(request):
    """Return ``await call(method, url, **kw)`` for httpx.Client / AsyncClient."""
    if request.param == "sync":
        async def _call(method, url, **kw):
            with httpx.Client() as c:
                return c.request(method, url, **kw)
    else:
        async def _call(method, url, **kw):
            async with httpx.AsyncClient() as c:
                return await c.request(method, url, **kw)
    return _call


def _users_bundle(**settings):
    bundle = _bundle(
        _endpoint(
            "GET",
            "/api/users/{id}",
            [_stub(_FP_EMPTY_GET, [_variant(200, '{"id": 42, "name": "Alice"}', headers=_JSON)])],
            is_dynamic=True,
        )
    )
    if settings:
        bundle["project_settings"] = settings
    return bundle


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_round_trip_status_headers_json(call):
    bundle = _bundle(
        _endpoint(
            "GET",
            "/api/users/{id}",
            [_stub(_FP_EMPTY_GET, [_variant(
                200, '{"id": 42, "name": "Alice"}',
                headers={"content-type": "application/json", "x-trace": "abc"},
            )])],
            is_dynamic=True,
        )
    )
    with replay(bundle=bundle):
        resp = await call("GET", f"{_BASE_URL}/api/users/42")
    assert resp.status_code == 200
    assert resp.headers["x-trace"] == "abc"
    assert resp.headers["content-type"] == "application/json"
    assert resp.json() == {"id": 42, "name": "Alice"}
    assert resp.request.url == f"{_BASE_URL}/api/users/42"


@pytest.mark.anyio
async def test_hop_by_hop_headers_stripped_and_elapsed_set(call):
    bundle = _bundle(
        _endpoint("GET", "/x", [_stub(_FP_EMPTY_GET, [_variant(
            200, "hi", duration_ms=7,
            headers={"content-length": "999", "transfer-encoding": "chunked",
                     "content-type": "text/plain"},
        )])])
    )
    with replay(bundle=bundle):
        resp = await call("GET", f"{_BASE_URL}/x")
    assert resp.content == b"hi"
    assert "transfer-encoding" not in resp.headers
    assert resp.headers.get("content-length") != "999"
    assert resp.elapsed.total_seconds() == pytest.approx(0.007)


@pytest.mark.anyio
async def test_path_pattern_matches_any_id(call):
    with replay(bundle=_users_bundle()):
        a = await call("GET", f"{_BASE_URL}/api/users/1")
        b = await call("GET", f"{_BASE_URL}/api/users/987654")
    assert a.json() == b.json() == {"id": 42, "name": "Alice"}


@pytest.mark.anyio
async def test_query_param_names_match_regardless_of_values(call):
    bundle = _bundle(
        _endpoint("GET", "/api/orders", [_stub(_FP_GET_WITH_PARAM, [_variant(
            200, '{"orders": []}', headers=_JSON)])])
    )
    with replay(bundle=bundle):
        via_params = await call("GET", f"{_BASE_URL}/api/orders", params={"status": "shipped"})
        in_url = await call("GET", f"{_BASE_URL}/api/orders?status=other")
        with pytest.raises(StubNotFound):
            await call("GET", f"{_BASE_URL}/api/orders", params={"state": "shipped"})
    assert via_params.json() == in_url.json() == {"orders": []}


@pytest.mark.anyio
async def test_group_ids_in_paths_false(call):
    """The setting decides how an unrecorded path is templated on a miss."""
    url = f"{_BASE_URL}/api/users/42/orders/7"
    bundle = _users_bundle()

    with replay(bundle=bundle):
        with pytest.raises(StubNotFound) as grouped:
            await call("GET", url)
    assert grouped.value.path_template == "/api/users/{id}/orders/{id}"

    bundle["project_settings"] = {"group_ids_in_paths": False}
    with replay(bundle=bundle):
        with pytest.raises(StubNotFound) as literal:
            await call("GET", url)
        with pytest.raises(StubNotFound) as via_requests:
            requests.get(url)
    assert literal.value.path_template == "/api/users/42/orders/7"
    assert str(literal.value) == str(via_requests.value)


@pytest.mark.anyio
async def test_masked_field_value_independent_matching(call):
    """Recorded response carries a masked value; request values may differ."""
    bundle = _bundle(
        _endpoint("POST", "/api/pay", [_stub(_FP_POST_JSON, [_variant(
            200, '{"card": "<masked>", "ok": true}', headers=_JSON)])])
    )
    with replay(bundle=bundle):
        r1 = await call("POST", f"{_BASE_URL}/api/pay", json={"action": "pay", "amount": 100})
        r2 = await call("POST", f"{_BASE_URL}/api/pay", json={"action": "refund", "amount": 5})
    assert r1.json() == r2.json() == {"card": "<masked>", "ok": True}


@pytest.mark.anyio
async def test_miss_message_equals_requests_message(call):
    bundle = _users_bundle()
    url = f"{_BASE_URL}/api/orders"
    with replay(bundle=bundle):
        with pytest.raises(StubNotFound) as req_exc:
            requests.get(url)
        with pytest.raises(StubNotFound) as hx_exc:
            await call("GET", url)
    assert str(hx_exc.value) == str(req_exc.value)


@pytest.mark.anyio
async def test_miss_message_equals_requests_message_with_body(call):
    bundle = _users_bundle()
    url = f"{_BASE_URL}/api/users/1"
    payload = {"action": "pay", "extra": 1}
    with replay(bundle=bundle):
        with pytest.raises(StubNotFound) as req_exc:
            requests.post(url, json=payload)
        with pytest.raises(StubNotFound) as hx_exc:
            await call("POST", url, json=payload)
    assert str(hx_exc.value) == str(req_exc.value)


@pytest.mark.anyio
async def test_non_json_text_body(call):
    bundle = _bundle(
        _endpoint("GET", "/note", [_stub(_FP_EMPTY_GET, [_variant(
            200, "plain words", headers={"content-type": "text/plain"})])])
    )
    with replay(bundle=bundle):
        resp = await call("GET", f"{_BASE_URL}/note")
    assert resp.text == "plain words"
    assert resp.content == b"plain words"


@pytest.mark.anyio
async def test_base64_binary_body(call):
    png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\xff\xfe"
    variant = _variant(200, base64.b64encode(png).decode(), headers={"content-type": "image/png"})
    variant["body_encoding"] = "base64"
    bundle = _bundle(_endpoint("GET", "/logo.png", [_stub(_FP_EMPTY_GET, [variant])]))
    with replay(bundle=bundle):
        resp = await call("GET", f"{_BASE_URL}/logo.png")
    assert resp.content == png


def _stream_bundle():
    return _bundle(
        _endpoint("GET", "/stream", [_stub(_FP_EMPTY_GET, [_variant(
            200, "line one\nline two\nline three",
            headers={"content-type": "text/plain"})])])
    )


# httpx < 0.24 keeps the line terminator in iter_lines(); strip it so one
# assertion holds across versions.
def test_sync_stream_bytes_and_lines():
    with replay(bundle=_stream_bundle()):
        with httpx.Client() as c:
            with c.stream("GET", f"{_BASE_URL}/stream") as r:
                data = b"".join(r.iter_bytes())
            with c.stream("GET", f"{_BASE_URL}/stream") as r:
                lines = [ln.rstrip("\r\n") for ln in r.iter_lines()]
    assert data == b"line one\nline two\nline three"
    assert lines == ["line one", "line two", "line three"]


@pytest.mark.anyio
async def test_async_stream_bytes_and_lines():
    with replay(bundle=_stream_bundle()):
        async with httpx.AsyncClient() as c:
            async with c.stream("GET", f"{_BASE_URL}/stream") as r:
                data = b"".join([chunk async for chunk in r.aiter_bytes()])
            async with c.stream("GET", f"{_BASE_URL}/stream") as r:
                lines = [ln.rstrip("\r\n") async for ln in r.aiter_lines()]
    assert data == b"line one\nline two\nline three"
    assert lines == ["line one", "line two", "line three"]


@pytest.mark.anyio
async def test_replay_all_serves_httpx(call):
    attempts = list(replay_all(_users_bundle()))
    assert len(attempts) == 1
    with attempts[0]:
        resp = await call("GET", f"{_BASE_URL}/api/users/3")
    assert resp.status_code == 200
    assert len(attempts[0].served()) == 1


@pytest.mark.anyio
async def test_unread_streaming_request_body_is_treated_as_empty(call):
    def gen():
        yield b"abc"

    with replay(bundle=_users_bundle()):
        resp = await call("GET", f"{_BASE_URL}/api/users/1", content=gen())
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# No network
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_no_socket_connect_during_replay(call, block_real_network, monkeypatch):
    connects = []

    def _record(self, address):
        connects.append(address)
        raise AssertionError(f"socket.connect({address!r}) during replay")

    monkeypatch.setattr(socket.socket, "connect", _record)
    with replay(bundle=_users_bundle()):
        resp = await call("GET", f"{_BASE_URL}/api/users/1")
        with pytest.raises(StubNotFound):
            await call("GET", f"{_BASE_URL}/nope")
    assert resp.status_code == 200
    assert connects == []


# ---------------------------------------------------------------------------
# Restoration and nesting
# ---------------------------------------------------------------------------

def test_send_restored_after_stop():
    sync_orig, async_orig = httpx.Client.send, httpx.AsyncClient.send
    with replay(bundle=_users_bundle()):
        assert httpx.Client.send is not sync_orig
        assert httpx.AsyncClient.send is not async_orig
    assert httpx.Client.send is sync_orig
    assert httpx.AsyncClient.send is async_orig


def test_send_restored_after_exception_in_block():
    sync_orig, async_orig = httpx.Client.send, httpx.AsyncClient.send
    with pytest.raises(RuntimeError):
        with replay(bundle=_users_bundle()):
            raise RuntimeError("boom")
    assert httpx.Client.send is sync_orig
    assert httpx.AsyncClient.send is async_orig


def test_send_restored_when_nested():
    sync_orig, async_orig = httpx.Client.send, httpx.AsyncClient.send
    with replay(bundle=_users_bundle()):
        outer_sync, outer_async = httpx.Client.send, httpx.AsyncClient.send
        with replay(bundle=_users_bundle()):
            assert httpx.Client.send is not outer_sync
        assert httpx.Client.send is outer_sync
        assert httpx.AsyncClient.send is outer_async
    assert httpx.Client.send is sync_orig
    assert httpx.AsyncClient.send is async_orig


def test_inner_context_serves_its_own_bundle_and_outer_resumes():
    other = _bundle(
        _endpoint("GET", "/api/users/{id}", [_stub(_FP_EMPTY_GET, [_variant(
            200, '{"who": "inner"}', headers=_JSON)])], is_dynamic=True)
    )
    with replay(bundle=_users_bundle()):
        with replay(bundle=other):
            assert httpx.get(f"{_BASE_URL}/api/users/1").json() == {"who": "inner"}
        assert httpx.get(f"{_BASE_URL}/api/users/1").json()["name"] == "Alice"


def test_restoration_with_capture_installed_before_replay():
    from stubsmith.client import StubSmith
    client = StubSmith(url="https://stubsmith.test/v1/captures", api_key="sk-test", _send_fn=lambda p: None)
    client.instrument_httpx()
    try:
        patched_sync, patched_async = httpx.Client.send, httpx.AsyncClient.send
        with replay(bundle=_users_bundle()):
            assert httpx.get(f"{_BASE_URL}/api/users/1").status_code == 200
        assert httpx.Client.send is patched_sync
        assert httpx.AsyncClient.send is patched_async
    finally:
        client.uninstrument()


def test_restoration_with_capture_installed_after_replay_start():
    from stubsmith.client import StubSmith
    original_sync = httpx.Client.send
    ctx = replay(bundle=_users_bundle()).start()
    client = StubSmith(url="https://stubsmith.test/v1/captures", api_key="sk-test", _send_fn=lambda p: None)
    try:
        client.instrument_httpx()
        client.uninstrument()
    finally:
        ctx.stop()
    assert getattr(httpx.Client, "_stubsmith_original_send", None) is None
    assert httpx.Client.send is original_sync


# ---------------------------------------------------------------------------
# Only one HTTP library installed
# ---------------------------------------------------------------------------

def _hide_requests(monkeypatch):
    # A None entry in sys.modules makes `import requests` raise ImportError,
    # as in a venv that installed stubsmith[httpx] only.
    import sys
    for name in ("requests", "requests.sessions"):
        monkeypatch.setitem(sys.modules, name, None)


@pytest.mark.anyio
async def test_httpx_replays_without_requests_installed(call, monkeypatch):
    sync_orig, async_orig = httpx.Client.send, httpx.AsyncClient.send
    _hide_requests(monkeypatch)
    with replay(bundle=_users_bundle()):
        resp = await call("GET", f"{_BASE_URL}/api/users/7")
        with pytest.raises(StubNotFound):
            await call("GET", f"{_BASE_URL}/nope")
    assert resp.status_code == 200
    assert resp.json() == {"id": 42, "name": "Alice"}
    assert httpx.Client.send is sync_orig
    assert httpx.AsyncClient.send is async_orig


def test_requests_send_untouched_when_requests_missing(monkeypatch):
    requests_orig = requests.Session.send
    _hide_requests(monkeypatch)
    with replay(bundle=_users_bundle()):
        assert requests.Session.send is requests_orig
    assert requests.Session.send is requests_orig


def test_replay_raises_when_neither_library_is_installed(monkeypatch):
    import sys
    sync_orig = httpx.Client.send
    _hide_requests(monkeypatch)
    monkeypatch.setitem(sys.modules, "httpx", None)
    with pytest.raises(ImportError, match="'requests' or 'httpx'"):
        with replay(bundle=_users_bundle()):
            pass
    assert httpx.Client.send is sync_orig
