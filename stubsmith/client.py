"""
StubSmith client - background sender, privacy pipeline, and configuration.

All sends are fire-and-forget: a daemon thread drains a bounded queue and
POSTs each capture to the ingest endpoint.  The caller is never blocked and
any send failure is silently swallowed.

Privacy pipeline
----------------
When an ``api_key`` is present, a :class:`~stubsmith.privacy.rules_cache.RulesCache`
and :class:`~stubsmith.privacy.pipeline.PrivacyPipeline` are created at init
time.  Every capture is processed through the pipeline before being enqueued:
masking is applied client-side at the edge so raw values never cross the
process boundary.  The pipeline never raises and degrades gracefully on error
(see :mod:`stubsmith.privacy.pipeline`).

When ``api_key`` is absent (or ``enabled=False``) the pipeline is not
constructed and no captures are sent - existing behaviour is preserved.
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import queue
import random
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import weakref
from collections.abc import Mapping
from typing import Any, Callable, Dict, Optional

from ._replay_state import is_replay_active
from ._version import __version__

logger = logging.getLogger("stubsmith")

_DEFAULT_URL          = "https://ingest.stubsmith.dev/v1/captures"
_DEFAULT_BACKEND_URL  = "https://app.stubsmith.dev/api"
_DEFAULT_TIMEOUT      = 5          # seconds for ingest POST
_MAX_BODY_BYTES       = 64 * 1024  # 64 KiB default cap
_QUEUE_MAXSIZE        = 1000
_FLUSH_TIMEOUT        = 5.0
# At-exit budget, deliberately far below _FLUSH_TIMEOUT. An explicit flush() is
# a request to deliver, and 5s is a reasonable ceiling for that. The atexit hook
# is not: it runs on every process exit, including short-lived scripts, CI jobs
# and serverless invocations, where waiting 5s because the ingest host is
# unreachable is a cost the application never asked for. A healthy endpoint
# drains in tens of milliseconds, so a small budget catches the tail without
# turning an outage into an exit penalty. Override with $STUBSMITH_FLUSH_TIMEOUT
# (0 disables the wait entirely).
_ATEXIT_FLUSH_TIMEOUT = 1.0
_SDK_USER_AGENT       = f"stubsmith-sdk/{__version__}"


def _resolve_debug_flag(debug: Optional[bool]) -> bool:
    """Return True when debug output is enabled.

    Priority: explicit *debug* argument > ``STUBSMITH_DEBUG`` env var.
    The env var is truthy for the values ``1``, ``true``, and ``yes``
    (case-insensitive).  All other values (including absent) are falsy.
    """
    if debug is not None:
        return bool(debug)
    return os.environ.get("STUBSMITH_DEBUG", "").strip().lower() in ("1", "true", "yes")


def _resolve_flush_timeout(flush_timeout: Optional[float]) -> float:
    """Return the seconds to wait for the queue to drain at process exit.

    Priority: explicit *flush_timeout* argument > ``STUBSMITH_FLUSH_TIMEOUT``
    env var > :data:`_ATEXIT_FLUSH_TIMEOUT`.  ``0`` disables the wait, which is
    the right setting for a serverless function or any process whose exit
    latency is charged for.  A malformed env var is ignored rather than raising,
    since the SDK must never break the application it instruments.
    """
    if flush_timeout is not None:
        return max(0.0, float(flush_timeout))
    raw = os.environ.get("STUBSMITH_FLUSH_TIMEOUT", "").strip()
    if raw:
        try:
            return max(0.0, float(raw))
        except ValueError:
            pass
    return _ATEXIT_FLUSH_TIMEOUT


class StubSmith:
    """
    Configures, instruments, and sends captures to the StubSmith ingest service.

    Parameters
    ----------
    url:
        Full URL of the ingest endpoint (POST /v1/captures).
        Defaults to ``STUBSMITH_URL`` env var, then ``https://ingest.stubsmith.dev/v1/captures``.
    api_key:
        Bearer token for the ingest service.
        Defaults to ``STUBSMITH_API_KEY`` env var.
        When empty/None the client auto-disables (no captures sent, no patching).
    enabled:
        Master switch.  Defaults to True but is automatically set to False when
        no api_key is available.
    timeout:
        HTTP timeout (seconds) for each POST to the ingest endpoint.
    max_body_bytes:
        Body strings are truncated to this many bytes inside the pipeline
        (after masking).  Set to 0 to disable truncation.
    sample_rate:
        Fraction of captures to forward (0.0-1.0).  Defaults to 1.0 (all).
    queue_maxsize:
        Maximum number of pending captures held in the background queue.
        Excess items are dropped silently rather than blocking the caller.
    backend_url:
        Base URL for the Node backend (``GET /v1/sdk/sync`` polling).
        The path ``/v1/sdk/sync`` is appended directly, so the value must
        include any path prefix the server requires (e.g.
        ``https://app.stubsmith.dev/api`` for the hosted service).
        Defaults to ``STUBSMITH_BACKEND_URL`` env var, then
        ``https://app.stubsmith.dev/api``.
    rules_poll_interval:
        Seconds between rules-sync polls.  Default ``60.0``.
    debug:
        Enable debug logging to stderr via the ``stubsmith`` logger.
        When ``True``, send failures (exception class + HTTP status/reason +
        target URL) and rules-sync failures are emitted at WARNING level.
        Payload content, headers, and the API key are never logged.
        Defaults to ``None``, which reads the ``STUBSMITH_DEBUG`` env var
        (truthy values: ``1``, ``true``, ``yes``).
    _send_fn:
        Internal hook used by tests to replace the network send.
    """

    def __init__(
        self,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
        enabled: bool = True,
        timeout: float = _DEFAULT_TIMEOUT,
        max_body_bytes: int = _MAX_BODY_BYTES,
        sample_rate: float = 1.0,
        queue_maxsize: int = _QUEUE_MAXSIZE,
        flush_timeout: Optional[float] = None,
        backend_url: Optional[str] = None,
        rules_poll_interval: float = 60.0,
        debug: Optional[bool] = None,
        _send_fn: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        self.url = url or os.environ.get("STUBSMITH_URL", _DEFAULT_URL)
        self.api_key = api_key or os.environ.get("STUBSMITH_API_KEY", "")
        self.enabled = enabled and bool(self.api_key)
        self.timeout = timeout
        self.max_body_bytes = max_body_bytes
        self.sample_rate = max(0.0, min(1.0, sample_rate))
        self._debug = _resolve_debug_flag(debug)
        self._send_fn = _send_fn

        # Running total of failed sends, written only by the sender thread and
        # read by flush(), which compares against a snapshot taken on entry -- so
        # a total is sufficient and a stale read costs at most one poll interval.
        self._send_failures = 0

        self._queue_maxsize = queue_maxsize
        self._rules_cache_needs_restart = False
        self._queue: queue.Queue[Dict[str, Any]] = queue.Queue(maxsize=queue_maxsize)
        self._stop = threading.Event()
        self._worker = threading.Thread(target=self._drain, daemon=True, name="stubsmith-sender")
        self._worker.start()

        self.flush_timeout = _resolve_flush_timeout(flush_timeout)
        atexit.register(self.flush, timeout=self.flush_timeout)

        # fork() copies only the calling thread, so a child inherits a dead
        # sender, a dead rules-cache poller, and a queue nothing will drain.
        # Under gunicorn --preload, uWSGI or Celery -- where install() runs in
        # the master and workers are forked -- every capture in every worker
        # would be enqueued and silently lost. Re-arm in the child instead.
        #
        # The hook holds a weak reference: os.register_at_fork has no
        # unregister, so a strong one would keep every client that was ever
        # constructed alive for the life of the process.
        if hasattr(os, "register_at_fork"):          # absent on Windows
            _self = weakref.ref(self)

            def _after_fork_in_child() -> None:
                obj = _self()
                if obj is not None:
                    obj._reinit_after_fork()

            os.register_at_fork(after_in_child=_after_fork_in_child)

        self._patched_requests = False
        self._patched_httpx_sync = False
        self._patched_httpx_async = False

        # Privacy pipeline (only when enabled)
        self._pipeline: Optional[Any] = None
        self._rules_cache: Optional[Any] = None
        # Explicit flag: True when enabled but pipeline init raised an exception.
        # Used to distinguish "intentionally disabled" from "broken init" so that
        # the broken-init path is fail-closed (drop capture) rather than falling
        # through to a raw payload.
        self._privacy_init_failed: bool = False

        if self.enabled:
            self._backend_url = (
                backend_url
                or os.environ.get("STUBSMITH_BACKEND_URL", _DEFAULT_BACKEND_URL)
            )
            self._init_privacy(
                rules_poll_interval=rules_poll_interval,
            )

    def _init_privacy(
        self,
        rules_poll_interval: float,
    ) -> None:
        """Construct and start the RulesCache + PrivacyPipeline."""
        try:
            from .privacy.rules_cache import RulesCache
            from .privacy.pipeline import PrivacyPipeline

            self._rules_cache = RulesCache(
                api_key=self.api_key,
                backend_url=self._backend_url,
                poll_interval=rules_poll_interval,
                debug=self._debug,
            )
            self._rules_cache.start()

            self._pipeline = PrivacyPipeline(
                rules_cache=self._rules_cache,
                max_body_bytes=self.max_body_bytes,
            )
        except Exception as exc:
            # Privacy pipeline init failure must not crash the SDK - but fail-
            # closed: mark the flag so _build_payload drops captures rather than
            # falling through to the raw legacy path.
            logger.debug("stubsmith: privacy pipeline init failed: %s", exc)
            self._pipeline = None
            self._rules_cache = None
            self._privacy_init_failed = True

    # ------------------------------------------------------------------
    # Public instrumentation API
    # ------------------------------------------------------------------

    def instrument_requests(self) -> None:
        """Patch ``requests.sessions.Session.request`` (idempotent)."""
        if self._patched_requests:
            return
        try:
            import requests.sessions as _rs
        except ImportError:
            return

        _client = self

        _original = getattr(_rs.Session, "_stubsmith_original_request", None) or _rs.Session.request

        def _patched(session, method, url, **kwargs):  # type: ignore[override]
            # Capture request metadata before the call; guard so this can never
            # raise and break the real HTTP call.
            try:
                req_body = _safe_extract_request_body(kwargs)
                req_headers = dict(session.headers or {})
                if isinstance(kwargs.get("headers"), dict):
                    req_headers.update(kwargs["headers"])
                # requests adds the body-derived Content-Type during prepare(),
                # which happens inside the call below - so infer it here or the
                # capture would describe a typed body as having no type at all.
                inferred_ct = _effective_request_content_type(kwargs, req_headers)
                if inferred_ct:
                    req_headers["Content-Type"] = inferred_ct
            except Exception:
                req_body = ""
                req_headers = {}

            t0 = time.monotonic()
            response = _original(session, method, url, **kwargs)
            duration_ms = int((time.monotonic() - t0) * 1000)

            # Resolve the URL that was actually put on the wire so that
            # query parameter names from params= are included in the
            # fingerprint.  requests merges params= into the URL during
            # PreparedRequest.prepare(), which runs inside _original above,
            # so the caller-supplied *url* never carries them.
            #
            # history[0] is the first request in any redirect chain; that
            # matches the semantics of the httpx instrumentation, which hooks
            # per-request at transport level before any redirect is followed.
            # Fall back to the caller-passed url if any attribute is absent.
            try:
                if response.history:
                    wire_url: str = str(response.history[0].request.url)
                else:
                    wire_url = str(response.request.url)
            except Exception:
                wire_url = url

            _client._capture_requests(method, wire_url, req_headers, req_body, response, duration_ms)
            return response

        _rs.Session._stubsmith_original_request = _original  # type: ignore[attr-defined]
        _rs.Session.request = _patched  # type: ignore[method-assign]
        self._patched_requests = True

    def instrument_httpx(self) -> None:
        """Patch ``httpx.Client.send`` and ``httpx.AsyncClient.send`` (idempotent)."""
        try:
            import httpx as _hx
        except ImportError:
            return

        self._instrument_httpx_sync(_hx)
        self._instrument_httpx_async(_hx)

    def _instrument_httpx_sync(self, _hx: Any) -> None:
        if self._patched_httpx_sync:
            return

        _client = self
        _original = getattr(_hx.Client, "_stubsmith_original_send", None) or _hx.Client.send

        def _patched(self_hx, request, **kwargs):  # type: ignore[override]
            t0 = time.monotonic()
            response = _original(self_hx, request, **kwargs)
            duration_ms = int((time.monotonic() - t0) * 1000)
            _client._capture_httpx(request, response, duration_ms, is_async=False)
            return response

        _hx.Client._stubsmith_original_send = _original  # type: ignore[attr-defined]
        _hx.Client.send = _patched  # type: ignore[method-assign]
        self._patched_httpx_sync = True

    def _instrument_httpx_async(self, _hx: Any) -> None:
        if self._patched_httpx_async:
            return

        _client = self
        _original = getattr(_hx.AsyncClient, "_stubsmith_original_send", None) or _hx.AsyncClient.send

        async def _patched_async(self_hx, request, **kwargs):  # type: ignore[override]
            t0 = time.monotonic()
            response = await _original(self_hx, request, **kwargs)
            duration_ms = int((time.monotonic() - t0) * 1000)
            _client._capture_httpx(request, response, duration_ms, is_async=True)
            return response

        _hx.AsyncClient._stubsmith_original_send = _original  # type: ignore[attr-defined]
        _hx.AsyncClient.send = _patched_async  # type: ignore[method-assign]
        self._patched_httpx_async = True

    def uninstrument(self) -> None:
        """Remove all patches installed by this client."""
        try:
            import requests.sessions as _rs
            orig = getattr(_rs.Session, "_stubsmith_original_request", None)
            if orig is not None:
                _rs.Session.request = orig  # type: ignore[method-assign]
                del _rs.Session._stubsmith_original_request  # type: ignore[attr-defined]
        except ImportError:
            pass
        self._patched_requests = False

        try:
            import httpx as _hx
            orig_sync = getattr(_hx.Client, "_stubsmith_original_send", None)
            if orig_sync is not None:
                _hx.Client.send = orig_sync  # type: ignore[method-assign]
                del _hx.Client._stubsmith_original_send  # type: ignore[attr-defined]
            orig_async = getattr(_hx.AsyncClient, "_stubsmith_original_send", None)
            if orig_async is not None:
                _hx.AsyncClient.send = orig_async  # type: ignore[method-assign]
                del _hx.AsyncClient._stubsmith_original_send  # type: ignore[attr-defined]
        except ImportError:
            pass
        self._patched_httpx_sync = False
        self._patched_httpx_async = False

    # ------------------------------------------------------------------
    # Queue / flush / close
    # ------------------------------------------------------------------

    def enqueue(self, payload: Dict[str, Any]) -> None:
        """Non-blocking enqueue.  Drops the item if the queue is full."""
        if not self.enabled:
            return
        if self.sample_rate < 1.0 and random.random() > self.sample_rate:
            return
        try:
            self._queue.put_nowait(payload)
        except queue.Full:
            pass  # drop silently

    def flush(self, timeout: float = _FLUSH_TIMEOUT) -> None:
        """
        Block until the queue is drained or *timeout* seconds elapse.

        Uses a deadline-based poll so it can never hang indefinitely.
        The background worker calls task_done() in a finally-block, so once
        the queue reports empty all items have been fully processed.
        """
        deadline = time.monotonic() + timeout
        failures_at_entry = self._send_failures
        while time.monotonic() < deadline:
            if self._queue.empty():
                break
            if self._send_failures > failures_at_entry:
                # A send has failed since we started waiting, so the endpoint is
                # unreachable or refusing. Draining cannot succeed and every
                # further second is charged to the application.
                break
            time.sleep(0.05)

    @property
    def rules_synced(self) -> bool:
        """``True`` when the rules cache has completed its first successful sync.

        ``False`` when no sync has completed yet, when the client is disabled
        (no API key), or when the privacy pipeline failed to initialise.
        Never raises.

        Typical use - check after :func:`~stubsmith.install` with
        ``wait_for_rules`` to confirm that approved field rules are loaded
        before generating traffic::

            client = stubsmith.install(
                url=ingest_url,
                api_key=api_key,
                wait_for_rules=5.0,
            )
            if not client.rules_synced:
                print("WARNING: rules not loaded - captures will be fully masked")
        """
        try:
            if self._rules_cache is None:
                return False
            return self._rules_cache.wait_for_first_sync(0)
        except Exception:
            return False

    def _reinit_after_fork(self) -> None:
        """Restart the background machinery in a freshly forked child.

        The inherited queue is discarded rather than resent: the parent holds
        the same items and its own sender is still running, so draining the
        child's copy would deliver every pending capture twice.
        """
        self._queue = queue.Queue(maxsize=self._queue_maxsize)
        self._send_failures = 0
        self._stop = threading.Event()
        self._worker = threading.Thread(
            target=self._drain, daemon=True, name="stubsmith-sender"
        )
        self._worker.start()
        # The rules cache is restarted lazily, on the next capture, rather than
        # here. Starting its poll thread from inside the at-fork handler
        # segfaults the child: the cache's lock can be held by the poller at the
        # moment of the fork, and the child inherits it locked with no owner.
        # Deferring means the restart happens on an ordinary call stack.
        self._rules_cache_needs_restart = self._rules_cache is not None

    def close(self) -> None:
        """Flush, stop the rules cache, and stop the background worker."""
        atexit.unregister(self.flush)
        self.flush()
        if self._rules_cache is not None:
            try:
                self._rules_cache.stop()
            except Exception:
                pass
        self._stop.set()
        self.uninstrument()

    # ------------------------------------------------------------------
    # Internal capture helpers
    # ------------------------------------------------------------------

    def _capture_requests(
        self,
        method: str,
        url: str,
        req_headers: Dict[str, Any],
        req_body: str,
        response: Any,
        duration_ms: int,
    ) -> None:
        if is_replay_active():
            return  # suppress capture while replay() is active
        try:
            resp_headers = dict(response.headers or {})
            resp_body = _safe_read_requests_body(response)
            payload = self._build_payload(
                source="python-requests",
                method=method,
                url=str(url),
                req_headers=req_headers,
                req_body=req_body,
                resp_status=response.status_code,
                resp_headers=resp_headers,
                resp_body=resp_body,
                duration_ms=duration_ms,
            )
            if payload is not None:
                self.enqueue(payload)
        except Exception:
            pass  # never propagate

    def _capture_httpx(
        self,
        request: Any,
        response: Any,
        duration_ms: int,
        is_async: bool,
    ) -> None:
        if is_replay_active():
            return  # suppress capture while replay() is active
        try:
            req_headers = dict(request.headers or {})
            req_body = _safe_read_httpx_request_body(request)
            resp_headers = dict(response.headers or {})
            resp_body = _safe_read_httpx_response_body(response)
            source = "python-httpx-async" if is_async else "python-httpx"
            payload = self._build_payload(
                source=source,
                method=request.method,
                url=str(request.url),
                req_headers=req_headers,
                req_body=req_body,
                resp_status=response.status_code,
                resp_headers=resp_headers,
                resp_body=resp_body,
                duration_ms=duration_ms,
            )
            if payload is not None:
                self.enqueue(payload)
        except Exception:
            pass  # never propagate

    def _build_payload(
        self,
        source: str,
        method: str,
        url: str,
        req_headers: Dict[str, Any],
        req_body: str,
        resp_status: int,
        resp_headers: Dict[str, Any],
        resp_body: str,
        duration_ms: int,
    ) -> Optional[Dict[str, Any]]:
        """Build the outbound capture payload.

        When the privacy pipeline is available it processes the capture and
        returns the canonical privacy-safe wire format.  On catastrophic
        pipeline failure (``process()`` returns ``None``) this method also
        returns ``None`` so the caller drops the capture.

        When the pipeline is not available (disabled client, failed init)
        the legacy raw payload is returned - this preserves backward
        compatibility for the disabled/no-api-key case.
        """
        if self._rules_cache_needs_restart:
            # Set by _reinit_after_fork. start() is idempotent and revives a
            # thread that died with the fork.
            self._rules_cache_needs_restart = False
            try:
                if self._rules_cache is not None:
                    self._rules_cache.start()
            except Exception:
                pass

        if self._pipeline is not None:
            result = self._pipeline.process(
                method=method,
                raw_url=url,
                req_headers=req_headers,
                req_body=req_body,
                resp_status=resp_status,
                resp_headers=resp_headers,
                resp_body=resp_body,
            )
            if result is None:
                return None  # catastrophic pipeline failure - drop capture
            result["source"] = source
            result["duration"] = duration_ms
            return result

        # Fail-closed: if the pipeline was expected but failed to initialise,
        # drop the capture entirely rather than sending raw (unmasked) data.
        if self._privacy_init_failed:
            return None

        # Intentionally disabled path (no api_key / enabled=False): raw payload.
        # This branch is only reached when self.enabled is False, which means
        # no captures are enqueued anyway (enqueue() is a no-op when disabled).
        # It is kept for completeness but is effectively dead code in production.
        return {
            "source": source,
            "method": method.upper(),
            # Go ingest reads getString(payload, "path", "/") - send the full
            # outbound URL as "path" so the replay worker can reconstruct it.
            "path": url,
            "headers": req_headers,
            "req_body": self._truncate(req_body),
            "status": resp_status,
            "duration": duration_ms,
            "resp_headers": resp_headers,
            "resp_body": self._truncate(resp_body),
        }

    def _truncate(self, s: str) -> str:
        """Truncate *s* to *max_body_bytes* UTF-8 bytes (legacy path only)."""
        if not s or self.max_body_bytes <= 0:
            return s or ""
        encoded = s.encode("utf-8", errors="replace")
        if len(encoded) <= self.max_body_bytes:
            return s
        return encoded[: self.max_body_bytes].decode("utf-8", errors="replace")

    # ------------------------------------------------------------------
    # Background worker
    # ------------------------------------------------------------------

    def _drain(self) -> None:
        while not self._stop.is_set():
            try:
                payload = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                self._do_send(payload)
            except Exception as exc:
                self._send_failures += 1
                # Errors are always swallowed so the caller is never affected.
                # In debug mode a WARNING is emitted with the exception class,
                # HTTP status/reason (when available), and target URL.
                # Payload content and API key are never logged.
                if self._debug:
                    status = getattr(exc, "code", None)
                    reason = getattr(exc, "reason", None)
                    if status is not None:
                        logger.warning(
                            "stubsmith: send failed - %s status=%s reason=%s url=%s",
                            type(exc).__name__,
                            status,
                            reason,
                            self.url,
                        )
                    else:
                        logger.warning(
                            "stubsmith: send failed - %s url=%s",
                            type(exc).__name__,
                            self.url,
                        )
            finally:
                self._queue.task_done()

    def _do_send(self, payload: Dict[str, Any]) -> None:
        """Send one capture.  All exceptions must be caught by the caller."""
        if self._send_fn is not None:
            self._send_fn(payload)
            return

        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
                "User-Agent": _SDK_USER_AGENT,
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
            resp.read()  # drain


# ------------------------------------------------------------------
# Body extraction helpers (never raise)
# ------------------------------------------------------------------

def _safe_extract_request_body(kwargs: Dict[str, Any]) -> str:
    """
    Pull body text from requests call kwargs without consuming it.

    Checks key presence explicitly so that legitimate empty bodies
    (data=b"", data="", data={}) are captured correctly rather than
    falling through to a different kwarg.

    requests always passes data=None and json=None as explicit kwargs even
    when neither was provided by the caller, so we skip None values and
    prefer a non-None data over a non-None json.

    The serialisation must match what requests actually puts on the wire, since
    the captured body is what gets fingerprinted and key-path extracted:

    - ``data=`` a mapping or a sequence of pairs → form-encoded, matching the
      ``application/x-www-form-urlencoded`` content-type requests will send.
      Serialising these as JSON instead made the fingerprinter run ``parse_qs``
      over a JSON string, deriving a key-path from the payload's *values* and so
      producing a brand-new fingerprint on every single call.
    - ``json=`` → JSON.
    - ``files=`` → "" : requests sends a multipart body that cannot be
      reconstructed here, and emitting the form-encoded fields instead would put
      a body in the capture that never went over the wire.
    - Anything else non-str/bytes (generators, file objects) yields "" rather
      than being consumed, which would corrupt the outgoing request.
    """
    try:
        # requests' prepare_body lets files= win over both data= and json=.
        if kwargs.get("files") is not None:
            return ""

        data_val = kwargs.get("data")
        json_val = kwargs.get("json")

        if data_val is not None:
            if isinstance(data_val, (bytes, bytearray)):
                return data_val.decode("utf-8", errors="replace")
            if isinstance(data_val, str):
                return data_val
            if _is_form_payload(data_val):
                return urllib.parse.urlencode(data_val, doseq=True)
            # Streams, file objects, and anything else requests would send
            # verbatim: never read it, or the real request loses its body.
            return ""

        if json_val is not None:
            return json.dumps(json_val)

        return ""
    except Exception:
        return ""


def _is_form_payload(value: Any) -> bool:
    """Return True when requests would form-encode *value* passed as ``data=``.

    That means a mapping, or a sequence of two-element pairs.  Strings, bytes,
    and file-like/iterator objects are excluded - requests streams those.
    """
    if isinstance(value, Mapping):
        return True
    if isinstance(value, (list, tuple)):
        return all(
            isinstance(item, (list, tuple)) and len(item) == 2 for item in value
        )
    return False


def _effective_request_content_type(
    kwargs: Dict[str, Any], headers: Dict[str, Any]
) -> str:
    """Return the Content-Type requests will send, or "" when it sets none.

    requests derives the header from the body kwargs while *preparing* the
    request - after an instrumentation wrapper around ``Session.request`` has
    already seen the caller's headers.  Without this, a ``json=`` call was
    captured as a JSON body with no content-type at all: the fingerprint's
    content-type dimension was permanently empty, and exported fixtures
    misrepresented the request they were recorded from.

    An explicit caller-supplied Content-Type always wins, mirroring requests.
    """
    for key in headers:
        if isinstance(key, str) and key.lower() == "content-type":
            return ""  # caller set it explicitly; nothing to infer

    # Precedence mirrors _safe_extract_request_body and requests itself: a
    # non-None data= wins over json=.
    if kwargs.get("files") is not None:
        # requests appends "; boundary=..." per request; the boundary is not
        # knowable here and is irrelevant to fingerprinting (parameters are
        # stripped before hashing), so record the bare type.
        return "multipart/form-data"
    data_val = kwargs.get("data")
    if data_val is not None:
        if _is_form_payload(data_val):
            return "application/x-www-form-urlencoded"
        return ""  # str/bytes/stream - requests sets no content-type
    if kwargs.get("json") is not None:
        return "application/json"
    return ""


def _safe_read_requests_body(response: Any) -> str:
    """
    Read response body from a requests Response (already buffered unless stream=True).

    requests sets response._content = False when the response is streaming and
    not yet read.  In that case return "" rather than forcing consumption.
    """
    try:
        if getattr(response, "_content", None) is False:
            # Streaming response not yet consumed by caller - skip body.
            return ""
        return response.text or ""
    except Exception:
        return ""


def _safe_read_httpx_request_body(request: Any) -> str:
    """Read body from an httpx.Request (always buffered)."""
    try:
        content = request.content  # bytes
        if not content:
            return ""
        return content.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _safe_read_httpx_response_body(response: Any) -> str:
    """
    Read body from an httpx.Response only when it has already been read.
    Never consume a stream the caller hasn't read yet.

    httpx sets is_stream_consumed=True once the body has been read.  If it is
    False the caller hasn't read the body yet - return "" to avoid consuming
    their stream.  Similarly if is_closed is False the response is still open.
    """
    try:
        if getattr(response, "is_stream_consumed", None) is False:
            return ""
        if not getattr(response, "is_closed", True):
            return ""
        return response.text or ""
    except Exception:
        return ""
