"""
Convenience wrappers for auto-instrumenting both requests and httpx.

Importing this module does nothing by itself; call ``install()`` or use the
``StubSmith`` class directly.
"""

from __future__ import annotations

import os
import threading
from typing import Optional, Tuple

from .client import StubSmith

# The client installed in this process, with the pid it was created under.
# install() is called from application startup, but also from plugin registries
# and framework hooks that can fire more than once per process; without this,
# each call built another client with its own sender thread, rules-cache poller,
# atexit hook and 60-second backend poll. The captures were never duplicated
# (the patch re-wraps the original, not the wrapper) but the threads accumulated,
# and every client except the most recent one was inert while still polling.
_installed: Optional[Tuple[int, StubSmith]] = None
_install_lock = threading.Lock()


def install(
    url: Optional[str] = None,
    api_key: Optional[str] = None,
    *,
    enabled: bool = True,
    timeout: float = 5.0,
    max_body_bytes: int = 64 * 1024,
    sample_rate: float = 1.0,
    queue_maxsize: int = 1000,
    flush_timeout: Optional[float] = None,
    backend_url: Optional[str] = None,
    rules_poll_interval: float = 60.0,
    wait_for_rules: float = 0,
) -> StubSmith:
    """
    Create a :class:`StubSmith` client, instrument ``requests`` and ``httpx``
    if either is importable, and return the client.

    This is the recommended one-liner integration::

        import stubsmith
        stubsmith.install(api_key="sk-...")

    Idempotent: calling ``install()`` again returns the client already
    installed in this process rather than building another one, so repeated
    calls from plugin registries or framework hooks cannot accumulate threads.
    Arguments are ignored on those subsequent calls; to reconfigure, call
    ``close()`` on the existing client first.

    Fork-safe: a client whose background threads died with a ``fork()`` is
    revived in the child, so ``install()`` in a pre-fork master (``gunicorn
    --preload``, uWSGI, Celery) still captures in every worker.

    Parameters mirror :class:`StubSmith.__init__` (including *flush_timeout*,
    *backend_url* and *rules_poll_interval*), plus:

    wait_for_rules:
        Seconds to block waiting for the first successful rules-cache sync
        before returning.  Default ``0`` (do not wait) preserves the existing
        behaviour exactly - long-running services should leave this at zero
        because the background sync has time to complete before real traffic
        arrives.

        Set a positive value (e.g. ``5.0``) for short capture scripts that
        finish in tens of milliseconds; without it the rules cache has not
        received its first response yet and every capture lands as
        ``novel=True`` with every field masked.

        The wait is bounded by *wait_for_rules* seconds; if the backend is
        unreachable the function returns after the timeout rather than
        hanging.  It never raises.
    """
    global _installed

    with _install_lock:
        if _installed is not None:
            _, existing = _installed
            # A live sender that has not been stopped means the client is
            # usable, including in a child whose threads were revived after a
            # fork. close() sets the stop event, so a closed client is replaced
            # rather than handed back inert.
            if existing._worker.is_alive() and not existing._stop.is_set():
                _installed = (os.getpid(), existing)
                return existing

    client = StubSmith(
        url=url,
        api_key=api_key,
        enabled=enabled,
        timeout=timeout,
        max_body_bytes=max_body_bytes,
        sample_rate=sample_rate,
        queue_maxsize=queue_maxsize,
        flush_timeout=flush_timeout,
        backend_url=backend_url,
        rules_poll_interval=rules_poll_interval,
    )
    client.instrument_requests()
    client.instrument_httpx()
    if wait_for_rules > 0 and client._rules_cache is not None:
        try:
            client._rules_cache.wait_for_first_sync(timeout=wait_for_rules)
        except Exception:
            pass

    with _install_lock:
        _installed = (os.getpid(), client)
    return client


def is_installed() -> bool:
    """
    Return ``True`` when this process has a live StubSmith client installed.

    Written for the check every integration wants to make - "is capture
    actually armed?" - without reaching for the patched attributes, which are
    private and easy to assert on wrongly.  ``requests.request`` and
    ``requests.get`` are *not* patched (they construct a ``Session`` and call
    the patched ``Session.request``), so an assertion against those reports a
    working install as broken.

    ``False`` after :meth:`StubSmith.close`, and in a child whose client could
    not be revived after a ``fork()``.
    """
    with _install_lock:
        if _installed is None:
            return False
        _, client = _installed
    return client._worker.is_alive() and not client._stop.is_set()
