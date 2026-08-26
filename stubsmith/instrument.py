"""
Convenience wrappers for auto-instrumenting both requests and httpx.

Importing this module does nothing by itself; call ``install()`` or use the
``StubSmith`` class directly.
"""

from __future__ import annotations

from typing import Optional

from .client import StubSmith


def install(
    url: Optional[str] = None,
    api_key: Optional[str] = None,
    *,
    enabled: bool = True,
    timeout: float = 5.0,
    max_body_bytes: int = 64 * 1024,
    sample_rate: float = 1.0,
    queue_maxsize: int = 1000,
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

    Both ``requests`` and ``httpx`` patching are idempotent; calling
    ``install()`` twice returns a second client but does not double-patch.

    Parameters mirror :class:`StubSmith.__init__`, plus:

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
    client = StubSmith(
        url=url,
        api_key=api_key,
        enabled=enabled,
        timeout=timeout,
        max_body_bytes=max_body_bytes,
        sample_rate=sample_rate,
        queue_maxsize=queue_maxsize,
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
    return client
