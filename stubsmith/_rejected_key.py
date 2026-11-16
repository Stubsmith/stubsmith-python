"""One WARNING per process when the API key is rejected (HTTP 401 or 403).

A rejected key used to be silent unless debug mode was on, so a mistyped key
looked like a working install that never recorded anything. Both the ingest
send and the rules sync report here, and they share one flag, so the warning
appears once per process however many requests are refused.

This module imports nothing from the package so client.py and the privacy
modules can both use it without a circular import.
"""

import logging
import os
import threading

logger = logging.getLogger("stubsmith")

_REJECTED_STATUSES = (401, 403)

# The lock is because the sender thread, the rules poll thread and tests all
# reach the flag. State is inherited across fork on purpose, so a pre-fork
# worker pool warns once overall rather than once per worker.
_warned = False
_warned_lock = threading.Lock()


def _reinit_lock_after_fork() -> None:
    # A fork while another thread holds the lock would leave it locked forever
    # in the child. The flag itself is kept.
    global _warned_lock
    _warned_lock = threading.Lock()


if hasattr(os, "register_at_fork"):          # absent on Windows
    os.register_at_fork(after_in_child=_reinit_lock_after_fork)


def _reset_rejected_key_warning() -> None:
    """Forget that the rejected-key warning was shown (for tests)."""
    global _warned
    with _warned_lock:
        _warned = False


def _report_rejected_key(status: object) -> None:
    """
    Log one WARNING the first time a 401 or 403 is seen. Never raises.

    Triggered on the status code alone, whatever the body says. The message
    holds only the status: never the API key, any part of it, or a URL (a URL
    can carry userinfo).
    """
    global _warned
    try:
        if status not in _REJECTED_STATUSES:
            return
        with _warned_lock:
            if _warned:
                return
            _warned = True
        logger.warning(
            "stubsmith: the API key was rejected (HTTP %s). Nothing is "
            "recorded until the key is fixed. Check the api_key option or the "
            "STUBSMITH_API_KEY environment variable. "
            "See https://docs.stubsmith.dev/#capturing. Reported once per process.",
            status,
        )
    except Exception:
        pass
