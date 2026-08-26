"""
Shared flag used to suppress capture while stubsmith.replay() is active.

Kept in its own module so both ``stubsmith.replay`` and ``stubsmith.client``
can import it without creating a circular dependency.

The counter rather than a boolean makes nested ``replay()`` blocks safe:
the inner block's ``stop()`` does not clear suppression while the outer
block is still running.
"""

from __future__ import annotations

import threading

# The counter is PROCESS-GLOBAL, not thread-local.  That matches the scope
# of the patch: Session.send is a class attribute replaced globally, so
# every thread sees the stub regardless of which thread called start().
# A thread-local counter would be incoherent: another thread's
# _capture_requests would return early even though its send() is serving
# stubs rather than real responses, or vice versa.
_lock = threading.Lock()
_depth: int = 0


def is_replay_active() -> bool:
    """Return True when at least one replay context is active."""
    return _depth > 0


def enter_replay() -> None:
    """Increment the active-replay depth counter (called by ReplayContext.start)."""
    global _depth
    with _lock:
        _depth += 1


def exit_replay() -> None:
    """Decrement the active-replay depth counter (called by ReplayContext.stop)."""
    global _depth
    with _lock:
        if _depth > 0:
            _depth -= 1
