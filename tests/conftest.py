"""
Test-suite isolation.

Since the SDK's defaults moved from localhost to the hosted service, anything
constructing a client without an explicit backend URL polls
``https://app.stubsmith.dev/api/v1/sdk/sync`` for real. That is wrong three ways:
the suite is not hermetic, CI generates unauthenticated traffic against
production, and each poll is a real network round-trip whose background thread
outlives the test that started it - logging into the *next* test's caplog and
making unrelated assertions fail depending on timing. That is exactly how
test_debug_off_send_failure_is_silent failed on one Python version and passed on
another.

Every test therefore runs with the URLs pointed at a closed local port, where a
connection is refused immediately and nothing leaves the machine. Tests that
care about a specific URL set it themselves.
"""

from __future__ import annotations

import pytest

# Port 1 is reserved and never listening: connections fail at once rather than
# hanging, so a leaked poll thread dies quickly instead of lingering.
_UNREACHABLE = "http://127.0.0.1:1"

_CLEARED = (
    "STUBSMITH_DEBUG",       # a developer's shell must not switch on logging here
    "STUBSMITH_API_KEY",     # never authenticate against anything real
    "STUBSMITH_ORG_API_KEY",
    "STUBSMITH_MASK_SALT",   # placeholder tests depend on the constant form
)


@pytest.fixture(autouse=True)
def _fresh_install_registry():
    """Give every test the process-start view of install().

    install() keeps the client it created so repeated calls cannot accumulate
    threads. That state is per-process and would otherwise leak between tests,
    letting one test receive a client another built.
    """
    from stubsmith import instrument

    instrument._installed = None
    yield
    instrument._installed = None


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    for var in _CLEARED:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("STUBSMITH_API_URL", _UNREACHABLE)
    monkeypatch.setenv("STUBSMITH_BACKEND_URL", _UNREACHABLE)
    monkeypatch.setenv("STUBSMITH_URL", f"{_UNREACHABLE}/v1/captures")
