"""
Top-level conftest for the fixtures-testing example.

Adds the example directory to sys.path so that ``import shopclient`` works when
pytest is invoked from the repo root (the shopclient package lives here, not
at the repo root).

Sets $STUBSMITH_BUNDLE for the duration of the test session and restores the
previous value (or removes it) on teardown.  This is necessary because the
example is a nested project inside the SDK repository: the bundle lives at
examples/fixtures-testing/.stubsmith/bundle.json, but when pytest runs from
the repo root the upward search starts there and never descends into the
example subdirectory.  In a normal project - where the bundle sits at the
project root and tests live in a subdirectory - no configuration like this is
needed; stubsmith.replay() finds the bundle automatically.

Registers the ``live`` marker here rather than only in the root pyproject.toml
so that a reader who copies this directory into its own project gets a
self-contained example with no unknown-mark warnings.
"""
import os
import pathlib
import sys

import pytest

_EXAMPLE_ROOT = pathlib.Path(__file__).parent
sys.path.insert(0, str(_EXAMPLE_ROOT))

# Put the SDK checkout ahead of site-packages so the tests exercise the SDK in
# this repository rather than whatever is installed. See _sdk_path.
import _sdk_path  # noqa: F401  (sys.path side effect)


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "live: tests that call the real Stubsmith backend (require STUBSMITH_API_KEY)",
    )


@pytest.fixture(scope="session", autouse=True)
def _bundle_env():
    """Point $STUBSMITH_BUNDLE at the example bundle for the entire session."""
    key = "STUBSMITH_BUNDLE"
    prev = os.environ.get(key)
    os.environ[key] = str(_EXAMPLE_ROOT / ".stubsmith" / "bundle.json")
    yield
    if prev is None:
        os.environ.pop(key, None)
    else:
        os.environ[key] = prev
