"""
Tests for the _bundle_env session fixture defined in the example conftest.

This checks the set half of the set/restore contract: the fixture must point
$STUBSMITH_BUNDLE at the example bundle while the session runs.

The teardown half (restoring the previous value) is not tested here.  The
restore logic runs after the session ends; a test that re-implements the
teardown code and then invokes it directly is not testing the fixture - it is
testing itself.  If you need confidence in the teardown, run a subprocess
pytest invocation (e.g. via pytester) and assert the parent environment is
unchanged afterwards.
"""
import os
import pathlib


_EXAMPLE_ROOT = pathlib.Path(__file__).parent.parent
_EXPECTED_BUNDLE = str(_EXAMPLE_ROOT / ".stubsmith" / "bundle.json")


def test_bundle_env_is_set_during_session():
    """$STUBSMITH_BUNDLE points at the example bundle while tests run."""
    assert os.environ.get("STUBSMITH_BUNDLE") == _EXPECTED_BUNDLE
