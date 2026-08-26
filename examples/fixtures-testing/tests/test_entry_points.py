"""
Subprocess tests for this example's runnable scripts.

Every other test in this directory imports the scripts in-process, under a
conftest that has already fixed up sys.path. That cannot see the failure mode
these scripts actually have: run as `python3 examples/fixtures-testing/x.py`,
sys.path[0] is the example directory and `import stubsmith` resolves to whatever
is installed - which on a PEP 668 Python is a non-editable, possibly stale copy
in site-packages. approve_fingerprints.py shipped broken exactly that way,
crashing on an SDK attribute that exists only in the checkout, while every
in-process test passed.

The decoy below makes these tests independent of what is installed on the
machine running them: a stale stubsmith is placed on PYTHONPATH, so a script
that fails to prefer the checkout picks it up and dies, whether or not the real
SDK is installed.
"""
from __future__ import annotations

import pathlib
import subprocess
import sys

import pytest

_EXAMPLE = pathlib.Path(__file__).resolve().parent.parent
_REPO_ROOT = _EXAMPLE.parent.parent

_SCRIPTS = ["approve_fingerprints.py", "generate_traffic.py"]


@pytest.fixture
def decoy_sdk(tmp_path):
    """A stale 'stubsmith' package, missing everything added since 0.5.0."""
    pkg = tmp_path / "stubsmith"
    pkg.mkdir()
    (pkg / "__init__.py").write_text(
        '"""Decoy: a stale installed SDK."""\n__version__ = "0.0.0-decoy"\n'
    )
    return tmp_path


def _run(script, *args, env_extra=None, decoy=None):
    env = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(pathlib.Path.home()),
    }
    if decoy is not None:
        env["PYTHONPATH"] = str(decoy)
    env.update(env_extra or {})
    return subprocess.run(
        [sys.executable, str(_EXAMPLE / script), *args],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )


@pytest.mark.parametrize("script", _SCRIPTS)
def test_help_runs_with_a_stale_sdk_on_the_path(script, decoy_sdk):
    """--help must reach argparse, not die importing the SDK.

    Both scripts read SDK attributes at module scope, so a stale copy winning
    the import is a traceback before any argument is parsed.
    """
    proc = _run(script, "--help", decoy=decoy_sdk)
    assert proc.returncode == 0, proc.stderr
    assert "Traceback" not in proc.stderr
    assert "usage:" in proc.stdout


@pytest.mark.parametrize("script", _SCRIPTS)
def test_scripts_do_not_import_the_decoy(script, decoy_sdk):
    proc = _run(script, "--help", decoy=decoy_sdk)
    assert "0.0.0-decoy" not in (proc.stdout + proc.stderr)


def test_approve_reports_an_unreachable_backend_rather_than_crashing(decoy_sdk):
    """The failure that shipped: resolving the default API URL raised
    AttributeError against a stale SDK, before any network call."""
    proc = _run(
        "approve_fingerprints.py",
        "--dry-run",
        env_extra={
            "STUBSMITH_ORG_API_KEY": "dummy-not-a-real-key",
            "STUBSMITH_PROJECT_ID": "some-project",
            "STUBSMITH_API_URL": "http://127.0.0.1:1",
        },
        decoy=decoy_sdk,
    )
    assert proc.returncode == 1, proc.stderr
    assert "Traceback" not in proc.stderr
    assert "could not reach" in proc.stderr


def test_approve_without_a_key_exits_two(decoy_sdk):
    proc = _run("approve_fingerprints.py", decoy=decoy_sdk)
    assert proc.returncode == 2
    assert "STUBSMITH_ORG_API_KEY" in proc.stderr


def test_approve_without_a_project_exits_two(decoy_sdk):
    """Checked before any request is made, so it needs no network."""
    proc = _run(
        "approve_fingerprints.py",
        env_extra={"STUBSMITH_ORG_API_KEY": "dummy-not-a-real-key"},
        decoy=decoy_sdk,
    )
    assert proc.returncode == 2
    assert "--project-id" in proc.stderr
