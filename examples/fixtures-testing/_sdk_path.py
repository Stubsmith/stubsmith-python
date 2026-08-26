"""Prefer the SDK checkout over site-packages, as an import side effect.

Running a script in this directory (``python3 examples/fixtures-testing/x.py``)
puts *this* directory on ``sys.path``, not the repo root, so ``import stubsmith``
resolves to whatever happens to be installed.  On a PEP 668 Python (Homebrew,
Debian) an install lands a non-editable copy in site-packages that shadows the
working tree and can be arbitrarily stale - including its default ingest and
backend URLs, which silently sends captures to localhost instead of the hosted
service, and which lacks attributes added since it was installed.

Import this module *before* importing ``stubsmith``:

    import _sdk_path  # noqa: F401  (sys.path side effect)
    import stubsmith

It exists as a module rather than three copies of the same four lines because
the copies were the bug: a new entry point silently omitted one.

No-op when the checkout is absent, so this directory stays correct after someone
copies it into their own project, where the installed SDK is the right one.
"""

from __future__ import annotations

import pathlib
import sys

SDK_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent

if (SDK_ROOT / "stubsmith" / "__init__.py").is_file():
    _root = str(SDK_ROOT)
    if _root in sys.path:
        sys.path.remove(_root)
    sys.path.insert(0, _root)
