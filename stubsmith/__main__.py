"""Support ``python -m stubsmith`` as an alias for the ``stubsmith`` console script.

Both entry points call :func:`stubsmith.cli.main`, so they accept identical
arguments. ``python -m stubsmith`` resolves the package from ``sys.path``, which
makes it the reliable way to run a checkout without installing it.
"""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
