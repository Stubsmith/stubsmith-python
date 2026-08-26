"""
Image body placeholder handling.

When a request or response body has an ``image/*`` content-type, the SDK
replaces the real image bytes with a canonical 1×1 placeholder before
fingerprinting and masking - ensuring that pixel data and EXIF
metadata (which can carry PII) never leave the process.

Three placeholder constants are provided:

- :data:`PNG_1X1` - 1×1 pixel PNG (used for ``image/png`` and any unknown
  ``image/*`` subtype)
- :data:`GIF_1X1` - 1×1 transparent GIF89a (used for ``image/gif``)
- :data:`JPEG_1X1` - 1×1 JPEG (used for ``image/jpeg`` and ``image/jpg``)

Use :func:`is_image` to test a content-type and :func:`placeholder_for` to
retrieve the appropriate placeholder bytes and the canonical subtype string.
"""

from __future__ import annotations

import base64 as _base64
from typing import Tuple


# ---------------------------------------------------------------------------
# Placeholder byte constants
# ---------------------------------------------------------------------------

# 1×1 transparent PNG (70 bytes, standard RGBA)
PNG_1X1: bytes = _base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ"
    "AAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
)

# 1×1 transparent GIF89a (42 bytes, standard web tracking pixel)
GIF_1X1: bytes = _base64.b64decode(
    "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"
)

# 1×1 JPEG - minimal valid JFIF file
JPEG_1X1: bytes = _base64.b64decode(
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAEBAQEBAQEBAQEBAQEBAQEB"
    "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQH/"
    "wAALCAABAAEBAREA/8QAFAABAAAAAAAAAAAAAAAAAAAAAP/aAAcBAQAAAH/"
    "//9k="
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def is_image(content_type: str) -> bool:
    """Return ``True`` when *content_type* indicates an image body.

    Parameters
    ----------
    content_type:
        Raw Content-Type header value; charset and boundary params are ignored.

    Returns
    -------
    bool
        ``True`` for any ``image/*`` media type (case-insensitive).
    """
    ct = _normalise_ct(content_type)
    return ct.startswith("image/")


def placeholder_for(content_type: str) -> Tuple[bytes, str]:
    """Return the canonical placeholder bytes for *content_type*.

    Parameters
    ----------
    content_type:
        Raw Content-Type header value.

    Returns
    -------
    tuple[bytes, str]
        ``(placeholder_bytes, matched_subtype)`` where *matched_subtype* is
        the canonical subtype string (``"png"``, ``"gif"``, or ``"jpeg"``).
        Unknown ``image/*`` subtypes fall back to PNG.
    """
    ct = _normalise_ct(content_type)
    if ct == "image/gif":
        return GIF_1X1, "gif"
    if ct in ("image/jpeg", "image/jpg"):
        return JPEG_1X1, "jpeg"
    # image/png and anything else image/* → PNG
    return PNG_1X1, "png"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _normalise_ct(content_type: str) -> str:
    """Lowercase and strip charset / boundary params."""
    return (content_type or "").lower().split(";")[0].strip()
