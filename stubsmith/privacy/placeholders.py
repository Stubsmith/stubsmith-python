"""
Format-preserving placeholder generation for masked field values.

When ``STUBSMITH_MASK_SALT`` is set, masked scalars can carry a semantic type
hint (from the field rule's ``type`` key) that enables generating a fake value
that is the same *shape* as the real one - a parseable ISO 8601 timestamp, an
RFC 4122-shaped UUID, an IBAN with a correct mod-97 checksum, etc.  Without a
salt the module falls back to the constant placeholders (``"<masked>"``, ``0``,
``False``) that have always been emitted, so existing users see no change.

Hint-not-mandate contract (mirrors ``SEMANTIC_TYPE_VOCAB`` in
``backend/src/privacy-helpers.js``)
---------------------------------------------------------------
The server infers a ``type`` from the field's *leaf name only* and never from
the value - it never sees values.  Name-based inference can be wrong: a field
named ``charge_id`` may hold a string Stripe ID or an integer.  So ``type`` is
a **hint, not a mandate**.

Before generating, this module validates the hint against the real value's
actual runtime Python type:

- Hints that produce strings (``email``, ``uuid``, ``iso8601``, ``e164``,
  ``iban``, ``url``, ``opaque_token``, ``free_text``) are only honoured when
  the real value is a ``str``; on a numeric real value the constant ``0`` is
  returned instead.
- ``integer_id`` is honoured when the real value is an ``int`` or a ``str``
  (bare-integer strings such as ``"42"`` are classified as ``integer_id`` by
  the edge classifier).  A string input yields a digit string (``str(n)``); an
  int input yields an int.  This preserves both the JSON type and the numeric
  character.  Floats and other types fall back to the constant.
- ``decimal_amount`` adapts its output to the real value's runtime type: string
  input yields a string decimal like ``"1234.56"``; int input yields an int;
  float input yields a float.  Any other runtime type returns the constant.
- ``currency_code`` and ``country_code`` are **always** refused - a keyed hash
  over a tiny cardinality set is a lookup-table attack, so the constant is
  returned and a debug log is emitted.  These fields should use action ``keep``
  in field rules rather than ``mask``.
- Booleans are treated as low-cardinality and always return ``False`` with a
  debug log, regardless of the hint.

Determinism and referential integrity
--------------------------------------
``generate`` derives the output from
``hashlib.blake2b(str(real_value).encode("utf-8"), key=salt, digest_size=16)``.
The same ``(real_value, salt, semantic_type)`` triple always yields the same
output, so two fields that held the same production value still match after
masking and two that differed still differ.
"""

from __future__ import annotations

import hashlib
import logging
import os
import uuid as _uuid_module
from typing import Any, Optional

logger = logging.getLogger("stubsmith")

# ---------------------------------------------------------------------------
# Closed vocabulary (mirrors backend/src/privacy-helpers.js SEMANTIC_TYPE_VOCAB)
# ---------------------------------------------------------------------------

SEMANTIC_TYPE_VOCAB: frozenset = frozenset({
    "email",
    "uuid",
    "iso8601",
    "e164",
    "iban",
    "url",
    "currency_code",
    "country_code",
    "decimal_amount",
    "integer_id",
    "opaque_token",
    "free_text",
})

# Types whose generated output is always a string.
_STRING_TYPES: frozenset = frozenset({
    "email", "uuid", "iso8601", "e164", "iban", "url", "opaque_token", "free_text",
})

# Types that are low-cardinality and therefore refused.
_LOW_CARDINALITY: frozenset = frozenset({"currency_code", "country_code"})

# Default email domain used when none has been synced from the backend.
DEFAULT_EMAIL_DOMAIN = "stub.invalid"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate(
    semantic_type: str,
    real_value: Any,
    salt: Optional[bytes],
    *,
    email_domain: Optional[str] = None,
) -> Any:
    """Return a format-preserving placeholder for *real_value*.

    Parameters
    ----------
    semantic_type:
        One of the closed vocabulary strings (see :data:`SEMANTIC_TYPE_VOCAB`).
        Unknown labels are treated as ``free_text``.
    real_value:
        The original, unmasked value being replaced.
    salt:
        BLAKE2b key bytes derived from ``STUBSMITH_MASK_SALT``.  When
        ``None`` (env var absent) the constant placeholder for the real
        value's type is returned - unchanged behaviour for all existing users.
    email_domain:
        Domain to use for generated email addresses, e.g. ``"acme.stub.invalid"``.
        The Go ingest service re-masks any email whose domain does not match the
        project placeholder domain, so this must agree with what the backend
        expects.  Defaults to :data:`DEFAULT_EMAIL_DOMAIN` (``"stub.invalid"``).

    Returns
    -------
    Any
        A format-preserving fake value whose Python/JSON type matches
        *real_value*'s type, or the constant placeholder on any failure or
        type mismatch.  Never raises.
    """
    try:
        return _generate_inner(semantic_type, real_value, salt, email_domain=email_domain)
    except Exception as exc:
        logger.debug("stubsmith placeholders: generation failed (%s); using constant", exc)
        return _constant_for(real_value)


def get_salt() -> Optional[bytes]:
    """Read ``STUBSMITH_MASK_SALT`` from the environment and encode as bytes.

    Returns
    -------
    bytes or None
        UTF-8 encoding of the env var value, truncated to 64 bytes (the
        BLAKE2b key-length limit).  ``None`` when the variable is absent or
        empty.
    """
    val = os.environ.get("STUBSMITH_MASK_SALT")
    if not val:
        return None
    return val.encode("utf-8")[:64]


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------

def _generate_inner(
    semantic_type: str,
    real_value: Any,
    salt: Optional[bytes],
    *,
    email_domain: Optional[str],
) -> Any:
    """Core generation logic - may raise; callers must catch."""
    # Absent salt: constant placeholder for all users who have not opted in.
    if salt is None:
        return _constant_for(real_value)

    # Booleans: low-cardinality - two possible values = lookup table trivially.
    if isinstance(real_value, bool):
        logger.debug(
            "stubsmith placeholders: bool is low-cardinality; using constant "
            "(set action=keep for flag fields)"
        )
        return False

    # None stays None regardless of hint.
    if real_value is None:
        return None

    # Low-cardinality types: currency/country codes have tiny domains.
    if semantic_type in _LOW_CARDINALITY:
        logger.debug(
            "stubsmith placeholders: %r is low-cardinality; using constant "
            "(use action=keep for enum-like fields)",
            semantic_type,
        )
        return _constant_for(real_value)

    # Normalise unknown labels to free_text.
    if semantic_type not in SEMANTIC_TYPE_VOCAB:
        semantic_type = "free_text"

    # Validate hint against real value's runtime type before hashing.
    # A mismatch means the server's name-based inference was wrong; fall back
    # to the constant rather than emitting a value of the wrong JSON type.
    if not _hint_matches_type(semantic_type, real_value):
        return _constant_for(real_value)

    # Derive 16-byte hash from value + salt.
    # str() normalisation is intentional: str(1) and str("1") hash identically,
    # so type safety comes exclusively from the hint-validation check above, not
    # from the hash.  A value that reaches here has already passed that check.
    h = hashlib.blake2b(
        str(real_value).encode("utf-8"),
        key=salt,
        digest_size=16,
    )
    b: bytes = h.digest()

    domain = email_domain if email_domain else DEFAULT_EMAIL_DOMAIN

    return _dispatch(semantic_type, real_value, b, domain)


def _hint_matches_type(semantic_type: str, real_value: Any) -> bool:
    """Return True when the hint is compatible with the value's runtime type.

    Compatibility means the generator for *semantic_type* will produce a value
    with the same JSON type as *real_value* (string → string, number → number).
    """
    if semantic_type in _STRING_TYPES:
        # All string-type generators produce strings.
        return isinstance(real_value, str)
    if semantic_type == "integer_id":
        # Accepts both int and str: a bare-integer string ("42") classifies as
        # integer_id at the edge so the server gets the numeric character; the
        # generator preserves the JSON type by returning str(int) for string
        # input.  Floats are excluded - they would change the JSON type.
        # isinstance(bool, int) is True in Python, but booleans are handled
        # before we reach here.
        return isinstance(real_value, (int, str))
    if semantic_type == "decimal_amount":
        # Accepts str, int, and float - output type matches input type.
        return isinstance(real_value, (str, int, float))
    # Default: pass through (shouldn't reach here after vocabulary normalisation).
    return True


def _dispatch(semantic_type: str, real_value: Any, b: bytes, email_domain: str) -> Any:
    """Route to the correct per-type generator."""
    if semantic_type == "email":
        return _gen_email(b, email_domain)
    if semantic_type == "uuid":
        return _gen_uuid(b)
    if semantic_type == "iso8601":
        return _gen_iso8601(b)
    if semantic_type == "e164":
        return _gen_e164(b)
    if semantic_type == "iban":
        return _gen_iban(b)
    if semantic_type == "url":
        return _gen_url(b)
    if semantic_type == "decimal_amount":
        return _gen_decimal_amount(b, real_value)
    if semantic_type == "integer_id":
        return _gen_integer_id(b, real_value)
    if semantic_type == "opaque_token":
        return _gen_opaque_token(b)
    # free_text (and any unexpected label normalised to it)
    return _gen_free_text(b)


# ---------------------------------------------------------------------------
# Per-type generators
# ---------------------------------------------------------------------------

def _gen_email(b: bytes, domain: str) -> str:
    """Generate a deterministic email address at *domain*.

    Local part is eight lowercase hex characters; format satisfies the
    ``[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}`` shape expected
    by the ingest backstop regex.
    """
    local = b[:4].hex()
    return f"{local}@{domain}"


def _gen_uuid(b: bytes) -> str:
    """Generate a version-4, RFC 4122-variant UUID from 16 hash bytes."""
    ba = bytearray(b)
    ba[6] = (ba[6] & 0x0F) | 0x40   # version 4
    ba[8] = (ba[8] & 0x3F) | 0x80   # variant 10xx (RFC 4122)
    return str(_uuid_module.UUID(bytes=bytes(ba)))


def _gen_iso8601(b: bytes) -> str:
    """Generate a UTC ISO 8601 timestamp parseable by ``datetime.fromisoformat``.

    All component values are bounded to always-valid ranges (day 1-28 is safe
    for every month) so no date arithmetic is required.
    """
    year   = 2000 + b[0] % 24    # 2000-2023
    month  = 1    + b[1] % 12    # 1-12
    day    = 1    + b[2] % 28    # 1-28 (safe for all months)
    hour   = b[3] % 24           # 0-23
    minute = b[4] % 60           # 0-59
    second = b[5] % 60           # 0-59
    return f"{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}+00:00"


def _gen_e164(b: bytes) -> str:
    """Generate a plausible E.164 phone number (``+1`` country code + 10 digits)."""
    digits = "".join(str(b[i] % 10) for i in range(10))
    return f"+1{digits}"


def _gen_iban(b: bytes) -> str:
    """Generate a Netherlands-format IBAN (18 chars) with a correct mod-97 checksum.

    BBAN: 4-letter bank code (bytes 0-3 mapped to A-Z) + 10-digit account
    (bytes 4-13 mapped to 0-9).  The two check digits are derived from the
    standard IBAN mod-97 formula so that ``int(converted_iban) % 97 == 1``.
    """
    bank = "".join(chr(65 + b[i] % 26) for i in range(4))
    acct = "".join(str(b[4 + i] % 10) for i in range(10))
    bban = bank + acct

    # IBAN mod-97 check-digit calculation:
    # 1. Rearrange: BBAN + country code + "00"
    # 2. Replace each letter c with str(ord(c) - 55)  (A→10, B→11, …, Z→35)
    # 3. check = 98 − (int(numeric_string) mod 97)
    rearranged = bban + "NL00"
    numeric = "".join(
        str(ord(c) - 55) if c.isalpha() else c for c in rearranged
    )
    check = 98 - (int(numeric) % 97)
    # check is in 02-98 (never 0 or 1: int(numeric) % 97 cannot be 97 or 98
    # for a non-zero int with letters in it).  98 is a valid check digit per the
    # IBAN spec - no clamping needed or permitted.
    return f"NL{check:02d}{bban}"


def _gen_url(b: bytes) -> str:
    """Generate a well-formed HTTPS URL at the ``stub.invalid`` TLD."""
    host = b[:4].hex()
    path = b[4:8].hex()
    return f"https://{host}.stub.invalid/{path}"


def _gen_decimal_amount(b: bytes, real_value: Any) -> Any:
    """Generate a non-zero decimal amount matching *real_value*'s JSON type.

    - ``str`` real_value → string like ``"1234.56"``.
    - ``int`` real_value → int (no decimal point in JSON).
    - ``float`` real_value → float.
    """
    int_part = (int.from_bytes(b[:4], "big") % 9999) + 1   # 1-9999
    frac_part = int.from_bytes(b[4:6], "big") % 100         # 0-99
    if isinstance(real_value, str):
        return f"{int_part}.{frac_part:02d}"
    if isinstance(real_value, float):
        return float(f"{int_part}.{frac_part:02d}")
    # int (bool already excluded upstream)
    return int_part


def _gen_integer_id(b: bytes, real_value: Any) -> Any:
    """Generate a non-zero positive integer ID, preserving the input JSON type.

    When *real_value* is a ``str`` (a bare-integer string like ``"42"``), the
    generated value is returned as a string digit-sequence so the JSON type is
    unchanged.  When *real_value* is an ``int``, the generated value is an int.
    """
    n = (int.from_bytes(b[:8], "big") % 999_999_999) + 1   # 1-999999999
    if isinstance(real_value, str):
        return str(n)
    return n


def _gen_opaque_token(b: bytes) -> str:
    """Generate a hex-ish opaque token string."""
    return b.hex()


def _gen_free_text(b: bytes) -> str:
    """Generate a short deterministic free-text placeholder string."""
    # Produce a stable human-readable-ish string from the hash bytes without
    # relying on any word list.  The format "text-{hex}" keeps it recognisably
    # synthetic and avoids any risk of accidentally reproducing real text.
    return f"text-{b[:8].hex()}"


# ---------------------------------------------------------------------------
# Constant-placeholder fallback
# ---------------------------------------------------------------------------

def _constant_for(value: Any) -> Any:
    """Return the type-appropriate constant placeholder for *value*.

    Mirrors ``_mask_all_values`` in :mod:`~stubsmith.privacy.masking` so that
    fallback behaviour is byte-identical to the pre-placeholder behaviour.
    """
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return 0
    if isinstance(value, str):
        return "<masked>"
    return None
