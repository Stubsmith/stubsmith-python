"""
Body key-path extraction and content fingerprinting.

The fingerprint is a 16-character blake2b hex digest (digest_size=8) computed
over the UTF-8 encoding of::

    sorted_keypaths + '|' + sorted_unique_query_names + '|' + content_type_lower

where *sorted_keypaths* and *sorted_unique_query_names* are each comma-joined.
Response variant fingerprints are prefixed with ``str(status)`` so they sort
separately from request fingerprints.

When *value_paths* are configured for the endpoint and at least one configured
path yields a scalar value in the request body, a fourth section is appended::

    ... + '|' + ','.join(sorted('{path}={canonical_value}'))

Canonical value encoding: ``str`` → raw string; ``bool`` → ``"true"`` /
``"false"`` (checked **before** int since Python bools are ints); ``int`` /
``float`` → ``json.dumps(v)``; ``None`` → ``"null"``; ``dict`` / ``list`` at
the path → skipped.  When no configured path yields a scalar the fourth section
is **omitted** and the digest is byte-identical to the three-argument form,
preserving backward compatibility with existing approved fingerprints.

Key-path conventions
--------------------
- Dict keys are joined with ``.`` to form a path, e.g. ``user.email``.
- Arrays contribute a ``[]`` path segment; only the first element is walked to
  avoid producing exponentially many paths for list-heavy payloads, e.g.
  ``items.[].price``.
- Values are excluded from key-paths; only structure and key names matter.
- Arrays at the root of a document produce paths like ``[].id``.
- Non-parseable bodies, empty bodies, and unknown content-types return ``[]``.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Observed value type classifier
# ---------------------------------------------------------------------------

# Closed vocabulary - mirrors SEMANTIC_TYPE_VOCAB in backend/src/privacy-helpers.js.
# Both sides must agree on labels for the server to accept what the SDK sends.
_VOCAB = frozenset({
    "email", "uuid", "iso8601", "e164", "iban", "url",
    "currency_code", "country_code", "decimal_amount",
    "integer_id", "opaque_token", "free_text",
})

# Pre-compiled patterns.  Order of declaration mirrors the check order in
# classify_scalar - most-specific patterns first so a UUID is never caught by
# the generic string fallback.
#
# Principle: observed labels come from RECOGNIZABLE FORMATS ONLY.
# Character composition (e.g. "has digits and letters, long, no spaces") is
# NOT a format - checking it derives metadata from the character content of
# the real value, which erodes the paths-only invariant.  opaque_token is
# reachable only via the server's name-based inference (fields named "token",
# "secret", "key", "hash"), where the source is the field name, not the value.
_RE_UUID = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE,
)
_RE_EMAIL = re.compile(
    r'^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$'
)
_RE_E164 = re.compile(r'^\+[0-9]{7,15}$')
# IBAN: 2-letter country + 2-digit check + 11-30 alphanumerics.
# Minimum real IBAN is 15 characters (Norway NO); {11,30} gives total minimum
# of 2+2+11=15, preventing short strings like "EU20240001" from matching.
_RE_IBAN = re.compile(r'^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$')
_RE_CURRENCY = re.compile(r'^[A-Z]{3}$')
_RE_COUNTRY = re.compile(r'^[A-Z]{2}$')

# ISO 8601 subset: accepts YYYY-MM-DD and datetime strings with T-separator.
# A lenient heuristic: anchored at start with a four-digit year and a dash.
_RE_ISO8601 = re.compile(
    r'^\d{4}-\d{2}-\d{2}'          # date prefix
    r'([T ]\d{2}:\d{2})'           # optional time (T or space separator)
    r'|^\d{4}-\d{2}-\d{2}$'        # date-only
)

# Bare integer string - checked BEFORE the decimal pattern so ordering is
# unambiguous: "-?[0-9]+" has no dot, while decimal requires one.
_RE_INTEGER_STRING = re.compile(r'^-?[0-9]+$')

# Decimal number: optional leading sign, digits, required dot + more digits.
_RE_DECIMAL = re.compile(r'^-?[0-9]+\.[0-9]+$')


def classify_scalar(value: Any) -> Optional[str]:
    """Classify a scalar leaf value into the shared semantic type vocabulary.

    Parameters
    ----------
    value:
        The raw Python value from a parsed JSON body.  Booleans and ``None``
        yield ``None`` - they are low-cardinality and must not be typed.

    Returns
    -------
    str or None
        One of the labels in ``_VOCAB``, or ``None`` when no classification
        applies (boolean, ``None``, non-scalar container).  Never raises.
    """
    try:
        # Booleans are a subtype of int in Python - check first.
        if isinstance(value, bool) or value is None:
            return None
        if isinstance(value, int):
            return "integer_id"
        if isinstance(value, float):
            return "decimal_amount"
        if not isinstance(value, str):
            return None   # dict / list - not a scalar

        s = value

        # ── Specific patterns - most specific first ───────────────────────
        if _RE_UUID.match(s):
            return "uuid"
        if _RE_EMAIL.match(s):
            return "email"
        if _RE_ISO8601.match(s):
            return "iso8601"
        if _RE_E164.match(s):
            return "e164"
        if _RE_IBAN.match(s):
            return "iban"
        if s.startswith("http://") or s.startswith("https://"):
            return "url"
        if _RE_CURRENCY.match(s):
            return "currency_code"
        if _RE_COUNTRY.match(s):
            return "country_code"
        # Integer string before decimal so "-?[0-9]+" (no dot) is caught first.
        if _RE_INTEGER_STRING.match(s):
            return "integer_id"
        if _RE_DECIMAL.match(s):
            return "decimal_amount"

        # ── Fallback ─────────────────────────────────────────────────────
        # opaque_token is NOT emitted here. Observed labels come from
        # recognizable formats only; character composition is not a format
        # and reading it would derive content-derived metadata from the value.
        # opaque_token remains reachable via the server's name-based inference.
        return "free_text"
    except Exception:
        return None


def extract_value_types(body: str, content_type: str = "") -> Dict[str, str]:
    """Return a map of dot-path → semantic type label for every typed scalar leaf.

    Parameters
    ----------
    body:
        Raw request or response body string.
    content_type:
        Value of the Content-Type header.

    Returns
    -------
    dict[str, str]
        Flat mapping of dotted key-paths (same format as :func:`extract_keypaths`)
        to vocabulary labels.  Booleans and ``None`` values are omitted.  Returns
        ``{}`` when the body cannot be parsed, is blank, or contains no typeable
        scalars.  Never raises.
    """
    if not body or not body.strip():
        return {}
    ct = _normalise_ct(content_type)
    result: Dict[str, str] = {}
    try:
        if ct == "application/x-www-form-urlencoded":
            try:
                parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
            except Exception:
                return {}
            for key, vals in parsed.items():
                if not vals:
                    continue
                label = classify_scalar(vals[0])
                if label is not None:
                    result[key] = label
        else:
            try:
                parsed = json.loads(body)
            except Exception:
                return {}
            _walk_values(parsed, "", result)
    except Exception:
        return {}
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_keypaths(body: str, content_type: str = "") -> List[str]:
    """Return all key-paths found in *body*.

    Parameters
    ----------
    body:
        Raw request or response body string.
    content_type:
        Value of the Content-Type header (charset and boundary params are
        stripped before comparison).

    Returns
    -------
    list[str]
        Unordered list of dot-joined key-paths.  Empty when the body cannot be
        parsed, is blank, or contains no structured keys.  Never raises.
    """
    if not body or not body.strip():
        return []
    ct = _normalise_ct(content_type)
    if ct == "application/x-www-form-urlencoded":
        try:
            parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
            return list(parsed.keys())
        except Exception:
            return []
    try:
        parsed = json.loads(body)
    except Exception:
        return []
    return _walk(parsed, "")


def fingerprint(
    body: str,
    query_string: str,
    content_type: str,
    value_paths: Optional[List[str]] = None,
) -> str:
    """Return a 16-character hex fingerprint for *body* + query names + content-type.

    Parameters
    ----------
    body:
        Raw request body string.
    query_string:
        Raw query string (without leading ``?``).
    content_type:
        Value of the Content-Type header.
    value_paths:
        Optional list of dot-separated body key-paths whose scalar values are
        folded into the hash (fingerprint value discrimination).  When
        ``None``, empty, or no configured path yields a scalar value, the
        fourth hash section is omitted and the result is byte-identical to the
        three-argument form.  Never raises.

    Returns
    -------
    str
        16-character lowercase hex digest.  Stable across processes for the
        same structural input; changes when any key is added or removed, or
        when the content-type or query parameter names change.  Never raises.
    """
    keypaths = extract_keypaths(body, content_type)
    ct = _normalise_ct(content_type)
    query_names = unique_query_names(query_string)
    raw = (
        ",".join(sorted(keypaths))
        + "|"
        + ",".join(sorted(query_names))
        + "|"
        + ct
    )
    if value_paths:
        pairs = _extract_value_pairs(body, content_type, value_paths)
        if pairs:
            raw += "|" + ",".join(sorted(pairs))
    return hashlib.blake2b(raw.encode("utf-8"), digest_size=8).hexdigest()


def resp_fingerprint(
    status: int, body: str, query_string: str, content_type: str
) -> str:
    """Response variant of :func:`fingerprint`, prefixed with the HTTP status.

    Parameters
    ----------
    status:
        HTTP response status code (e.g. 200, 404).
    body:
        Raw response body string.
    query_string:
        Raw query string from the originating request.
    content_type:
        Value of the response Content-Type header.

    Returns
    -------
    str
        ``str(status) + fingerprint(...)`` - a string that varies across both
        response shape *and* status code.  Never raises.
    """
    return str(status) + fingerprint(body, query_string, content_type)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Sentinel returned by _get_scalar_at_path when the path is absent.
_ABSENT = object()


def _canonical_scalar(v: Any) -> Optional[str]:
    """Canonicalise a scalar value for inclusion in the fingerprint hash.

    Rules
    -----
    - ``bool`` → ``"true"`` or ``"false"`` (checked **before** ``int``; Python
      bools are a subtype of int so the order is critical).
    - ``str`` → returned as-is (raw string, no JSON quoting).
    - ``int`` / ``float`` → ``json.dumps(v)`` for JSON-canonical form (e.g.
      ``"42"``, ``"1.5"``).
    - ``None`` → ``"null"``.
    - ``dict`` / ``list`` → returns ``None`` (non-scalar; caller skips).

    Never raises.
    """
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, str):
        return v
    if isinstance(v, (int, float)):
        return json.dumps(v)
    if v is None:
        return "null"
    return None  # dict / list → non-scalar, caller should skip


def _get_scalar_at_path(parsed: Any, dot_path: str) -> Any:
    """Navigate a parsed JSON structure by a dot-separated path.

    Parameters
    ----------
    parsed:
        Parsed JSON value (typically a dict).
    dot_path:
        Dot-separated path, e.g. ``"user.email"`` or ``"action"``.
        No array (``[]``) indexing is supported; a path containing ``[]``
        will never match a real key and returns :data:`_ABSENT`.

    Returns
    -------
    Any
        The value found at the path, or :data:`_ABSENT` when the path does
        not exist or when an intermediate node is not a dict.  Never raises.
    """
    try:
        node: Any = parsed
        for key in dot_path.split("."):
            if not isinstance(node, dict):
                return _ABSENT
            node = node.get(key, _ABSENT)
            if node is _ABSENT:
                return _ABSENT
        return node
    except Exception:
        return _ABSENT


def _extract_value_pairs(
    body: str,
    content_type: str,
    value_paths: List[str],
) -> List[str]:
    """Extract ``path=canonical_value`` strings for each configured path.

    Parameters
    ----------
    body:
        Raw request body string.
    content_type:
        Value of the Content-Type header.
    value_paths:
        List of paths to extract values from.  For JSON bodies these are
        dot-separated key paths; for form-encoded bodies they are flat key
        names (top-level only, first value per key via ``parse_qs``).

    Returns
    -------
    list[str]
        ``["{path}={canonical}"]`` for each configured path that exists and
        holds a scalar value.  Returns ``[]`` when the body cannot be parsed,
        is empty, or no configured path yields a scalar.  Never raises.
    """
    if not body or not body.strip() or not value_paths:
        return []

    ct = _normalise_ct(content_type)
    pairs: List[str] = []

    try:
        if ct == "application/x-www-form-urlencoded":
            try:
                parsed_form = urllib.parse.parse_qs(body, keep_blank_values=True)
            except Exception:
                return []
            for path in value_paths:
                # Form-encoded bodies are flat; use path as a literal key name.
                vals = parsed_form.get(path)
                if vals is None:
                    continue
                canonical = _canonical_scalar(vals[0])
                if canonical is not None:
                    pairs.append(f"{path}={canonical}")
        else:
            try:
                parsed = json.loads(body)
            except Exception:
                return []
            if not isinstance(parsed, dict):
                return []
            for path in value_paths:
                val = _get_scalar_at_path(parsed, path)
                if val is _ABSENT:
                    continue
                canonical = _canonical_scalar(val)
                if canonical is not None:
                    pairs.append(f"{path}={canonical}")
    except Exception:
        return []

    return pairs


def _normalise_ct(content_type: str) -> str:
    """Lowercase and strip charset / boundary params from a content-type value."""
    return (content_type or "").lower().split(";")[0].strip()


def _walk(obj: Any, prefix: str) -> List[str]:
    """Recursively collect dot-joined key-paths from a parsed JSON structure.

    Rules
    -----
    - Each dict key at every nesting level is emitted as a path.
    - Arrays contribute a ``[]`` segment; only the first element is walked.
    - Scalar arrays emit the ``[]`` segment itself as a leaf (e.g. ``items.[]``
      for ``{"items": [1, 2, 3]}``), mirroring the path used by
      ``_walk_and_mask`` so that a reviewer keep rule on ``items.[]`` actually
      matches at masking time.
    - Scalar values contribute no path themselves.
    """
    paths: List[str] = []
    if isinstance(obj, dict):
        for key, val in obj.items():
            full = f"{prefix}.{key}" if prefix else key
            paths.append(full)
            paths.extend(_walk(val, full))
    elif isinstance(obj, list) and obj:
        arr_prefix = f"{prefix}.[]" if prefix else "[]"
        first = obj[0]
        if isinstance(first, (dict, list)):
            paths.extend(_walk(first, arr_prefix))
        else:
            # Scalar array: emit the [] segment as the leaf path so that
            # a keep rule on e.g. "body.items.[]" matches in _walk_and_mask.
            paths.append(arr_prefix)
    return paths


def unique_query_names(query_string: str) -> List[str]:
    """Return deduplicated query parameter names from *query_string*."""
    if not query_string:
        return []
    try:
        parsed = urllib.parse.parse_qs(query_string, keep_blank_values=True)
        return list(parsed.keys())
    except Exception:
        return []


def _walk_values(obj: Any, prefix: str, result: Dict[str, str]) -> None:
    """Recursively collect (path, type) pairs for every typeable scalar leaf.

    Mirrors the path structure of :func:`_walk`: dict keys joined with ``.``,
    arrays contribute a ``[]`` segment with only the first element walked.
    Booleans and ``None`` are skipped (not typed per spec).  Never raises.
    """
    if isinstance(obj, dict):
        for key, val in obj.items():
            full = f"{prefix}.{key}" if prefix else key
            if isinstance(val, (dict, list)):
                _walk_values(val, full, result)
            else:
                label = classify_scalar(val)
                if label is not None:
                    result[full] = label
    elif isinstance(obj, list) and obj:
        arr_prefix = f"{prefix}.[]" if prefix else "[]"
        first = obj[0]
        if isinstance(first, (dict, list)):
            _walk_values(first, arr_prefix, result)
        else:
            label = classify_scalar(first)
            if label is not None:
                result[arr_prefix] = label
