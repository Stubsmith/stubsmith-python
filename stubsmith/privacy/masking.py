"""
Request/response masking - field masks, regex masks, and fail-closed masking.

This module is a Python port of ``ingest-go/anonymizer.go`` with the following
exact parity guarantees:

- **Field masks**: case-insensitive key comparison (both sides lowercased).
  When a key matches, the entire value is replaced with ``'<masked>'`` with
  **no recursion** into the masked value.
- **Regex masks**: applied to string values in declaration order.  The ``i``
  flag is honoured by prepending ``(?i)`` to the compiled pattern.  An empty
  ``replace`` string becomes ``'<masked>'``.  Invalid patterns are silently
  skipped.
- **Lists** are recursed element-wise; other scalars (numbers, bools, None)
  pass through unchanged in rule-based masking.

Header ALLOWLIST
----------------
The following header names (lowercased) are considered safe metadata and their
values are kept.  All other header values are replaced with ``'<masked>'`` in
both :func:`mask_known` and :func:`mask_all`::

    content-type, content-length, accept, accept-encoding,
    accept-language, user-agent, host, cache-control, transfer-encoding

Fail-closed masking (:func:`mask_all`)
---------------------------------------
Every scalar in the body is replaced with a type-appropriate placeholder:
``'<masked>'`` for strings, ``0`` for numbers, ``False`` for booleans, ``None``
stays ``None``.  Structure (dicts, lists) and keys are preserved.  Form-encoded
bodies keep their field names but replace all values with ``'<masked>'``.
Non-JSON, non-form-encoded bodies become the string ``'<masked>'``.

Parity note - divergence from ``ingest-go/anonymizer.go``
----------------------------------------------------------
When ``STUBSMITH_MASK_SALT`` is set in the SDK process environment, the
path-based masker in :mod:`~stubsmith.privacy.field_rules` may emit
format-preserving placeholders (ISO 8601 timestamps, UUIDs, IBANs, etc.)
via :mod:`~stubsmith.privacy.placeholders` rather than the constant
``"<masked>"`` / ``0`` / ``False`` values.  This diverges from the Go ingest
server's backstop masker, which never has access to the salt and always emits
constant placeholders.  The divergence is intentional: the salt is edge-local
by design so that the server structurally cannot generate these values.

:func:`mask_all` (this module's fail-closed path) is NOT affected - it has no
field-type context and remains constant-only.  Only the rule-based path in
:mod:`~stubsmith.privacy.field_rules` participates in format-preserving
generation.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Header allowlist
# ---------------------------------------------------------------------------

HEADER_ALLOWLIST: frozenset = frozenset({
    "content-type",
    "content-length",
    "accept",
    "accept-encoding",
    "accept-language",
    "user-agent",
    "host",
    "cache-control",
    "transfer-encoding",
})

# ---------------------------------------------------------------------------
# Compiled rule container
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CompiledRules:
    """Immutable, pre-compiled masking rules ready for hot-path application."""

    field_masks: frozenset  # lowercased, stripped field names
    regex_masks: tuple      # tuple of (re.Pattern, replacement_str)


def compile_rules(
    field_masks: Optional[List[str]],
    regex_masks: Optional[List[Dict[str, str]]],
) -> CompiledRules:
    """Build a :class:`CompiledRules` from raw rule dicts.

    Parameters
    ----------
    field_masks:
        List of field-name strings to mask in their entirety (case-insensitive).
    regex_masks:
        List of ``{"pattern": ..., "replace": ..., "flags": ...}`` dicts.
        ``flags="i"`` causes ``(?i)`` to be prepended.  Empty ``replace``
        becomes ``'<masked>'``.  Patterns that fail to compile are silently
        dropped.

    Returns
    -------
    CompiledRules
        Thread-safe, immutable compiled-rule set.
    """
    fields = frozenset(
        f.lower().strip() for f in (field_masks or []) if f is not None
    )
    compiled: List[Tuple[re.Pattern, str]] = []
    for m in (regex_masks or []):
        pattern = m.get("pattern") or ""
        flags = m.get("flags") or ""
        replace = m.get("replace")
        if replace is None or replace == "":
            replace = "<masked>"
        if "i" in flags:
            pattern = "(?i)" + pattern
        try:
            compiled.append((re.compile(pattern), replace))
        except re.error:
            continue  # silently skip invalid patterns
    return CompiledRules(field_masks=fields, regex_masks=tuple(compiled))


# ---------------------------------------------------------------------------
# Rule-based masking (mask_known)
# ---------------------------------------------------------------------------

def mask_known(
    body: str,
    headers: Dict[str, Any],
    query_params: str,
    content_type: str,
    rules: CompiledRules,
) -> Tuple[str, Dict[str, Any], str]:
    """Apply *rules* to *body*, *headers*, and *query_params*.

    - Non-allowlisted headers are replaced with ``'<masked>'`` (the allowlist
      masking is independent of and in addition to the field/regex rules).
    - JSON bodies: field and regex rules applied with Go-parity semantics.
    - Form-encoded bodies: field names in ``rules.field_masks`` have their
      values replaced; remaining values have regex masks applied.
    - Query params: same logic as form-encoded.
    - Unrecognised or non-parseable bodies are returned unchanged.

    Returns
    -------
    tuple[str, dict, str]
        ``(masked_body, masked_headers, masked_query_string)``
    """
    masked_headers = _mask_headers(headers)
    ct = _normalise_ct(content_type)

    if ct == "application/x-www-form-urlencoded":
        masked_body = _mask_form_known(body, rules)
    else:
        try:
            parsed = json.loads(body)
            masked_body = json.dumps(_mask_object(parsed, rules))
        except Exception:
            # Non-JSON plain-text body: still run regex masks so that e.g.
            # credit-card numbers in text/plain bodies are caught.  Matches
            # the string branch of applyRulesToInterface in anonymizer.go.
            masked_body = _apply_regexes(body, rules)

    masked_query = _mask_query_known(query_params, rules)
    return masked_body, masked_headers, masked_query


def _mask_object(obj: Any, rules: CompiledRules) -> Any:
    """Recursively apply *rules* to a parsed JSON structure.

    Matches ``applyRulesToInterface`` in ``ingest-go/anonymizer.go`` exactly:
    - dict: if lowercased key is in field_masks → replace whole value with
      ``'<masked>'``, no recursion.  Otherwise recurse.
    - list: recurse into each element.
    - str: apply regex masks in order.
    - other: return unchanged.
    """
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            if k.lower() in rules.field_masks:
                out[k] = "<masked>"
            else:
                out[k] = _mask_object(v, rules)
        return out
    if isinstance(obj, list):
        return [_mask_object(e, rules) for e in obj]
    if isinstance(obj, str):
        return _apply_regexes(obj, rules)
    return obj  # int, float, bool, None - unchanged


def _apply_regexes(s: str, rules: CompiledRules) -> str:
    """Apply regex masks in declaration order."""
    out = s
    for pattern, replace in rules.regex_masks:
        out = pattern.sub(replace, out)
    return out


# ---------------------------------------------------------------------------
# Fail-closed masking (mask_all)
# ---------------------------------------------------------------------------

def mask_all(
    body: str,
    headers: Dict[str, Any],
    query_params: str,
    content_type: str,
) -> Tuple[str, Dict[str, Any], str]:
    """Fail-closed masking - every scalar value is replaced.

    - Header allowlist still applies (safe metadata headers are kept).
    - JSON: structure and keys preserved; strings → ``'<masked>'``,
      numbers → ``0``, booleans → ``False``, ``None`` stays ``None``.
    - Form-encoded: field names kept, all values → ``'<masked>'``.
    - Any other body type → ``'<masked>'`` string.
    - All query param values → ``'<masked>'``.

    Returns
    -------
    tuple[str, dict, str]
        ``(masked_body, masked_headers, masked_query_string)``
    """
    masked_headers = _mask_headers(headers)
    ct = _normalise_ct(content_type)

    if ct == "application/x-www-form-urlencoded":
        try:
            parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
            out = {k: ["<masked>"] * len(v) for k, v in parsed.items()}
            masked_body = urllib.parse.urlencode(out, doseq=True)
        except Exception:
            masked_body = "<masked>"
    else:
        try:
            parsed = json.loads(body)
            masked_body = json.dumps(_mask_all_values(parsed))
        except Exception:
            masked_body = "<masked>"

    masked_query = _mask_query_all(query_params)
    return masked_body, masked_headers, masked_query


def _mask_all_values(obj: Any) -> Any:
    """Replace every scalar with its type-appropriate placeholder."""
    if isinstance(obj, dict):
        return {k: _mask_all_values(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_mask_all_values(e) for e in obj]
    if isinstance(obj, bool):
        return False
    if isinstance(obj, (int, float)):
        return 0
    if isinstance(obj, str):
        return "<masked>"
    return None  # None stays None (and handles any other type gracefully)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _mask_headers(headers: Dict[str, Any]) -> Dict[str, Any]:
    """Apply header allowlist - non-allowlisted values become ``'<masked>'``."""
    out: Dict[str, Any] = {}
    for k, v in headers.items():
        if k.lower() in HEADER_ALLOWLIST:
            out[k] = v
        else:
            out[k] = "<masked>"
    return out


def _mask_form_known(body: str, rules: CompiledRules) -> str:
    """Apply *rules* to a form-encoded body string."""
    try:
        parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
    except Exception:
        return body
    out: Dict[str, List[str]] = {}
    for k, vals in parsed.items():
        if k.lower() in rules.field_masks:
            out[k] = ["<masked>"] * len(vals)
        else:
            out[k] = [_apply_regexes(v, rules) for v in vals]
    return urllib.parse.urlencode(out, doseq=True)


def _mask_query_known(query_string: str, rules: CompiledRules) -> str:
    """Apply *rules* to a query string.

    Params in ``rules.field_masks`` have their values replaced; all other
    param values have the regex masks applied.
    """
    if not query_string:
        return query_string or ""
    try:
        parsed = urllib.parse.parse_qs(query_string, keep_blank_values=True)
    except Exception:
        return query_string
    out: Dict[str, List[str]] = {}
    for k, vals in parsed.items():
        if k.lower() in rules.field_masks:
            out[k] = ["<masked>"] * len(vals)
        else:
            out[k] = [_apply_regexes(v, rules) for v in vals]
    return urllib.parse.urlencode(out, doseq=True)


def _mask_query_all(query_string: str) -> str:
    """Replace all query param values with ``'<masked>'``."""
    if not query_string:
        return query_string or ""
    try:
        parsed = urllib.parse.parse_qs(query_string, keep_blank_values=True)
    except Exception:
        return "<masked>"
    out = {k: ["<masked>"] * len(v) for k, v in parsed.items()}
    return urllib.parse.urlencode(out, doseq=True)


def _normalise_ct(content_type: str) -> str:
    """Lowercase and strip charset / boundary params."""
    return (content_type or "").lower().split(";")[0].strip()
