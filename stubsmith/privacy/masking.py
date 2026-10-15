"""
Request/response masking - field masks, regex masks, and fail-closed masking.

This module is a Python port of ``ingest-go/anonymizer.go`` with the following
exact parity guarantees:

- **Field masks**: case-insensitive key comparison (both sides lowercased).
  When a key matches, the entire value is replaced with ``'<masked>'`` with
  **no recursion** into the masked value.
- **Regex masks**: applied to string values in declaration order.  The ``i``
  flag is honoured by prepending ``(?i)`` to the compiled pattern.  An empty
  ``replace`` string becomes ``'<masked>'``.  A pattern that does not compile
  is not skipped: the rule set is marked unusable and every string it is
  applied to becomes ``'<masked>'`` (see :func:`compile_rules`).  Strings
  longer than :data:`MAX_REGEX_SCAN_CHARS` are masked without running any
  regex.
- **Lists** are recursed element-wise; other scalars (numbers, bools, None)
  pass through unchanged in rule-based masking.

Header ALLOWLIST
----------------
The following header names (lowercased) are considered safe metadata and their
values are kept.  All other header values are replaced with ``'<masked>'`` in
both :func:`mask_known` and :func:`mask_all`::

    content-type, content-length, accept, accept-encoding, host,
    transfer-encoding

The allowlist applies to request and response headers alike.  ``user-agent``,
``cache-control`` and ``accept-language`` are not on it: their values are
masked unless a ``header.`` or ``resp_header.`` keep rule keeps them.

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
import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("stubsmith")

# ---------------------------------------------------------------------------
# Header allowlist
# ---------------------------------------------------------------------------

HEADER_ALLOWLIST: frozenset = frozenset({
    "content-type",
    "content-length",
    "accept",
    "accept-encoding",
    "host",
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
    # True when at least one regex mask could not be compiled.  The rule's
    # effect is unknown, so :func:`_apply_regexes` masks every string.
    unusable: bool = False


# Strings longer than this are replaced by ``'<masked>'`` without running any
# regex mask.  A customer pattern can backtrack badly on long input, and
# masking runs inside the host application's request path.  Only applies
# while at least one regex mask is active.  Counts code points; the Node SDK
# applies the same number to UTF-16 code units.
MAX_REGEX_SCAN_CHARS = 65536

_warned_unusable_pattern = False


def _reset_masking_warnings_for_tests() -> None:
    """Re-arm the once-per-process unusable-pattern warning."""
    global _warned_unusable_pattern
    _warned_unusable_pattern = False


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
        becomes ``'<masked>'``.  A pattern that fails to compile marks the
        result :attr:`CompiledRules.unusable`, so every string is masked;
        the first one per process logs a WARNING naming its index.  So does
        any malformed entry (a non-list, a non-string field mask, a regex
        mask that is not an object, or has an empty or non-string pattern or
        a non-string replacement or flags): the rule's intent is unknown, so nothing is skipped.

    Returns
    -------
    CompiledRules
        Thread-safe, immutable compiled-rule set.
    """
    unusable = False

    def fail_closed(what: str, reason: Any) -> None:
        # Dropping a rule would quietly send what it was meant to mask.  Fail
        # closed instead: every string the rules are applied to gets masked.
        global _warned_unusable_pattern
        nonlocal unusable
        unusable = True
        if not _warned_unusable_pattern:
            _warned_unusable_pattern = True
            logger.warning(
                "stubsmith: %s cannot be used: %s; every kept string will be "
                "masked (further invalid rules are reported silently)",
                what, reason,
            )

    fields_list: List[str] = []
    if field_masks and not isinstance(field_masks, (list, tuple)):
        fail_closed("field_masks", "not a list")
        field_masks = []
    for index, f in enumerate(field_masks or []):
        if f is None:
            continue
        if not isinstance(f, str):
            fail_closed(f"field mask at index {index}", "not a string")
            continue
        fields_list.append(f.lower().strip())
    fields = frozenset(fields_list)

    compiled: List[Tuple[re.Pattern, str]] = []
    if regex_masks and not isinstance(regex_masks, (list, tuple)):
        fail_closed("regex_masks", "not a list")
        regex_masks = []
    for index, m in enumerate(regex_masks or []):
        what = f"regex mask at index {index}"
        if not isinstance(m, dict):
            fail_closed(what, "not an object")
            continue
        pattern = m.get("pattern") or ""
        flags = m.get("flags") or ""
        replace = m.get("replace")
        if replace is None or replace == "":
            replace = "<masked>"
        if not isinstance(pattern, str):
            fail_closed(what, "the pattern is not a string")
            continue
        if pattern == "":
            fail_closed(what, "the pattern is empty")
            continue
        if not isinstance(replace, str):
            fail_closed(what, "the replacement is not a string")
            continue
        if not isinstance(flags, (str, list, tuple)):
            fail_closed(what, "the flags are not a string")
            continue
        if "i" in flags:
            pattern = "(?i)" + pattern
        try:
            compiled.append((re.compile(pattern), replace))
        except Exception as exc:
            # re.error, or OverflowError for a repeat count Python cannot
            # represent (e.g. a{99999999999}).
            fail_closed(what, exc)
    return CompiledRules(
        field_masks=fields, regex_masks=tuple(compiled), unusable=unusable
    )


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
    - Unrecognised or non-parseable bodies, including a form body that is not
      ``key=value`` pairs, have only the regex masks applied.

    Returns
    -------
    tuple[str, dict, str]
        ``(masked_body, masked_headers, masked_query_string)``
    """
    masked_headers = _mask_headers(headers)
    ct = _normalise_ct(content_type)

    if ct == "application/x-www-form-urlencoded":
        form = parse_form(body)
        if form is not None:
            masked_body = _mask_form_known(form, rules)
        else:
            masked_body = _apply_regexes(body, rules)
    else:
        try:
            parsed = json.loads(body)
            masked_body = json.dumps(_mask_object(parsed, rules))
        except Exception:
            # Non-JSON plain-text body: still run regex masks so that a
            # customer pattern also covers text/plain bodies.  Matches
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
    """Apply regex masks in declaration order.

    Returns ``'<masked>'`` when the rule set is unusable, or when a regex
    would run on a string longer than :data:`MAX_REGEX_SCAN_CHARS`.
    """
    if rules.unusable:
        return "<masked>"
    if rules.regex_masks and len(s) > MAX_REGEX_SCAN_CHARS:
        return "<masked>"
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
    - Form-encoded: field names kept, all values → ``'<masked>'``. A form
      body with a segment that has no ``=`` → ``'<masked>'``.
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
            parsed = parse_form(body)
            if parsed is None:
                masked_body = "<masked>"
            else:
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


def _mask_form_known(parsed: Dict[str, List[str]], rules: CompiledRules) -> str:
    """Apply *rules* to a parsed form-encoded body."""
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


def parse_form(body: str) -> Optional[Dict[str, List[str]]]:
    """Parse a form-encoded body, or return ``None`` if it is not one.

    ``parse_qs`` turns a segment without ``=`` into a key with an empty value,
    so free text labelled as a form would be sent as a field name. A body with
    any non-empty ``&``-separated segment that has no ``=`` is therefore not a
    form, and callers treat it like any other unparseable body.
    """
    if any(seg and "=" not in seg for seg in (body or "").split("&")):
        return None
    return urllib.parse.parse_qs(body, keep_blank_values=True)
