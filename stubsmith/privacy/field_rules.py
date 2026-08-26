"""
Per-fingerprint path-based field rule application.

Cloud rules are PATH-BASED (not field-name based).  ``GET /v1/sdk/sync``
delivers ``field_rules: [{path, action}]`` where path is namespaced::

    body.user.email            - request body JSON/form field by dotted key-path
    query.notify               - query parameter by name
    header.x-custom            - request header by name (lowercased)
    path.{id}                  - path segment placeholder (metadata only; unused here)
    resp.user.id               - response body JSON field by dotted key-path
    resp_header.x-custom       - response header by name (lowercased; independent of header.)
    resp:404.error             - response body field, status-scoped (status 404 only)
    resp_header:429.retry-after - response header, status-scoped (status 429 only)

Status-scoped namespaces
------------------------
A status-scoped path takes the form ``<ns>:<status>.<subpath>`` where:

- ``<ns>`` is ``resp`` or ``resp_header``.
- ``<status>`` is exactly three decimal digits in the range 100-599.
- ``<subpath>`` is a non-empty body path or header name (lowercased for headers).

The colon separator was chosen because body paths are ``.``-joined, so
``resp.404.error`` would be ambiguous against a body key ``"404"``.

Status-scoped precedence (applied per field at masking time)
------------------------------------------------------------
For a response with HTTP status *S* and body path *p*:

1. A ``resp:S.p`` rule exists → its action wins.
   A status-scoped ``mask`` **overrides** a generic ``keep``.
   A status-scoped ``keep`` **adds** to paths kept beyond what the generic set provides.
2. Else a ``resp.p`` rule exists → its action.
3. Else mask (fail-closed).

Identical precedence applies to response headers via ``resp_header:S.n`` / ``resp_header.n``.

Unlike generic namespaces (where only ``keep`` entries are recorded because
absence means mask), status-scoped rules record **both** ``keep`` and ``mask``
actions: a scoped ``mask`` is meaningful precisely because it must be able to
override a generic ``keep``.

:func:`compile_field_rules` pre-processes those rule lists into a
:class:`CompiledFieldRules` that the hot-path :func:`apply_field_rules` and
:func:`apply_resp_field_rules` can consume without repeated string splitting.

Fail-closed semantics
---------------------
Every scalar in the request body is replaced with a type-appropriate
placeholder (``"<masked>"``, ``0``, ``False``, ``None``) *unless* its
namespaced path has an explicit ``action: "keep"`` rule.  The same principle
applies to query params and headers (with the additional header allowlist from
:mod:`~stubsmith.privacy.masking`).

Response body fields follow identical fail-closed semantics using the
``resp.`` namespace: every scalar is masked unless its response-body-relative
path is in the effective keep set.  Kept strings still pass the regex backstop.

Response headers are masked independently via the ``resp_header.`` namespace
(``keep_resp_header``).  A ``header.`` keep rule for a request header does NOT
automatically keep a same-named response header; the namespaces are fully
decoupled.

Belt-and-suspenders regex
--------------------------
String scalars that survive the "keep" check still have regex masks applied
in order to catch residual PII patterns.  When the caller passes ``extra_rules``
(a :class:`~stubsmith.privacy.masking.CompiledRules` from the project's synced
rules), those are used.  Otherwise the module-level
:data:`_EMBEDDED_REGEX_MASKS` (email + credit-card patterns) are applied.
"""

from __future__ import annotations

import json
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

from .masking import (
    HEADER_ALLOWLIST,
    CompiledRules,
    _apply_regexes,
    compile_rules,
)
from .placeholders import generate as _ph_generate, get_salt as _ph_get_salt


# ---------------------------------------------------------------------------
# Embedded default regex masks (belt-and-suspenders backstop)
# ---------------------------------------------------------------------------

_EMBEDDED_REGEX_MASKS: CompiledRules = compile_rules(
    field_masks=[],
    regex_masks=[
        # Email addresses
        {
            "pattern": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
            "replace": "<masked>",
            "flags": "",
        },
        # Credit/debit card - 16 contiguous digits (allow optional space/dash separators)
        {
            "pattern": r"\b(?:\d[ \-]?){15}\d\b",
            "replace": "<masked>",
            "flags": "",
        },
    ],
)


# ---------------------------------------------------------------------------
# Compiled field-rule container
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CompiledFieldRules:
    """Immutable, pre-compiled field rules ready for hot-path application.

    Paths are stored as frozensets keyed within their namespace (body, query,
    header, resp) so lookup is O(1).  For the ``body`` and ``resp`` namespaces,
    paths follow the same dotted/``[]``-segment convention as
    :func:`~stubsmith.privacy.fingerprint.extract_keypaths`.

    Status-scoped response rules use ``FrozenSet[Tuple[int, str]]`` where the
    int is the HTTP status code (100-599) and the str is the body path or
    lowercased header name.  Both ``keep`` and ``mask`` actions are recorded
    for status-scoped rules because a scoped ``mask`` is semantically
    meaningful (it can override a generic ``keep``).
    """

    keep_body: FrozenSet[str]                      # e.g. {"user.email", "items.[].id"}
    keep_query: FrozenSet[str]                     # param names, e.g. {"page", "limit"}
    keep_header: FrozenSet[str]                    # request header names, lowercased
    keep_resp: FrozenSet[str]                      # response-body-relative, e.g. {"id", "status"}
    keep_resp_header: FrozenSet[str]               # response header names, lowercased
    keep_resp_status: FrozenSet[Tuple[int, str]]   # status-scoped response body keeps
    mask_resp_status: FrozenSet[Tuple[int, str]]   # status-scoped response body masks
    keep_resp_header_status: FrozenSet[Tuple[int, str]]  # status-scoped response header keeps
    mask_resp_header_status: FrozenSet[Tuple[int, str]]  # status-scoped response header masks
    # Semantic type hints for mask rules - only populated when the rule carries
    # a ``type`` key.  Absence means no hint is available; the constant placeholder
    # is used.  These are plain dicts (not frozensets) keyed by the namespaced
    # sub-path (after stripping the namespace prefix, matching the keep_* sets).
    body_mask_types: Dict[str, str]   # body sub-path → semantic_type
    query_mask_types: Dict[str, str]  # query param name → semantic_type
    resp_mask_types: Dict[str, str]   # resp body sub-path → semantic_type


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compile_field_rules(field_rules: List[Dict[str, str]]) -> CompiledFieldRules:
    """Build a :class:`CompiledFieldRules` from a raw ``field_rules`` list.

    Parameters
    ----------
    field_rules:
        List of ``{"path": ..., "action": "keep"|"mask"}`` dicts, as returned
        by ``GET /v1/sdk/sync``.  For generic namespaces (``body.``, ``query.``,
        ``header.``, ``resp.``, ``resp_header.``), only ``action: "keep"``
        entries are recorded - absence means mask (fail-closed).  For
        status-scoped namespaces (``resp:NNN.`` and ``resp_header:NNN.``),
        **both** ``keep`` and ``mask`` actions are recorded, because a scoped
        ``mask`` must be able to override a generic ``keep``.

        Malformed status values are silently ignored - no rule is recorded,
        which fails closed to mask.  A status is malformed when it:

        - is not exactly three decimal digits (e.g. ``resp:1.x``,
          ``resp:0404.x``, ``resp:abc.x``),
        - falls outside 100-599 (e.g. ``resp:600.x``, ``resp:099.x``),
        - has no subpath (e.g. ``resp:404`` with no dot),
        - has an empty subpath (e.g. ``resp:404.`` with nothing after the dot).

    Returns
    -------
    CompiledFieldRules
        Thread-safe, immutable compiled field-rule set.  Never raises.
    """
    keep_body: List[str] = []
    keep_query: List[str] = []
    keep_header: List[str] = []
    keep_resp: List[str] = []
    keep_resp_header: List[str] = []
    keep_resp_status: List[Tuple[int, str]] = []
    mask_resp_status: List[Tuple[int, str]] = []
    keep_resp_header_status: List[Tuple[int, str]] = []
    mask_resp_header_status: List[Tuple[int, str]] = []
    body_mask_types: Dict[str, str] = {}
    query_mask_types: Dict[str, str] = {}
    resp_mask_types: Dict[str, str] = {}

    for rule in (field_rules or []):
        if not isinstance(rule, dict):
            continue
        path = rule.get("path") or ""
        action = rule.get("action") or "mask"
        is_keep = action == "keep"
        # Semantic type hint - only meaningful on mask rules.
        sem_type = rule.get("type") if not is_keep else None

        if path.startswith("body."):
            sub = path[5:]              # strip "body." prefix
            if is_keep:
                keep_body.append(sub)
            elif sem_type:
                body_mask_types[sub] = sem_type
        elif path.startswith("query."):
            sub = path[6:]
            if is_keep:
                keep_query.append(sub)
            elif sem_type:
                query_mask_types[sub] = sem_type
        elif path.startswith("resp_header:"):
            # Status-scoped response header - both keep and mask recorded.
            # Must be checked before resp_header. to avoid prefix collision.
            parsed = _parse_status_suffix(path[12:])   # strip "resp_header:"
            if parsed is not None:
                status, name = parsed
                name = name.lower()
                if is_keep:
                    keep_resp_header_status.append((status, name))
                else:
                    mask_resp_header_status.append((status, name))
        elif path.startswith("resp_header."):
            if is_keep:
                keep_resp_header.append(path[12:].lower())  # strip "resp_header." prefix
        elif path.startswith("header."):
            if is_keep:
                keep_header.append(path[7:].lower())
        elif path.startswith("resp:"):
            # Status-scoped response body - both keep and mask recorded.
            # Must be checked before resp. to avoid prefix collision.
            parsed = _parse_status_suffix(path[5:])    # strip "resp:"
            if parsed is not None:
                status, sub_path = parsed
                if is_keep:
                    keep_resp_status.append((status, sub_path))
                else:
                    mask_resp_status.append((status, sub_path))
                    # Propagate type hint into resp_mask_types so that
                    # _walk_and_mask can generate format-preserving values for
                    # status-scoped rules too.  When the same sub-path appears
                    # under multiple status codes with different types, last
                    # write wins - an acceptable approximation given that the
                    # effective keep/mask set is resolved per-status at call time.
                    if sem_type:
                        resp_mask_types[sub_path] = sem_type
        elif path.startswith("resp."):
            sub = path[5:]              # strip "resp." prefix
            if is_keep:
                keep_resp.append(sub)
            elif sem_type:
                resp_mask_types[sub] = sem_type
        # path.{id} entries are metadata (path template namespace) - ignore

    return CompiledFieldRules(
        keep_body=frozenset(keep_body),
        keep_query=frozenset(keep_query),
        keep_header=frozenset(keep_header),
        keep_resp=frozenset(keep_resp),
        keep_resp_header=frozenset(keep_resp_header),
        keep_resp_status=frozenset(keep_resp_status),
        mask_resp_status=frozenset(mask_resp_status),
        keep_resp_header_status=frozenset(keep_resp_header_status),
        mask_resp_header_status=frozenset(mask_resp_header_status),
        body_mask_types=body_mask_types,
        query_mask_types=query_mask_types,
        resp_mask_types=resp_mask_types,
    )


def apply_field_rules(
    body: str,
    headers: Dict[str, Any],
    query_params: str,
    content_type: str,
    compiled: CompiledFieldRules,
    extra_rules: Optional[CompiledRules] = None,
    email_domain: Optional[str] = None,
) -> Tuple[str, Dict[str, Any], str]:
    """Apply *compiled* field rules to *body*, *headers*, and *query_params*.

    Fail-closed: every scalar value is masked unless its namespaced path has
    an explicit ``keep`` rule.  String scalars that survive the keep check
    have *extra_rules* (or the embedded defaults) applied for belt-and-
    suspenders PII removal.

    Parameters
    ----------
    body:
        Raw request or response body string.
    headers:
        Dict of header name → value.
    query_params:
        Raw query string (without leading ``?``).
    content_type:
        Value of the Content-Type header.
    compiled:
        Pre-compiled field rules from :func:`compile_field_rules`.
    extra_rules:
        Optional project-level :class:`~stubsmith.privacy.masking.CompiledRules`
        for additional regex masking.  When ``None``, the built-in
        :data:`_EMBEDDED_REGEX_MASKS` are used as a backstop.
    email_domain:
        Domain to use for generated email placeholders (see
        :mod:`~stubsmith.privacy.placeholders`).  ``None`` defers to the
        module default (``stub.invalid``).

    Returns
    -------
    tuple[str, dict, str]
        ``(masked_body, masked_headers, masked_query_string)``
    """
    regex = extra_rules if extra_rules is not None else _EMBEDDED_REGEX_MASKS
    ct = _normalise_ct(content_type)
    salt = _ph_get_salt()

    masked_headers = _apply_header_rules(headers, compiled.keep_header)
    masked_query = _apply_query_rules(
        query_params, compiled.keep_query, compiled.query_mask_types, regex, salt, email_domain
    )
    masked_body = _apply_body_rules(
        body, ct, compiled.keep_body, compiled.body_mask_types, regex, salt, email_domain
    )

    return masked_body, masked_headers, masked_query


def apply_resp_field_rules(
    resp_body: str,
    resp_headers: Dict[str, Any],
    content_type: str,
    compiled: CompiledFieldRules,
    extra_rules: Optional[CompiledRules] = None,
    resp_status: Optional[int] = None,
    email_domain: Optional[str] = None,
) -> Tuple[str, Dict[str, Any]]:
    """Apply *compiled* field rules to a *resp_body* and *resp_headers*.

    Identical fail-closed semantics to the request body path in
    :func:`apply_field_rules`, but uses the ``resp.`` namespace for the body
    so that request-body keep paths never accidentally expose response body
    scalars.  When *resp_status* is provided, status-scoped rules are resolved
    first according to the precedence below.

    Status-scoped precedence (per field)
    -------------------------------------
    For a response with HTTP status *S* and body path *p*:

    1. A ``resp:S.p`` rule exists → its action wins.
    2. Else a ``resp.p`` rule exists → its action.
    3. Else mask (fail-closed).

    Identical logic applies for response headers (``resp_header:S.n`` /
    ``resp_header.n``).  When *resp_status* is ``None``, only the generic
    ``resp.`` / ``resp_header.`` sets are consulted - existing callers that
    do not pass a status continue to work unchanged.

    Response headers are masked via the allowlist + ``keep_resp_header``
    (the ``resp_header.`` namespace), which is fully independent of
    ``keep_header`` (the ``header.`` request namespace).  A header name present
    only in ``keep_header`` does **not** leak the same-named response header.
    Response query params do not exist; none are processed.

    Parameters
    ----------
    resp_body:
        Raw response body string (may be empty).
    resp_headers:
        Dict of response header name → value.
    content_type:
        Value of the response Content-Type header.
    compiled:
        Pre-compiled field rules from :func:`compile_field_rules`.
    extra_rules:
        Optional project-level :class:`~stubsmith.privacy.masking.CompiledRules`
        for additional regex masking.  When ``None``, the built-in
        :data:`_EMBEDDED_REGEX_MASKS` are used as a backstop.
    resp_status:
        HTTP response status code.  When provided, status-scoped rules for
        this status are applied on top of the generic ``resp.`` /
        ``resp_header.`` sets.  When ``None``, only generic rules apply
        (backward-compatible with callers that predate status-scoped rules).
    email_domain:
        Domain to use for generated email placeholders (see
        :mod:`~stubsmith.privacy.placeholders`).  ``None`` defers to the
        module default (``stub.invalid``).

    Returns
    -------
    tuple[str, dict]
        ``(masked_resp_body, masked_resp_headers)``
    """
    regex = extra_rules if extra_rules is not None else _EMBEDDED_REGEX_MASKS
    ct = _normalise_ct(content_type)
    salt = _ph_get_salt()

    effective_keep_resp = _resolve_resp_keep_set(
        compiled.keep_resp,
        compiled.keep_resp_status,
        compiled.mask_resp_status,
        resp_status,
    )
    effective_keep_resp_header = _resolve_resp_keep_set(
        compiled.keep_resp_header,
        compiled.keep_resp_header_status,
        compiled.mask_resp_header_status,
        resp_status,
    )

    masked_headers = _apply_header_rules(resp_headers, effective_keep_resp_header)
    masked_body = _apply_body_rules(
        resp_body, ct, effective_keep_resp, compiled.resp_mask_types, regex, salt, email_domain
    )
    return masked_body, masked_headers


# ---------------------------------------------------------------------------
# Internal helpers - status-scoped rule resolution
# ---------------------------------------------------------------------------

def _parse_status_suffix(suffix: str) -> Optional[Tuple[int, str]]:
    """Parse the ``NNN.subpath`` tail of a status-scoped rule path.

    Parameters
    ----------
    suffix:
        The portion of the rule path after the namespace prefix and colon,
        e.g. ``"404.error"`` from ``"resp:404.error"``.

    Returns
    -------
    tuple[int, str] or None
        ``(status_code, subpath)`` when valid; ``None`` when the status is
        malformed or the subpath is missing or empty.  Malformed conditions:
        the status string is not exactly three decimal digits, falls outside
        100-599, is absent, or the subpath after the dot is empty.
    """
    dot = suffix.find(".")
    if dot == -1:
        return None  # no dot separator - no subpath
    status_str = suffix[:dot]
    sub_path = suffix[dot + 1:]
    if not sub_path:
        return None  # empty subpath
    # Guard: must be exactly three ASCII decimal digits.  str.isdigit() alone
    # accepts Unicode digit characters (e.g. '²', '٤') that are truthy for
    # isdigit() but cannot be parsed by int(), so the isascii() check is
    # required before the isdigit() check.
    if len(status_str) != 3 or not status_str.isascii() or not status_str.isdigit():
        return None  # not exactly three ASCII decimal digits
    try:
        status = int(status_str)
    except ValueError:
        return None  # belt-and-suspenders: int() must not raise regardless of guard
    if not (100 <= status <= 599):
        return None  # out of valid HTTP status range
    return (status, sub_path)


def _resolve_resp_keep_set(
    generic_keep: FrozenSet[str],
    scoped_keep: FrozenSet[Tuple[int, str]],
    scoped_mask: FrozenSet[Tuple[int, str]],
    status: Optional[int],
) -> FrozenSet[str]:
    """Compute the effective keep set for *status* from generic and scoped sets.

    Parameters
    ----------
    generic_keep:
        Generic ``resp.`` or ``resp_header.`` keep paths.
    scoped_keep:
        Status-scoped keep entries as ``(status, path)`` tuples.
    scoped_mask:
        Status-scoped mask entries as ``(status, path)`` tuples.
    status:
        HTTP response status code.  When ``None``, returns *generic_keep*
        unchanged.

    Returns
    -------
    FrozenSet[str]
        Resolved keep set for this status:
        1. Start from *generic_keep*.
        2. Add any path that has a scoped ``keep`` for *status*.
        3. Remove any path that has a scoped ``mask`` for *status*.
        When the same ``(status, path)`` appears in both sets (a contradictory
        pair), the mask wins - ambiguity resolves to masked (fail-closed).
    """
    if status is None:
        return generic_keep
    effective = set(generic_keep)
    # Apply scoped keeps first, then scoped masks.  When the same (status, path)
    # appears in both sets (a contradictory pair), the mask wins - consistent
    # with the module's fail-closed posture that ambiguity resolves to masked.
    for s, p in scoped_keep:
        if s == status:
            effective.add(p)
    for s, p in scoped_mask:
        if s == status:
            effective.discard(p)
    return frozenset(effective)


# ---------------------------------------------------------------------------
# Internal helpers - body
# ---------------------------------------------------------------------------

def _apply_body_rules(
    body: str,
    ct: str,
    keep_body: FrozenSet[str],
    mask_types: Dict[str, str],
    regex: CompiledRules,
    salt: Optional[bytes],
    email_domain: Optional[str],
) -> str:
    """Mask all scalars in *body* that are not in *keep_body*."""
    if not body:
        return body or ""

    if ct == "application/x-www-form-urlencoded":
        return _apply_form_rules(body, keep_body, mask_types, regex, salt, email_domain)

    try:
        parsed = json.loads(body)
    except Exception:
        # Non-JSON, non-form body - fail-closed: mask entirely
        return "<masked>"

    return json.dumps(_walk_and_mask(parsed, "", keep_body, mask_types, regex, salt, email_domain))


def _walk_and_mask(
    obj: Any,
    prefix: str,
    keep_set: FrozenSet[str],
    mask_types: Dict[str, str],
    regex: CompiledRules,
    salt: Optional[bytes],
    email_domain: Optional[str],
) -> Any:
    """Recursively mask all scalars whose path is not in *keep_set*.

    - Dicts: recurse into each key (path grows with ``.key``).
    - Lists: iterate ALL elements through the ``[]`` path segment.
    - Scalars at a path in *keep_set*: kept; string values still get regex masks.
    - Scalars not in *keep_set*: type-appropriate placeholder (fail-closed).
      When the path has a semantic type hint in *mask_types* and a salt is
      available, a format-preserving placeholder is generated instead.
    """
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            child_path = f"{prefix}.{k}" if prefix else k
            out[k] = _walk_and_mask(v, child_path, keep_set, mask_types, regex, salt, email_domain)
        return out

    if isinstance(obj, list):
        arr_path = f"{prefix}.[]" if prefix else "[]"
        return [_walk_and_mask(e, arr_path, keep_set, mask_types, regex, salt, email_domain) for e in obj]

    # Scalar
    if obj is None:
        return None

    if prefix in keep_set:
        # Keep this value; run regex backstop on strings.
        if isinstance(obj, str):
            return _apply_regexes(obj, regex)
        return obj

    # Mask - type-appropriate placeholder (mirrors mask_all semantics).
    # When a semantic type hint is available and a salt has been configured,
    # delegate to placeholders.generate for a format-preserving fake value.
    sem_type = mask_types.get(prefix)
    if sem_type is not None:
        return _ph_generate(sem_type, obj, salt, email_domain=email_domain)

    if isinstance(obj, bool):
        return False
    if isinstance(obj, (int, float)):
        return 0
    return "<masked>"  # str and any other scalar


def _apply_form_rules(
    body: str,
    keep_body: FrozenSet[str],
    mask_types: Dict[str, str],
    regex: CompiledRules,
    salt: Optional[bytes],
    email_domain: Optional[str],
) -> str:
    """Apply field rules to a form-encoded body string."""
    try:
        parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
    except Exception:
        return "<masked>"
    out: Dict[str, List[str]] = {}
    for k, vals in parsed.items():
        if k in keep_body:
            out[k] = [_apply_regexes(v, regex) for v in vals]
        else:
            sem_type = mask_types.get(k)
            if sem_type is not None:
                out[k] = [
                    str(_ph_generate(sem_type, v, salt, email_domain=email_domain))
                    for v in vals
                ]
            else:
                out[k] = ["<masked>"] * len(vals)
    return urllib.parse.urlencode(out, doseq=True)


# ---------------------------------------------------------------------------
# Internal helpers - headers
# ---------------------------------------------------------------------------

def _apply_header_rules(
    headers: Dict[str, Any],
    keep_header: FrozenSet[str],
) -> Dict[str, Any]:
    """Apply allowlist + explicit keep rules to headers.

    A header value is kept when the lowercased header name is in
    ``HEADER_ALLOWLIST`` **or** has an explicit ``keep`` rule.  Everything
    else is masked.
    """
    out: Dict[str, Any] = {}
    for k, v in headers.items():
        lower = k.lower()
        if lower in HEADER_ALLOWLIST or lower in keep_header:
            out[k] = v
        else:
            out[k] = "<masked>"
    return out


# ---------------------------------------------------------------------------
# Internal helpers - query
# ---------------------------------------------------------------------------

def _apply_query_rules(
    query_string: str,
    keep_query: FrozenSet[str],
    mask_types: Dict[str, str],
    regex: CompiledRules,
    salt: Optional[bytes],
    email_domain: Optional[str],
) -> str:
    """Mask all query param values not in *keep_query*."""
    if not query_string:
        return query_string or ""
    try:
        parsed = urllib.parse.parse_qs(query_string, keep_blank_values=True)
    except Exception:
        return "<masked>"
    out: Dict[str, List[str]] = {}
    for k, vals in parsed.items():
        if k in keep_query:
            out[k] = [_apply_regexes(v, regex) for v in vals]
        else:
            sem_type = mask_types.get(k)
            if sem_type is not None:
                out[k] = [
                    str(_ph_generate(sem_type, v, salt, email_domain=email_domain))
                    for v in vals
                ]
            else:
                out[k] = ["<masked>"] * len(vals)
    return urllib.parse.urlencode(out, doseq=True)


# ---------------------------------------------------------------------------
# Internal helpers - shared
# ---------------------------------------------------------------------------

def _normalise_ct(content_type: str) -> str:
    """Lowercase and strip charset / boundary params."""
    return (content_type or "").lower().split(";")[0].strip()
