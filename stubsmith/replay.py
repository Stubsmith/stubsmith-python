"""
stubsmith.replay - offline HTTP replay for the requests library.

Intercepts outbound requests at the ``Session.send`` level, fingerprints each
request the same way the capture path does, and returns the recorded response
from a bundle file.  No network call is ever made.

Usage::

    import stubsmith

    def test_checkout():
        with stubsmith.replay():
            result = my_app.checkout(cart)
        assert result.order_id

Also works with explicit ``start()`` / ``stop()`` for ``unittest.setUp``::

    class MyTest(unittest.TestCase):
        def setUp(self):
            self._replay = stubsmith.replay()
            self._replay.start()

        def tearDown(self):
            self._replay.stop()

Public API
----------
* :func:`replay` - factory returning a :class:`ReplayContext`
* :class:`ReplayContext` - the context manager / explicit start-stop
* :exc:`StubNotFound` - raised on a miss in strict mode

Bundle format
-------------
Produced by ``stubsmith pull`` (``GET /v1/replay/bundle``)::

    {
      "ok": true,
      "version": 1,
      "endpoints": [
        {
          "domain": "api.example.com",
          "method": "GET",
          "path_template": "/api/users/{id}",
          "is_dynamic": true,
          "fingerprint_value_paths": [],
          "stubs": [
            {
              "fingerprint": "abc123def456...",
              "key_paths": ["id", "name"],
              "field_rules": [],
              "degraded": false,
              "variants": [
                {
                  "status": 200,
                  "count": 42,
                  "duration_ms": 15,
                  "headers": {"content-type": "application/json"},
                  "body": "{...}"
                }
              ]
            }
          ]
        }
      ]
    }

Bundle lookup key
-----------------
Lookups are keyed on the composite ``(domain, method, path_template,
fingerprint)`` - never on fingerprint alone.  A fingerprint hashes body
key-paths, query-parameter names, and content-type but does NOT include the
host or path.  Every body-less GET therefore shares the same hash.  In one
production catalog run, six endpoints (three ``/avatars/*.png``,
``GET /api/products``, ``GET /api/users/{id}``, ``GET /api/orders/{id}``)
all carried the hash ``fc552c95a0bb0d3e``.  Keying on hash alone would serve
one endpoint's body for all six callers.

Interaction with install()
--------------------------
When both :func:`~stubsmith.instrument.install` and :func:`replay` are
active, capture is suppressed entirely while replay is running.
``install()`` patches ``Session.request`` (outer layer), which eventually
calls ``Session.send`` - the layer replay patches.  Without suppression,
install's wrapper would receive the stub response and enqueue it as though
it were production traffic, polluting the project with synthetic fingerprints
and captures that consume plan quota and contaminate the review queue.

``replay.start()`` increments a shared depth counter; ``stop()`` decrements
it.  ``client._capture_requests`` and ``client._capture_httpx`` return early
when the counter is positive.  The counter (not a boolean) makes nested
``replay()`` blocks safe: the inner block's ``stop()`` does not re-enable
capture while the outer block is still running.  Capture resumes immediately
after the outermost ``replay()`` context exits.
"""

from __future__ import annotations

import datetime
import http.client
import json
import os
import pathlib
from typing import AbstractSet, Any, Callable, Dict, Iterator, List, Optional, Tuple, Union
from urllib.parse import urlparse

from ._replay_state import enter_replay, exit_replay
from .privacy.fingerprint import (
    extract_keypaths as _extract_keypaths,
    fingerprint as _fingerprint,
    unique_query_names as _unique_query_names,
)
from .privacy.templating import CuratedTemplate, load_curated_templates, template_path
from .testing import _HOP_BY_HOP

_DEFAULT_BUNDLE_ENV = "STUBSMITH_BUNDLE"
_DEFAULT_BUNDLE_PATH = ".stubsmith/bundle.json"
_REFRESH_HINT = "  refresh the bundle:  stubsmith pull"

# Type aliases
_BundleDict = Dict[str, Any]
_StubKey = Tuple[str, str, str, str]   # (domain, method, path_template, fingerprint)
_EndpointKey = Tuple[str, str, str]    # (domain, method, path_template)

# ---------------------------------------------------------------------------
# Module-level helpers for near-miss diagnostics
# ---------------------------------------------------------------------------

# Sentinel returned when a key-path is absent from a body.
_PATH_MISSING: object = object()


def _ct_norm(ct: str) -> str:
    """Lowercase and strip charset/boundary params from a content-type value."""
    return (ct or "").lower().split(";")[0].strip()


def _get_path_value(body: str, content_type: str, dot_path: str) -> Any:
    """Return the value at *dot_path* in *body*, or :data:`_PATH_MISSING`.

    Parameters
    ----------
    body:
        Raw request or response body string.
    content_type:
        Content-Type header value.
    dot_path:
        Dot-separated key path (e.g. ``"user.id"``).  For form-encoded
        bodies, treated as a literal top-level key name.

    Returns
    -------
    Any
        The scalar or container value found at the path, or
        :data:`_PATH_MISSING` when the path does not exist or the body
        cannot be parsed.  Never raises.
    """
    try:
        ct = _ct_norm(content_type)
        if ct == "application/x-www-form-urlencoded":
            import urllib.parse as _up
            parsed_form = _up.parse_qs(body or "", keep_blank_values=True)
            vals = parsed_form.get(dot_path)
            return vals[0] if vals else _PATH_MISSING
        parsed = json.loads(body or "null")
        node: Any = parsed
        for key in dot_path.split("."):
            if not isinstance(node, dict):
                return _PATH_MISSING
            node = node.get(key, _PATH_MISSING)
            if node is _PATH_MISSING:
                return _PATH_MISSING
        return node
    except Exception:
        return _PATH_MISSING


# _PATH_COL_WIDTH: minimum column width for the path segment of a diff line.
# Paths shorter than this are padded so the annotation aligns across lines.
_PATH_COL_WIDTH = 36


def _filter_leaf_paths(paths: List[str]) -> List[str]:
    """Return *paths* with intermediate-node entries removed.

    A path is an intermediate node when another path in the same set starts
    with ``path + "."``.  Leaf paths (nothing beneath them in the set) are
    always kept, including an empty object that differs as a unit with no
    child paths in the diff.

    This mirrors ``filterLeafPaths`` in ``ui/src/lib/fieldRules.js``, which
    applies the same suppression when rendering the field-rules review UI.

    Parameters
    ----------
    paths:
        Sorted list of dot-separated key-paths.

    Returns
    -------
    list[str]
        Filtered list, preserving order.  Never returns an empty list when
        *paths* is non-empty (caller falls back to *paths* unchanged if
        filtering would empty the result, but that case is unreachable for
        well-formed path sets).
    """
    filtered = [p for p in paths if not any(other.startswith(p + ".") for other in paths)]
    # Safety: if filtering somehow removed everything, fall back to the
    # original list so the diff is noisy rather than blank.
    return filtered if filtered else paths


def _fmt_diff_line(sigil: str, path: str, annotation: str) -> str:
    """Format one ``+``/``-`` diff line with aligned annotation column.

    Parameters
    ----------
    sigil:
        ``"+"`` or ``"-"``.
    path:
        The key-path (or query param name) being annotated.
    annotation:
        Human-readable explanation (e.g. ``"sent, not in the recording"``).

    Returns
    -------
    str
        A single line like ``"    + metadata.coupon_code        sent, not in the recording"``.
    """
    padded = path.ljust(_PATH_COL_WIDTH)
    return f"    {sigil} {padded}  {annotation}"


def _build_miss_message(
    method: str,
    path_tmpl: str,
    fp: str,
    domain: str,
    sent_body: str,
    sent_content_type: str,
    sent_query_string: str,
    value_paths: List[str],
    ep_candidates: List[Dict[str, Any]],
    all_ep_keys: List["_EndpointKey"],
) -> str:
    """Build a human-readable near-miss diagnostic message for a stub miss.

    Parameters
    ----------
    method:
        HTTP method of the unmatched request.
    path_tmpl:
        Templated path of the unmatched request.
    fp:
        Fingerprint of the unmatched request.
    domain:
        Netloc of the unmatched request (used in case-1 messages).
    sent_body:
        Raw body string of the unmatched request.
    sent_content_type:
        Content-Type header value of the unmatched request.
    sent_query_string:
        Raw query string of the unmatched request.
    value_paths:
        ``fingerprint_value_paths`` configured for this endpoint.
    ep_candidates:
        Stubs recorded for this endpoint.  Empty when no traffic was
        recorded for the endpoint at all (case 1).
    all_ep_keys:
        All ``(domain, method, path_template)`` tuples present in the
        bundle.  Used to list alternatives for case-1 messages.

    Returns
    -------
    str
        Multi-line diagnostic message suitable for passing directly to
        :exc:`StubNotFound`.
    """
    header = (
        f"no recorded stub for {method} {path_tmpl}  "
        f"(fingerprint {fp})"
    )

    if not ep_candidates:
        # ── Case 1: no endpoint match ──────────────────────────────────────
        lines: List[str] = [header, ""]
        lines.append(
            f"No traffic has been recorded for {method} {domain}."
        )
        same_method = [
            (d, pt) for (d, m, pt) in all_ep_keys if m == method
        ]
        if same_method:
            lines.append(f"\nEndpoints recorded with {method} in this bundle:")
            show_ep = same_method[:6]
            for d, pt in show_ep:
                if d == domain:
                    lines.append(f"  {method} {pt}")
                else:
                    lines.append(f"  {method} {d}{pt}")
            if len(same_method) > 6:
                lines.append(f"  … and {len(same_method) - 6} more")
        else:
            lines.append(
                f"\nNo {method} endpoints are recorded in this bundle."
            )
        lines.append("")
        lines.append(_REFRESH_HINT)
        return "\n".join(lines)

    # ── Case 2+: endpoint matched, fingerprint did not ─────────────────────
    sent_kps = set(_extract_keypaths(sent_body, sent_content_type))
    sent_qns = set(_unique_query_names(sent_query_string))
    sent_ct = _ct_norm(sent_content_type)

    def _score(cand: Dict[str, Any]) -> int:
        cand_kps = set(cand["key_paths"])
        score = len(sent_kps.symmetric_difference(cand_kps))
        cand_qns = cand.get("query_names")
        if cand_qns is not None:
            score += len(sent_qns.symmetric_difference(set(cand_qns)))
        cand_ct = cand.get("content_type")
        if cand_ct is not None and _ct_norm(cand_ct) != sent_ct:
            score += 1
        return score

    scored = sorted(ep_candidates, key=_score)
    total = len(scored)
    show_cands = scored[:2]

    lines = [header, ""]
    if total > 2:
        lines.append(
            f"{total} recordings found for this endpoint; "
            f"showing the 2 closest.\n"
        )

    for cand in show_cands:
        cand_fp = cand["fingerprint"]
        total_count = cand["total_count"]
        cand_kps = set(cand["key_paths"])

        # ── Key-path diff - filter intermediate nodes at render time only.
        # Scoring (above) uses the full symmetric difference for accuracy;
        # display collapses parent paths when a child is also in the diff.
        raw_only_sent_kps = sorted(sent_kps - cand_kps)
        raw_only_rec_kps = sorted(cand_kps - sent_kps)
        only_sent_kps = _filter_leaf_paths(raw_only_sent_kps)
        only_rec_kps = _filter_leaf_paths(raw_only_rec_kps)
        has_kp_diff = bool(raw_only_sent_kps or raw_only_rec_kps)

        qn_diff_lines: List[str] = []
        cand_qns = cand.get("query_names")
        if cand_qns is not None:
            cand_qns_set = set(cand_qns)
            for q in sorted(sent_qns - cand_qns_set):
                qn_diff_lines.append(
                    _fmt_diff_line("+", f"?{q}", "sent, not in the recording")
                )
            for q in sorted(cand_qns_set - sent_qns):
                qn_diff_lines.append(
                    _fmt_diff_line("-", f"?{q}", "in the recording, not sent")
                )

        ct_diff_lines: List[str] = []
        cand_ct_raw = cand.get("content_type")
        if cand_ct_raw is not None:
            cand_ct = _ct_norm(cand_ct_raw)
            if cand_ct != sent_ct:
                ct_diff_lines.append(
                    f"    Content-Type:\n"
                    f"      sent:       {sent_ct or '(none)'}\n"
                    f"      recording:  {cand_ct or '(none)'}"
                )

        has_any_diff = has_kp_diff or qn_diff_lines or ct_diff_lines

        if not has_any_diff:
            # Determine which fingerprint inputs the bundle supplied.
            # TODO: GET /v1/replay/bundle should emit query_names and
            # content_type per stub.  The server already holds both
            # (fingerprints.query_names and the capture's request
            # Content-Type header), so this is a bundle-shape addition,
            # not new data collection.
            # TODO: for value-discriminated endpoints (fingerprint_value_paths
            # non-empty), showing which discriminator value the recording holds
            # would give the user a direct "you sent X, recording expects Y"
            # hint.  That requires a per-stub request_value_samples map in the
            # bundle - only for paths that are 'keep' (values are legitimately
            # retained), and it is a new data flow out of the server that needs
            # deliberate privacy review before shipping.
            missing_bundle_fields: List[str] = []
            if cand_qns is None:
                missing_bundle_fields.append("query-parameter names")
            if cand_ct_raw is None:
                missing_bundle_fields.append("content-type")

            if not missing_bundle_fields:
                # All three fingerprint inputs (key-paths, query-parameter
                # names, content-type) compared and matched - genuine anomaly.
                lines.append(
                    f"The request appears structurally identical to recording "
                    f"{cand_fp} but hashed differently.\n"
                    f"This indicates a fingerprint symmetry bug in the SDK - "
                    f"please report it at "
                    f"https://github.com/stubsmith/stubsmith-python/issues."
                )
            else:
                # Key-paths are identical but the bundle omits some fingerprint
                # inputs; only advise checking the ones we could not compare.
                missing_str = " and ".join(missing_bundle_fields)
                check_lines: List[str] = []
                if cand_qns is None:
                    check_lines.append(
                        f"  - query-parameter names: compare ?name=... in "
                        f"your request to what was captured"
                    )
                if cand_ct_raw is None:
                    check_lines.append(
                        f"  - content-type: compare the Content-Type header "
                        f"in your request to what was captured"
                    )
                lines.append(
                    f"Closest recording  {cand_fp}  (seen {total_count}x) - "
                    f"key-paths are identical.\n"
                    f"The fingerprint difference likely lies in {missing_str}, "
                    f"which this bundle does not record.\n"
                    f"Check by hand:\n"
                    + "\n".join(check_lines) + "\n"
                    f"Re-pull with a newer server to get a bundle that "
                    f"includes {missing_str}."
                )
            lines.append("")
        else:
            lines.append(
                f"Closest recording  {cand_fp}  (seen {total_count}x):"
            )
            for kp in only_sent_kps:
                lines.append(_fmt_diff_line("+", kp, "sent, not in the recording"))
            for kp in only_rec_kps:
                lines.append(_fmt_diff_line("-", kp, "in the recording, not sent"))
            lines.extend(qn_diff_lines)
            lines.extend(ct_diff_lines)
            lines.append("")

    lines.append(_REFRESH_HINT)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public exceptions
# ---------------------------------------------------------------------------

class StubNotFound(Exception):
    """Raised when a request cannot be matched to any stub in strict mode.

    Attributes
    ----------
    method:
        HTTP method of the unmatched request (e.g. ``"GET"``).
    path_template:
        Templated path as computed by the replay hook (e.g.
        ``"/api/users/{id}"``).
    fingerprint:
        Structural fingerprint of the unmatched request.
    """

    def __init__(
        self,
        method: str,
        path_template: str,
        fp: str,
        message: str = "",
    ) -> None:
        self.method = method
        self.path_template = path_template
        self.fingerprint = fp
        if not message:
            message = (
                f"no recorded stub for {method} {path_template}  "
                f"(fingerprint {fp})\n\n"
                f"{_REFRESH_HINT}"
            )
        super().__init__(message)


# ---------------------------------------------------------------------------
# Bundle loading
# ---------------------------------------------------------------------------

def _load_bundle_from_path(path: Union[str, pathlib.Path]) -> _BundleDict:
    """Load and parse a bundle JSON file.

    Parameters
    ----------
    path:
        Filesystem path to the bundle file.

    Returns
    -------
    dict
        Parsed bundle data.

    Raises
    ------
    FileNotFoundError
        When *path* does not exist or cannot be read.
    ValueError
        When the file is not valid JSON or does not contain a JSON object.
    """
    p = pathlib.Path(path)
    if not p.exists():
        raise FileNotFoundError(
            f"Bundle file not found: {p}. "
            "Run 'stubsmith pull' to fetch the bundle from the server."
        )
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise FileNotFoundError(f"Cannot read bundle file {p}: {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Bundle file {p} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(
            f"Bundle file {p} must contain a JSON object at the top level."
        )
    return data


def _find_bundle_upward(start: pathlib.Path) -> Optional[pathlib.Path]:
    """Walk upward from *start* looking for ``.stubsmith/bundle.json``.

    The walk is capped at the first project-boundary directory - i.e. the
    first ancestor (inclusive) that contains ``.git`` or ``pyproject.toml``.
    That directory is still checked for a bundle before the walk stops, but
    the walk does not continue past it.  This prevents a bundle that lives
    outside the project from being picked up silently, which would cause the
    wrong stubs to be replayed.

    Returns the first path found inside the project boundary, or ``None``
    when no bundle is found within that boundary.
    """
    current = start.resolve()
    while True:
        candidate = current / _DEFAULT_BUNDLE_PATH
        if candidate.is_file():
            return candidate
        # Check whether this directory is a project boundary.  Do this AFTER
        # checking for the bundle so that a bundle at the boundary is found.
        is_boundary = (current / ".git").exists() or (current / "pyproject.toml").exists()
        if is_boundary:
            return None
        parent = current.parent
        if parent == current:
            # Filesystem root reached without hitting a boundary.
            return None
        current = parent


def _resolve_bundle(
    bundle: Optional[Union[str, pathlib.Path, _BundleDict]],
) -> Tuple[_BundleDict, Optional[pathlib.Path]]:
    """Resolve the *bundle* argument to a parsed dict and its filesystem path.

    Resolution order:

    1. *bundle* when provided (dict used as-is; str/Path loaded from disk).
    2. ``$STUBSMITH_BUNDLE`` environment variable (interpreted as a path).
    3. ``.stubsmith/bundle.json`` searched upward from the current working
       directory, stopping at the first directory that contains ``.git`` or
       ``pyproject.toml`` (the project boundary).

    Parameters
    ----------
    bundle:
        A filesystem path (str or :class:`pathlib.Path`), a pre-parsed
        dict, or ``None`` to trigger environment/default resolution.

    Returns
    -------
    tuple
        ``(data, path)`` where *data* is the parsed bundle dict and *path* is
        the :class:`pathlib.Path` to the file that was loaded, or ``None``
        when the bundle was supplied as an in-memory dict.

    Raises
    ------
    FileNotFoundError
        When no bundle can be located via any of the three resolution steps.
    ValueError
        When the resolved file is not valid JSON or is malformed.
    """
    if bundle is not None:
        if isinstance(bundle, dict):
            return bundle, None
        p = pathlib.Path(bundle)
        return _load_bundle_from_path(p), p.resolve()

    env_path = os.environ.get(_DEFAULT_BUNDLE_ENV)
    if env_path:
        p = pathlib.Path(env_path)
        return _load_bundle_from_path(p), p.resolve()

    start = pathlib.Path.cwd()
    found = _find_bundle_upward(start)
    if found is None:
        raise FileNotFoundError(
            f"No bundle found. Searched for {_DEFAULT_BUNDLE_PATH!r} starting "
            f"from {start} up to the first .git / pyproject.toml boundary. "
            f"Provide a path, set ${_DEFAULT_BUNDLE_ENV}, "
            "or run 'stubsmith pull' to create the file."
        )
    return _load_bundle_from_path(found), found


# ---------------------------------------------------------------------------
# Bundle index
# ---------------------------------------------------------------------------

def _build_index(  # noqa: C901
    data: _BundleDict,
) -> Tuple[
    Dict[_StubKey, Dict[str, Any]],
    Dict[Tuple[str, str], List[CuratedTemplate]],
    Dict[_EndpointKey, List[str]],
    Dict[_EndpointKey, List[Dict[str, Any]]],
]:
    """Build in-memory lookup tables from bundle data.

    Returns
    -------
    index:
        Maps ``(domain, method, path_template, fingerprint)`` to a dict
        with keys ``"variants"`` and ``"key_paths"``.  The composite key
        is used for all lookups to avoid fingerprint hash collisions across
        endpoints (see module docstring).
    curated_by_method_domain:
        Maps ``(method, domain)`` to a sorted :class:`CuratedTemplate` list
        for use with :func:`~stubsmith.privacy.templating.template_path`.
    value_paths_by_endpoint:
        Maps ``(domain, method, path_template)`` to the endpoint's
        ``fingerprint_value_paths`` list, consulted before fingerprint
        computation.
    stubs_by_endpoint:
        Maps ``(domain, method, path_template)`` to a list of candidate
        stub dicts (fingerprint, key_paths, total_count, variants, and
        optionally query_names/content_type when the bundle includes them).
        Used by :func:`_build_miss_message` for near-miss diagnostics.
    """
    endpoints: List[Dict[str, Any]] = data.get("endpoints") or []

    index: Dict[_StubKey, Dict[str, Any]] = {}
    template_map: Dict[Tuple[str, str], List[str]] = {}
    value_paths_by_endpoint: Dict[_EndpointKey, List[str]] = {}
    stubs_by_endpoint: Dict[_EndpointKey, List[Dict[str, Any]]] = {}

    for ep in endpoints:
        domain = ep.get("domain") or ""
        method = (ep.get("method") or "").upper()
        path_template = ep.get("path_template") or ""
        value_paths: List[str] = ep.get("fingerprint_value_paths") or []

        ep_key: _EndpointKey = (domain, method, path_template)
        value_paths_by_endpoint[ep_key] = value_paths
        if ep_key not in stubs_by_endpoint:
            stubs_by_endpoint[ep_key] = []

        # Accumulate all path templates for this (method, domain) so that
        # template_path() can find the best-matching curated template.
        meth_dom_key: Tuple[str, str] = (method, domain)
        if meth_dom_key not in template_map:
            template_map[meth_dom_key] = []
        if path_template not in template_map[meth_dom_key]:
            template_map[meth_dom_key].append(path_template)

        stubs: List[Dict[str, Any]] = ep.get("stubs") or []
        for stub in stubs:
            fp = stub.get("fingerprint") or ""
            stub_key: _StubKey = (domain, method, path_template, fp)
            variants: List[Dict[str, Any]] = stub.get("variants") or []
            key_paths: List[str] = stub.get("key_paths") or []
            index[stub_key] = {
                "variants": variants,
                "key_paths": key_paths,
            }
            # Build candidate entry for near-miss diagnostics.
            total_count = sum(v.get("count", 1) for v in variants)
            candidate: Dict[str, Any] = {
                "fingerprint": fp,
                "key_paths": key_paths,
                "total_count": total_count,
                "variants": variants,
            }
            # query_names and content_type are optional - included when the
            # server embeds them in the bundle stub (future bundle schema
            # v2+).  Stored as None when absent so the diff renderer can
            # tell "not recorded" from "empty list / empty string".
            raw_qn = stub.get("query_names")
            candidate["query_names"] = list(raw_qn) if raw_qn is not None else None
            raw_ct = stub.get("content_type")
            candidate["content_type"] = raw_ct if raw_ct is not None else None
            stubs_by_endpoint[ep_key].append(candidate)

    curated_by_method_domain: Dict[Tuple[str, str], List[CuratedTemplate]] = {
        k: load_curated_templates(v) for k, v in template_map.items()
    }

    return index, curated_by_method_domain, value_paths_by_endpoint, stubs_by_endpoint


# ---------------------------------------------------------------------------
# Variant selection
# ---------------------------------------------------------------------------

def _flatten_responses(variants: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Expand *variants* into a flat, ordered list of individual responses.

    A bundle variant is one response status. When the bundle was fetched with
    ``samples>1`` the variant also carries a ``samples`` array holding that
    status's rolling window, newest first, and each entry is a distinct
    recording with its own body. This flattens both dimensions into the unit a
    caller actually iterates: one recorded response.

    Order is deliberate and stable:

    1. The variant :func:`_select_variant` would have chosen comes first, with
       its newest sample at index 0. That makes ``replay_all()``'s first pass
       serve exactly what plain ``replay()`` serves, so a test that passes
       under ``replay()`` still passes on pass one.
    2. Remaining variants follow, ordered by status, so a 200 is exercised
       before a 500 and the order does not shift between runs.
    3. Within a variant, samples stay in bundle order (newest first).

    Each returned dict is shaped for :func:`_build_response` (``status``,
    ``headers``, ``body``, ``duration_ms``) plus, when the bundle supplied
    them, ``capture_id`` and ``captured_at`` identifying the recording.
    """
    if not variants:
        return []

    primary = _select_variant(variants)
    ordered: List[Dict[str, Any]] = []
    if primary is not None:
        ordered.append(primary)
    ordered.extend(
        sorted(
            (v for v in variants if v is not primary),
            key=lambda v: v.get("status", 0),
        )
    )

    responses: List[Dict[str, Any]] = []
    for variant in ordered:
        status = variant.get("status", 200)
        count = variant.get("count", 1)
        samples = variant.get("samples")
        if not samples:
            # samples=1 bundle (or a pre-samples server): the variant is the
            # only recording of this status.
            responses.append({
                "status": status,
                "count": count,
                "duration_ms": variant.get("duration_ms"),
                "headers": variant.get("headers") or {},
                "body": variant.get("body"),
                "capture_id": None,
                "captured_at": None,
                "body_capped": bool(variant.get("body_capped")),
            })
            continue
        for sample in samples:
            responses.append({
                "status": status,
                "count": count,
                "duration_ms": sample.get("duration_ms", variant.get("duration_ms")),
                "headers": sample.get("headers") or variant.get("headers") or {},
                "body": sample.get("body"),
                "capture_id": sample.get("capture_id"),
                "captured_at": sample.get("captured_at"),
                "body_capped": bool(sample.get("body_capped")),
            })
    return responses


def _select_variant(variants: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Select the best variant deterministically.

    Rule: prefer the variant with the highest ``count`` (most frequently
    observed in captured traffic).  Ties are broken by lowest ``status``
    code so the choice is stable across runs and predictably favours the
    happy-path 200 over error variants when both are equally common.

    Parameters
    ----------
    variants:
        List of variant dicts from the bundle (each has ``status``,
        ``count``, ``headers``, ``body``, ``duration_ms``).

    Returns
    -------
    dict or None
        The selected variant, or ``None`` when *variants* is empty.
    """
    if not variants:
        return None
    # Sort key: (-count, status) → highest count first, lowest status on ties.
    return min(variants, key=lambda v: (-v.get("count", 1), v.get("status", 0)))


# ---------------------------------------------------------------------------
# Response construction
# ---------------------------------------------------------------------------

def _build_response(request: Any, variant: Dict[str, Any]) -> Any:
    """Construct a genuine ``requests.Response`` from a bundle variant.

    The returned object behaves identically to a real network response:
    ``raise_for_status()``, ``.json()``, and ``.headers`` all work as in
    production.

    Hop-by-hop headers (``content-length``, ``transfer-encoding``, etc.)
    are stripped before serving - urllib3 rejects a body whose
    Content-Length no longer matches the replayed bytes, and
    Transfer-Encoding has no meaning for an in-process stub (reuses the
    ``_HOP_BY_HOP`` set from :mod:`stubsmith.testing`).

    Parameters
    ----------
    request:
        The originating ``PreparedRequest``; stored as ``response.request``.
    variant:
        A bundle variant dict.

    Returns
    -------
    requests.Response
    """
    import requests as _requests
    from requests.structures import CaseInsensitiveDict

    response = _requests.Response()
    response.status_code = variant.get("status", 200)
    response.request = request
    # url is required for raise_for_status() to produce a useful message
    # (without it the exception reads "None for url: None").
    response.url = request.url or ""
    # reason is required so raise_for_status() renders "404 Not Found" rather
    # than "404 None"; http.client.responses maps codes to canonical phrases.
    response.reason = http.client.responses.get(response.status_code, "")

    # Elapsed: use the recorded duration_ms; fall back to zero.
    duration_ms = variant.get("duration_ms") or 0
    response.elapsed = datetime.timedelta(milliseconds=duration_ms)

    # Strip hop-by-hop headers.
    raw_headers: Dict[str, str] = variant.get("headers") or {}
    safe_headers = {
        k: v
        for k, v in raw_headers.items()
        if k.lower() not in _HOP_BY_HOP
    }
    response.headers = CaseInsensitiveDict(safe_headers)

    # Body: bundle stores it as a JSON-encoded string or null.
    raw_body = variant.get("body") or ""
    if isinstance(raw_body, (dict, list)):
        raw_body = json.dumps(raw_body)
    body_bytes = raw_body.encode("utf-8") if raw_body else b""
    response._content = body_bytes
    response.encoding = "utf-8"

    return response


class ServedResponse:
    """One recorded response that a replay context served.

    Yielded through :meth:`ReplayContext.served` so a test can assert on what
    it actually exercised rather than assuming.
    """

    __slots__ = ("domain", "method", "path_template", "fingerprint",
                 "status", "capture_id", "captured_at", "index", "total")

    def __init__(
        self,
        domain: str,
        method: str,
        path_template: str,
        fingerprint: str,
        status: int,
        capture_id: Optional[str],
        captured_at: Optional[str],
        index: int,
        total: int,
    ) -> None:
        self.domain = domain
        self.method = method
        self.path_template = path_template
        self.fingerprint = fingerprint
        self.status = status
        self.capture_id = capture_id
        self.captured_at = captured_at
        #: Position of this response in its stub's recorded list.
        self.index = index
        #: How many responses that stub has recorded in total.
        self.total = total

    @property
    def endpoint(self) -> str:
        """``"GET api.example.com/v1/orders/{id}"`` - for test ids and messages."""
        return f"{self.method} {self.domain}{self.path_template}"

    @property
    def exhausted(self) -> bool:
        """True when this was the last recorded response for its stub.

        A stub with fewer responses than the current pass number keeps serving
        its final recording, so this distinguishes "clamped, nothing new" from
        "genuinely advancing".
        """
        return self.index >= self.total - 1

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return (
            f"<ServedResponse {self.endpoint} status={self.status} "
            f"{self.index + 1}/{self.total}"
            + (f" capture={self.capture_id}" if self.capture_id else "")
            + ">"
        )


def _status_filter_message(
    method: str,
    path_tmpl: str,
    fp: str,
    statuses: "AbstractSet[int]",
    available: List[int],
) -> str:
    """Explain that recordings exist for this shape, but not of the wanted status.

    Distinct from an ordinary miss: the shape matched and has recordings, so the
    near-miss key-path diff would be noise. What the caller needs is the gap
    between what they asked for and what was recorded.
    """
    wanted = ", ".join(str(x) for x in sorted(statuses))
    got = ", ".join(str(x) for x in sorted(set(available))) or "none"
    return (
        f"no recorded {wanted} response for {method} {path_tmpl}  "
        f"(fingerprint {fp})\n\n"
        f"statuses recorded for this shape: {got}\n\n"
        "This shape is in the bundle, so the request matched; it has no recording "
        "of the status you filtered to. Serving one of the statuses above instead "
        "would make the loop assert against a response it was told to exclude.\n\n"
        "Either widen statuses=, or exclude this endpoint from the loop.\n\n"
        f"{_REFRESH_HINT}"
    )


class _PassState:
    """Shared cursor across the contexts :func:`replay_all` yields.

    A cursor **per request shape**, not one global pass index. Which endpoints
    a pass touches is only discovered by running the caller's code, and a later
    pass can reach shapes an earlier one never did: code that branches on a 429
    takes a different path than code that got a 200. A global index would then
    start a late-discovered shape partway through its recordings and skip the
    earlier ones - the shape would be looped incompletely precisely because it
    was found late.

    So each shape advances its own cursor once per pass, from the pass on which
    it was first served, and the loop continues while any shape it has served
    still has a recording nobody has seen.
    """

    __slots__ = ("pass_no", "_cursors", "_totals", "_served_pairs", "_touched_this_pass")

    def __init__(self) -> None:
        self.pass_no = 0
        self._cursors: Dict[_StubKey, int] = {}
        self._totals: Dict[_StubKey, int] = {}
        self._served_pairs: set = set()
        self._touched_this_pass: set = set()

    def index_for(self, stub_key: _StubKey, total: int) -> int:
        """Which recording this shape serves for the current pass.

        Fixed for the duration of a pass: a shape called twice in one pass
        serves the same recording both times, so a pass is a coherent snapshot
        rather than a moving target within a single run of the code.
        """
        self._totals[stub_key] = total
        cursor = self._cursors.setdefault(stub_key, 0)
        index = min(cursor, total - 1)
        self._touched_this_pass.add(stub_key)
        self._served_pairs.add((stub_key, index))
        return index

    def advance(self) -> bool:
        """End the pass; return whether another is needed."""
        for key in self._touched_this_pass:
            if self._cursors[key] < self._totals[key] - 1:
                self._cursors[key] += 1
        self._touched_this_pass = set()
        self.pass_no += 1
        # Another pass is worth running only if some shape already served has a
        # recording at its new cursor that has not been served yet. A shape
        # sitting at its last recording is done and re-serving it changes
        # nothing.
        return any(
            (key, self._cursors[key]) not in self._served_pairs
            for key in self._cursors
        )


# ---------------------------------------------------------------------------
# ReplayContext
# ---------------------------------------------------------------------------

class ReplayContext:
    """Context manager / explicit start-stop for replay mode.

    Do not instantiate directly - use :func:`replay` instead.

    Patches ``requests.sessions.Session.send`` so that every outbound
    ``requests`` call is intercepted and matched against the bundle.
    Patching at ``Session.send`` level ensures the ``PreparedRequest``
    already carries the final URL with ``params=`` merged in, matching the
    fingerprint that the capture path recorded.

    Parameters
    ----------
    bundle:
        Pre-parsed bundle dict.
    on_miss:
        Currently only ``"strict"`` is accepted.
    bundle_path:
        Filesystem path from which the bundle was loaded, or ``None`` when
        the bundle was supplied as an in-memory dict.  Exposed as
        :attr:`bundle_path` for diagnostics.
    """

    def __init__(
        self,
        bundle: _BundleDict,
        *,
        on_miss: str = "strict",
        bundle_path: Optional[pathlib.Path] = None,
        select: Optional[Callable[[List[Dict[str, Any]]], Optional[Dict[str, Any]]]] = None,
        statuses: Optional["AbstractSet[int]"] = None,
        _pass_state: Optional["_PassState"] = None,
    ) -> None:
        self._bundle = bundle
        self._on_miss = on_miss
        self.bundle_path: Optional[pathlib.Path] = bundle_path
        self._index, self._curated, self._vp, self._stubs_by_ep = _build_index(bundle)
        self._original_send: Optional[Any] = None
        self._active = False
        self._select = select
        self._statuses = frozenset(statuses) if statuses is not None else None
        self._pass_state = _pass_state
        self._served: List[ServedResponse] = []

    # ------------------------------------------------------------------
    # What this context served
    # ------------------------------------------------------------------

    @property
    def pass_number(self) -> int:
        """1-based pass number under :func:`replay_all`, else 1."""
        return (self._pass_state.pass_no + 1) if self._pass_state is not None else 1

    def served(self) -> List[ServedResponse]:
        """Every response served through this context, in call order.

        Repeated calls to the same endpoint appear once per call. Use it to
        assert coverage instead of trusting that the code under test reached
        what you expected::

            with stubsmith.replay() as r:
                connector.sync()
            assert {s.status for s in r.served()} == {200}
        """
        return list(self._served)

    def _choose_response(
        self,
        stub_key: _StubKey,
        responses: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Pick which recorded response to serve for this call."""
        if not responses:
            return None
        if self._select is not None:
            chosen = self._select(responses)
            if chosen is None:
                return None
            index = responses.index(chosen) if chosen in responses else 0
        elif self._pass_state is not None:
            index = self._pass_state.index_for(stub_key, len(responses))
            chosen = responses[index]
        else:
            index = 0
            chosen = responses[0]

        domain, method, path_template, fingerprint = stub_key
        self._served.append(ServedResponse(
            domain=domain,
            method=method,
            path_template=path_template,
            fingerprint=fingerprint,
            status=chosen.get("status", 200),
            capture_id=chosen.get("capture_id"),
            captured_at=chosen.get("captured_at"),
            index=index,
            total=len(responses),
        ))
        return chosen

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> "ReplayContext":
        """Activate the replay hook.  Idempotent.

        Multiple active contexts must be stopped in reverse order (LIFO)
        - stopping A while B started later is still active would restore the
        wrong ``Session.send``.  ``with`` blocks enforce this automatically.

        Returns
        -------
        ReplayContext
            *self* - for the ``setUp`` idiom::

                self._replay = stubsmith.replay().start()
        """
        if self._active:
            return self
        try:
            import requests.sessions as _rs
        except ImportError as exc:
            raise ImportError(
                "stubsmith.replay() requires the 'requests' library. "
                "Install it with:  pip install requests"
            ) from exc

        self._original_send = _rs.Session.send
        _context = self

        def _send_stub(session: Any, request: Any, **kwargs: Any) -> Any:
            # replay wins: intercept at transport level, never touch the wire.
            return _context._handle(request)

        _rs.Session.send = _send_stub  # type: ignore[method-assign]
        enter_replay()
        self._active = True
        return self

    def stop(self) -> None:
        """Deactivate the replay hook and restore the original ``Session.send``."""
        if not self._active:
            return
        try:
            import requests.sessions as _rs
        except ImportError:
            return
        if self._original_send is not None:
            _rs.Session.send = self._original_send  # type: ignore[method-assign]
        self._original_send = None
        exit_replay()
        self._active = False

    def __enter__(self) -> "ReplayContext":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        # Always restore even when the body of the with block raises.
        self.stop()

    # ------------------------------------------------------------------
    # Request matching
    # ------------------------------------------------------------------

    def _handle(self, request: Any) -> Any:
        """Match *request* against the bundle and return the stub response.

        Parameters
        ----------
        request:
            A ``requests.PreparedRequest`` with the final prepared URL
            (including any ``params=`` merged in by
            ``PreparedRequest.prepare()``).

        Returns
        -------
        requests.Response

        Raises
        ------
        StubNotFound
            When no stub matches in strict mode.  Never falls through to
            the network - that is the absolute guarantee of this method.
        """
        # ── Parse the prepared URL ────────────────────────────────────────
        url = request.url or ""
        parsed = urlparse(url)
        domain = parsed.netloc        # e.g. "api.example.com:8080"
        path = parsed.path or "/"
        query_string = parsed.query or ""
        method = (request.method or "GET").upper()

        # ── Template the path ─────────────────────────────────────────────
        curated = self._curated.get((method, domain), [])
        path_tmpl = template_path(path, curated)

        # ── Extract body and content-type ─────────────────────────────────
        raw_body = request.body
        if isinstance(raw_body, bytes):
            try:
                body_str: str = raw_body.decode("utf-8")
            except UnicodeDecodeError:
                body_str = ""
        elif isinstance(raw_body, str):
            body_str = raw_body
        else:
            body_str = ""

        headers_lower = {
            k.lower(): v for k, v in (request.headers or {}).items()
        }
        content_type = headers_lower.get("content-type", "")

        # ── Look up fingerprint_value_paths for this endpoint ─────────────
        ep_key: _EndpointKey = (domain, method, path_tmpl)
        value_paths: List[str] = self._vp.get(ep_key) or []

        # ── Compute fingerprint ───────────────────────────────────────────
        # Reuses the same fingerprint() function as the capture path
        # (stubsmith/privacy/fingerprint.py) so structural identity is
        # guaranteed to match.  value_paths is passed as None when empty so
        # the four-section form is only triggered when the endpoint actually
        # has discriminating paths configured.
        fp = _fingerprint(
            body_str,
            query_string,
            content_type,
            value_paths=value_paths or None,
        )

        # ── Look up the stub ──────────────────────────────────────────────
        # Key on the composite (domain, method, path_template, fingerprint).
        # Keying on fingerprint alone would cause collisions: every body-less
        # GET shares the same structural hash regardless of host or path.
        # In one production catalog run, six endpoints all carried the hash
        # fc552c95a0bb0d3e - three /avatars/*.png, GET /api/products,
        # GET /api/users/{id}, and GET /api/orders/{id}.
        stub_key: _StubKey = (domain, method, path_tmpl, fp)
        entry = self._index.get(stub_key)

        if entry is None:
            ep_candidates = self._stubs_by_ep.get(ep_key) or []
            all_ep_keys = list(self._stubs_by_ep.keys())
            msg = _build_miss_message(
                method=method,
                path_tmpl=path_tmpl,
                fp=fp,
                domain=domain,
                sent_body=body_str,
                sent_content_type=content_type,
                sent_query_string=query_string,
                value_paths=value_paths,
                ep_candidates=ep_candidates,
                all_ep_keys=all_ep_keys,
            )
            if self.bundle_path is not None:
                msg = f"{msg}\n[bundle loaded from: {self.bundle_path}]"
            raise StubNotFound(method, path_tmpl, fp, msg)

        responses = _flatten_responses(entry["variants"])
        if self._statuses is not None:
            kept = [r for r in responses if r.get("status") in self._statuses]
            if not kept:
                # The shape matched and has recordings, just not of the wanted
                # status. Raise rather than substitute, for the same reason
                # by_status() does: a loop told to exercise 200s must not
                # silently assert against a 500.
                msg = _status_filter_message(
                    method, path_tmpl, fp, self._statuses,
                    [r.get("status") for r in responses],
                )
                if self.bundle_path is not None:
                    msg = f"{msg}\n[bundle loaded from: {self.bundle_path}]"
                raise StubNotFound(method, path_tmpl, fp, msg)
            responses = kept

        variant = self._choose_response(stub_key, responses)
        if variant is None:
            # Fingerprint matched but stub has no variants (degraded stub).
            degraded_msg = (
                f"no recorded stub for {method} {path_tmpl}  "
                f"(fingerprint {fp})\n\n"
                f"{_REFRESH_HINT}"
            )
            if self.bundle_path is not None:
                degraded_msg = f"{degraded_msg}\n[bundle loaded from: {self.bundle_path}]"
            raise StubNotFound(method, path_tmpl, fp, degraded_msg)

        return _build_response(request, variant)


# ---------------------------------------------------------------------------
# Public factory
# ---------------------------------------------------------------------------

def by_status(status: int) -> Callable[[List[Dict[str, Any]]], Optional[Dict[str, Any]]]:
    """A *select* function that serves the newest recording of *status*.

    ::

        with stubsmith.replay(select=stubsmith.by_status(429)):
            with pytest.raises(RateLimited):
                connector.sync()

    Returns ``None`` when no recording of that status exists, which surfaces as
    the usual :exc:`StubNotFound` rather than quietly serving a different
    status: a rate-limit test that silently ran against a 200 would pass while
    testing nothing.
    """
    def _select(responses: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        for response in responses:
            if response.get("status") == status:
                return response
        return None
    return _select


def replay_all(
    bundle: Optional[Union[str, pathlib.Path, _BundleDict]] = None,
    *,
    on_miss: str = "strict",
    statuses: Optional["AbstractSet[int]"] = None,
    max_passes: int = 64,
) -> "Iterator[ReplayContext]":
    """Yield one replay context per recorded response, to loop the whole window.

    Plain :func:`replay` serves a single response per request shape: the newest
    recording of the most frequent status. That leaves every other recording
    unexercised, including the rare 500 or 429 your API really returned. This
    runs the block repeatedly, advancing one recorded response each pass::

        for attempt in stubsmith.replay_all():
            with attempt:
                result = connector.sync_orders()
            assert result.ok or result.retried

    Pass one serves exactly what :func:`replay` serves, so a test that passes
    under ``replay()`` still passes on the first pass. Pass two serves the next
    recording for every shape, and so on.

    The endpoints are never named: which ones a pass touches is discovered by
    running the code, so this works for a connector whose call sequence you do
    not want to spell out, and for one whose sequence *changes* between passes
    because it branches on the response it got.

    Iteration stops when every shape that has actually been touched has served
    its last recording. A shape with fewer recordings than the current pass
    keeps serving its final one rather than raising, so a short window never
    truncates the loop for everything else - check
    :attr:`ServedResponse.exhausted` on :meth:`ReplayContext.served` if a test
    needs to know which shapes were clamped.

    Note what this asks of the test body: it runs against a 200 on one pass and
    possibly a 500 on the next, so the assertions have to hold for the whole
    recorded range. That is the point - it is how you find out the code breaks
    on a response your API already returns - but it is a different style of
    test from one written for a single known response, and :func:`replay` stays
    the right tool for that.

    Because the body runs against a different recording each pass, write it to
    hold for the whole range you are looping.  Asserting the happy path inside
    an unfiltered loop is the common mistake: the day a 500 enters the window,
    the build breaks on a new recording rather than on a code change, which
    inverts what a red test is supposed to tell you.  Either filter with
    *statuses* or assert on the contract both outcomes share::

        for attempt in stubsmith.replay_all(statuses={500, 502}):
            with attempt:
                with pytest.raises(UpstreamUnavailable):
                    connector.sync_orders()

    Parameters
    ----------
    bundle:
        As :func:`replay`. To loop more than one recording per status the
        bundle must have been fetched with samples, either
        ``stubsmith pull --samples all`` or
        :func:`~stubsmith.fetch_bundle` with ``samples="all"``; a default
        bundle carries one recording per status and yields one pass per status.
    on_miss:
        As :func:`replay`.
    statuses:
        Loop only recordings whose response status is in this set, e.g.
        ``statuses={200}`` or ``statuses={429, 500}``.  ``None`` (default)
        loops every recording.

        This is usually what you want, because it decides what a red build
        means.  Unfiltered, the loop mixes successes and failures into one test
        body, so the body has to hold for both, and a status that enters the
        window later breaks assertions written when only the other kind
        existed.  Filtered, every pass is the same kind of response, the
        assertions can be specific, and a failure means the code cannot handle
        a response the API genuinely returns.

        A shape with recordings but none of the requested status raises
        :exc:`StubNotFound` naming the filter and listing what it does have.
        Substituting another status would have the loop assert against a
        response it was told to exclude.

        Note that the "first pass matches :func:`replay`" property does not
        hold under a filter, since ``replay()``'s choice may not be in the set.
    max_passes:
        Hard ceiling on iterations, as a backstop. Reaching it stops the loop.

        Worth knowing when unfiltered: the pass count is the largest recorded
        window among the shapes touched, which is roughly
        (samples per response) x (distinct statuses), so it grows with traffic
        without any code change.  A *statuses* filter bounds it to one status's
        window.

    Yields
    ------
    ReplayContext
        Not yet started - use it as a context manager, one ``with`` per pass.
    """
    if on_miss != "strict":
        raise ValueError(
            f"on_miss={on_miss!r} is not supported. "
            "Currently only 'strict' is accepted; other modes come in a later release."
        )
    if max_passes < 1:
        raise ValueError(f"max_passes must be at least 1, got {max_passes!r}")

    # Resolve once: re-reading per pass would re-hit the filesystem and, worse,
    # could pick up a different bundle mid-loop.
    data, bundle_path = _resolve_bundle(bundle)
    state = _PassState()

    while True:
        yield ReplayContext(
            data,
            on_miss=on_miss,
            bundle_path=bundle_path,
            statuses=statuses,
            _pass_state=state,
        )
        more = state.advance()
        if not more or state.pass_no >= max_passes:
            return


def replay(
    bundle: Optional[Union[str, pathlib.Path, _BundleDict]] = None,
    *,
    on_miss: str = "strict",
    select: Optional[Callable[[List[Dict[str, Any]]], Optional[Dict[str, Any]]]] = None,
) -> ReplayContext:
    """Create a replay context that intercepts outbound ``requests`` calls.

    Usage::

        with stubsmith.replay():
            result = my_app.checkout(cart)   # real client code, recorded responses
        assert result.order_id

    Parameters
    ----------
    bundle:
        Where to load the bundle from.  Accepted types:

        - ``None`` (default) - resolves via environment then default path:
          ``$STUBSMITH_BUNDLE`` → ``.stubsmith/bundle.json``.
        - A filesystem path (``str`` or :class:`pathlib.Path`).
        - A pre-parsed ``dict`` (useful in tests).
    on_miss:
        What to do when a request matches no stub.  Only ``"strict"`` is
        accepted in this version; other values raise :exc:`ValueError`
        immediately.  In strict mode every miss raises
        :exc:`StubNotFound`.
    select:
        Chooses which recorded response to serve. Receives the shape's
        recordings as a list, newest-first within each status and ordered so
        the default choice is first, and returns one of them or ``None`` to
        force a :exc:`StubNotFound`.  Default picks the first, which is the
        newest recording of the most frequent status.
        :func:`by_status` covers the common case; to loop every recording use
        :func:`replay_all`.

    Returns
    -------
    ReplayContext
        A context manager.  Also exposes :meth:`ReplayContext.start` and
        :meth:`ReplayContext.stop` for ``setUp``/``tearDown`` patterns.

    Raises
    ------
    ValueError
        When *on_miss* is not ``"strict"``.
    FileNotFoundError
        When the bundle cannot be located.
    ValueError
        When the bundle file is not valid JSON.
    """
    if on_miss != "strict":
        raise ValueError(
            f"on_miss={on_miss!r} is not supported. "
            "Currently only 'strict' is accepted; other modes come in a later release."
        )
    data, bundle_path = _resolve_bundle(bundle)
    return ReplayContext(data, on_miss=on_miss, bundle_path=bundle_path, select=select)
