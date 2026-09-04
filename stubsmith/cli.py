"""
stubsmith pull - fetch the replay bundle from the StubSmith backend and write
it to disk so tests can run offline with no API key.

Usage::

    stubsmith pull [--out PATH] [--endpoint "METHOD /path/template"]

Environment variables
---------------------
STUBSMITH_API_KEY
    Required.  Bearer token for the project.
STUBSMITH_API_URL
    Base URL of the StubSmith backend.  Falls back to ``STUBSMITH_BACKEND_URL``,
    then ``https://app.stubsmith.dev/api``.

Determinism
-----------
The written file is sorted deterministically so repeated pulls produce no
spurious diff when nothing has changed on the server.  Endpoints are ordered
by ``(domain, method, path_template)``, stubs by ``fingerprint``, and variants
by ``status``.  ``json.dumps`` is called with ``sort_keys=True`` so every dict
is key-sorted regardless of insertion order.

Collision note
--------------
Do NOT collapse the bundle to a fingerprint-hash-only index.  A fingerprint
hashes body key-paths, query-parameter names, and content-type - it does not
include the host or path.  Every body-less GET therefore shares the same hash.
In one catalog run six endpoints (three ``/avatars/*.png``, ``GET /api/products``,
``GET /api/users/{id}``, ``GET /api/orders/{id}``) all carried the hash
``fc552c95a0bb0d3e``.  The file preserves endpoint → stub nesting exactly so
that ``replay()`` can key lookups on the full composite
``(domain, method, path_template, fingerprint)`` rather than on fingerprint alone.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple, Union

from ._version import __version__

_DEFAULT_OUT      = ".stubsmith/bundle.json"
_DEFAULT_API_URL  = "https://app.stubsmith.dev/api"
_SDK_USER_AGENT   = f"stubsmith-cli/{__version__}"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _resolve_api_url() -> str:
    """Return the backend base URL from the environment.

    Priority: ``STUBSMITH_API_URL`` > ``STUBSMITH_BACKEND_URL`` >
    ``https://app.stubsmith.dev/api``.
    """
    return (
        os.environ.get("STUBSMITH_API_URL")
        or os.environ.get("STUBSMITH_BACKEND_URL")
        or _DEFAULT_API_URL
    )


def _fetch_bundle(
    api_url: str,
    api_key: str,
    method: Optional[str] = None,
    path: Optional[str] = None,
    samples: Optional[Union[int, str]] = None,
) -> Dict[str, Any]:
    """Fetch ``GET /v1/replay/bundle`` and return the parsed JSON body.

    Parameters
    ----------
    api_url:
        Backend base URL (no trailing slash).
    api_key:
        Bearer token for the project.
    method:
        Optional HTTP method filter (e.g. ``"GET"``).
    path:
        Optional path-template filter (e.g. ``"/api/users/{id}"``).
        Required when *method* is supplied.
    samples:
        How many recordings to fetch per response.  ``None`` (default) asks
        the server for one, the newest, which is all replay needs to serve a
        response.  A positive integer or ``"all"`` fetches the rolling sample
        window so every recording can be looped over.  Above one the server
        requires an endpoint filter and rejects an unscoped request, since the
        full window for a whole project is neither small nor useful.

    Returns
    -------
    dict
        Parsed response body.

    Raises
    ------
    RuntimeError
        On any HTTP error or network failure.
    ValueError
        When the response body cannot be parsed as JSON.
    """
    params: Dict[str, str] = {}
    if method:
        params["method"] = method
    if path:
        params["path"] = path
    if samples is not None:
        params["samples"] = str(samples)

    qs = ("?" + urllib.parse.urlencode(params)) if params else ""
    url = api_url.rstrip("/") + "/v1/replay/bundle" + qs

    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {api_key}",
            "User-Agent": _SDK_USER_AGENT,
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        if exc.code == 404:
            raise RuntimeError(
                f"HTTP 404 from {url}\n"
                f"The StubSmith backend was not found at that URL.\n"
                f"For the hosted service the URL is https://app.stubsmith.dev/api.\n"
                f"Override with STUBSMITH_API_URL, or unset it to use the default."
            ) from exc
        raise RuntimeError(f"HTTP {exc.code}: {body}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(
            f"Network error reaching {url}: {exc.reason}\n"
            f"Check that the backend is reachable, or set STUBSMITH_API_URL "
            f"to override (default: https://app.stubsmith.dev/api)."
        ) from exc

    try:
        return json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Server returned unparseable JSON: {exc}") from exc


def _sort_bundle(data: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of *data* with endpoints/stubs/variants sorted.

    Sorting is deterministic so that two pulls with the same server state
    produce byte-for-byte identical files.

    - Endpoints: by ``(domain, method, path_template)``
    - Stubs: by ``fingerprint``
    - Variants: by ``status``

    Body strings are passed through as received; they are not re-encoded.
    """
    endpoints: List[Dict[str, Any]] = data.get("endpoints") or []

    sorted_endpoints = []
    for ep in sorted(
        endpoints,
        key=lambda e: (e.get("domain") or "", e.get("method") or "", e.get("path_template") or ""),
    ):
        stubs: List[Dict[str, Any]] = ep.get("stubs") or []
        sorted_stubs = []
        for stub in sorted(stubs, key=lambda s: s.get("fingerprint") or ""):
            variants: List[Dict[str, Any]] = stub.get("variants") or []
            sorted_variants = sorted(variants, key=lambda v: v.get("status") or 0)
            sorted_stubs.append({**stub, "variants": sorted_variants})
        sorted_endpoints.append({**ep, "stubs": sorted_stubs})

    return {**data, "endpoints": sorted_endpoints}


def _count_stubs(endpoints: List[Dict[str, Any]]) -> int:
    return sum(len(ep.get("stubs") or []) for ep in endpoints)


def _count_variants(endpoints: List[Dict[str, Any]]) -> int:
    return sum(
        len(stub.get("variants") or [])
        for ep in endpoints
        for stub in (ep.get("stubs") or [])
    )


def _count_degraded(endpoints: List[Dict[str, Any]]) -> int:
    return sum(
        1
        for ep in endpoints
        for stub in (ep.get("stubs") or [])
        if stub.get("degraded")
    )


def _count_body_capped(endpoints: List[Dict[str, Any]]) -> int:
    return sum(
        1
        for ep in endpoints
        for stub in (ep.get("stubs") or [])
        for variant in (stub.get("variants") or [])
        if variant.get("body_capped")
    )


def _write_bundle(out_path: str, data: Dict[str, Any]) -> None:
    """Write *data* to *out_path* atomically.

    The file is written to a temporary path in the same directory first, then
    renamed into place.  This means a concurrent reader never sees a partial
    file, and a failed write leaves the previous bundle intact.

    Parameters
    ----------
    out_path:
        Destination file path.  Parent directories are created if absent.
    data:
        Bundle data to serialise.
    """
    dest = pathlib.Path(out_path)
    dest.parent.mkdir(parents=True, exist_ok=True)

    # json.dumps with sort_keys=True guarantees key-sorted output regardless
    # of insertion order in any nested dict.
    serialised = json.dumps(data, sort_keys=True, indent=2, ensure_ascii=False) + "\n"

    # Write atomically: temp file in the same directory so the rename is local.
    fd, tmp = tempfile.mkstemp(dir=str(dest.parent), prefix=".stubsmith-bundle-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(serialised)
        # mkstemp creates 0600; restore conventional 0644 before renaming so
        # that each pull does not silently reset permissions on a committed file.
        os.chmod(tmp, 0o644)
        os.replace(tmp, str(dest))
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _print_summary(data: Dict[str, Any], out_path: str) -> None:
    """Print a human-readable summary of the bundle to stdout."""
    endpoints = data.get("endpoints") or []
    n_ep       = len(endpoints)
    n_stubs    = _count_stubs(endpoints)
    n_variants = _count_variants(endpoints)
    cursor     = data.get("cursor", "")
    gen_at     = data.get("generated_at", "")

    print(f"Wrote {out_path}")
    print(f"  endpoints : {n_ep}")
    print(f"  stubs     : {n_stubs}")
    print(f"  variants  : {n_variants}")
    print(f"  cursor    : {cursor}")
    print(f"  generated : {gen_at}")

    # Surface caps and degraded stubs prominently - a bundle that looks complete
    # but contains unusable stubs is the worst outcome.
    truncated = data.get("truncated")
    if truncated:
        print()
        print("WARNING: bundle is truncated - not all data was included.")
        stubs_trunc = truncated.get("stubs")
        if stubs_trunc:
            print(
                f"  stubs: {stubs_trunc.get('dropped')} stubs dropped "
                f"(server limit: {stubs_trunc.get('limit')})"
            )
        variants_trunc = truncated.get("variants")
        if variants_trunc:
            total_dropped = sum(v.get("dropped", 0) for v in variants_trunc)
            print(
                f"  variants: {total_dropped} variant(s) dropped across "
                f"{len(variants_trunc)} fingerprint(s) "
                f"(server limit per fingerprint: {variants_trunc[0].get('limit')})"
            )
        body_bytes_trunc = truncated.get("body_bytes")
        if body_bytes_trunc:
            limit_kb = body_bytes_trunc.get("limit", 0) // 1024
            print(
                f"  body_bytes: {body_bytes_trunc.get('capped')} variant body/bodies "
                f"omitted (exceeded {limit_kb} KB cap) - these stubs will replay with "
                f"an empty body"
            )

    n_degraded   = _count_degraded(endpoints)
    n_body_capped = _count_body_capped(endpoints)

    if n_degraded:
        print(
            f"WARNING: {n_degraded} stub(s) marked degraded - "
            "no recorded captures are available; replay will fail for those stubs."
        )
    if n_body_capped:
        print(
            f"WARNING: {n_body_capped} variant(s) have body_capped=true - "
            "body exceeded the server size cap and was omitted; "
            "replay will return an empty body for those variants."
        )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def _cmd_pull(args: argparse.Namespace) -> int:
    """Implement the ``pull`` subcommand.

    Parameters
    ----------
    args:
        Parsed namespace from the ``pull`` subparser.

    Returns
    -------
    int
        Exit code: 0 on success, non-zero on any failure.
    """
    # ── Resolve credentials ───────────────────────────────────────────────
    api_key = os.environ.get("STUBSMITH_API_KEY", "")
    if not api_key:
        print(
            "Error: STUBSMITH_API_KEY is not set. "
            "Export your project API key before running stubsmith pull.",
            file=sys.stderr,
        )
        return 1

    api_url = _resolve_api_url()

    # ── Parse --endpoint filter ───────────────────────────────────────────
    endpoints: List[Tuple[Optional[str], Optional[str]]] = []
    for raw_ep in (args.endpoint or []):
        parts = raw_ep.split(" ", 1)
        if len(parts) != 2 or not parts[0].strip() or not parts[1].strip():
            print(
                f"Error: --endpoint must be \"METHOD /path\" (e.g. \"GET /api/users\"), "
                f"got: {raw_ep!r}",
                file=sys.stderr,
            )
            return 1
        endpoints.append((parts[0].strip().upper(), parts[1].strip()))
    if not endpoints:
        endpoints = [(None, None)]   # whole project

    # ── Validate --samples ────────────────────────────────────────────────
    samples: Optional[str] = None
    if args.samples is not None:
        raw = args.samples.strip().lower()
        if raw != "all" and not raw.isdigit():
            print(
                f"Error: --samples must be a positive integer or 'all', got: {args.samples!r}",
                file=sys.stderr,
            )
            return 1
        if raw.isdigit() and int(raw) < 1:
            print("Error: --samples must be at least 1.", file=sys.stderr)
            return 1
        # Checked here rather than only server-side so the failure names the
        # flag the user typed instead of surfacing as an HTTP 400.
        if (raw == "all" or int(raw) > 1) and not args.endpoint:
            print(
                "Error: --samples greater than 1 requires --endpoint.\n"
                "Fetching every recording for a whole project is not supported; "
                'scope it, e.g. --endpoint "GET /api/orders". Repeat --endpoint '
                "to cover several in one bundle.",
                file=sys.stderr,
            )
            return 1
        samples = raw

    # ── Fetch ─────────────────────────────────────────────────────────────
    fetched: List[Dict[str, Any]] = []
    try:
        for ep_method, ep_path in endpoints:
            if ep_method:
                print(f"Fetching {ep_method} {ep_path} ...", file=sys.stderr)
            fetched.append(
                _fetch_bundle(api_url, api_key, method=ep_method, path=ep_path, samples=samples)
            )
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    raw_data = _merge_bundles(fetched)

    # ── Sort for determinism, then write ─────────────────────────────────
    try:
        data = _sort_bundle(raw_data)
        _write_bundle(args.out, data)
    except Exception as exc:
        print(f"Error writing bundle: {exc}", file=sys.stderr)
        return 1

    # ── Summary ───────────────────────────────────────────────────────────
    _print_summary(data, args.out)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point for the ``stubsmith`` command.

    Parameters
    ----------
    argv:
        Argument list (excluding the program name), e.g. ``["pull"]`` or
        ``["pull", "--out", "my/bundle.json"]``.  Defaults to
        ``sys.argv[1:]`` when ``None``.

    Returns
    -------
    int
        Exit code: 0 on success, non-zero on any failure.
    """
    parser = argparse.ArgumentParser(
        prog="stubsmith",
        description="StubSmith command-line tools.",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")
    # required=True makes argparse emit "the following arguments are required:
    # <command>" and exit 2 when no subcommand is given, which is the correct
    # behaviour for a CLI whose no-argument form should not silently take an action.
    subparsers.required = True

    # ── pull subcommand ───────────────────────────────────────────────────
    pull_parser = subparsers.add_parser(
        "pull",
        help="Fetch the replay bundle and write it to disk.",
        description=(
            "Fetch the StubSmith replay bundle and write it to disk so tests "
            "can run offline without an API key."
        ),
    )
    pull_parser.add_argument(
        "--out",
        default=_DEFAULT_OUT,
        metavar="PATH",
        help=f"Destination file (default: {_DEFAULT_OUT})",
    )
    pull_parser.add_argument(
        "--endpoint",
        action="append",
        default=None,
        metavar="\"METHOD /path/template\"",
        help=(
            'Filter to an endpoint, e.g. "GET /api/users/{id}". '
            "Repeat to pull several into one bundle, which is how to get a "
            "sample window for more than one endpoint, since --samples above 1 "
            "is not served project-wide. Each endpoint is one request; the "
            "responses are merged."
        ),
    )
    pull_parser.add_argument(
        "--samples",
        default=None,
        metavar="N|all",
        help=(
            "How many recordings to keep per response (default: 1, the newest). "
            "Use N or 'all' to pull the rolling sample window so "
            "stubsmith.replay_all() can loop every recording. "
            "Requires --endpoint: the full window for a whole project is not "
            "served."
        ),
    )

    args = parser.parse_args(argv)

    if args.command == "pull":
        return _cmd_pull(args)

    # Unreachable when subparsers.required=True, but kept for forward safety.
    parser.print_help(sys.stderr)
    return 2


def _cli_entry() -> None:
    """Console script shim: calls ``main()`` and exits with its return code."""
    sys.exit(main())


def _merge_bundles(parts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Merge per-endpoint bundles into one, as if the server had returned it.

    Needed because ``--samples`` above 1 requires an endpoint filter, so a
    sample window covering several endpoints can only be assembled from one
    response per endpoint. Doing it here keeps that off the user, who would
    otherwise be hand-merging JSON.

    Endpoints are keyed on ``(domain, method, path_template)``; a repeated key
    has its stubs concatenated, with duplicate fingerprints dropped so an
    overlapping filter cannot produce two stubs with the same identity. The
    cursor is the maximum across parts, matching the server's own rule, and any
    ``truncated`` report is carried through so a partial pull still says so.
    """
    if not parts:
        return {"ok": True, "version": 1, "cursor": "0", "endpoints": []}
    if len(parts) == 1:
        return parts[0]

    merged: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    seen_fps: Dict[Tuple[str, str, str], set] = {}
    truncated: Dict[str, Any] = {}
    cursor = 0

    for part in parts:
        try:
            cursor = max(cursor, int(part.get("cursor") or 0))
        except (TypeError, ValueError):
            pass
        for key, value in (part.get("truncated") or {}).items():
            truncated.setdefault(key, value)
        for ep in part.get("endpoints") or []:
            key = (ep.get("domain") or "", (ep.get("method") or "").upper(),
                   ep.get("path_template") or "")
            if key not in merged:
                merged[key] = dict(ep, stubs=[])
                seen_fps[key] = set()
            for stub in ep.get("stubs") or []:
                fp = stub.get("fingerprint") or ""
                if fp in seen_fps[key]:
                    continue
                seen_fps[key].add(fp)
                merged[key]["stubs"].append(stub)

    out: Dict[str, Any] = {
        "ok": True,
        "version": parts[0].get("version", 1),
        "cursor": str(cursor),
        "generated_at": parts[-1].get("generated_at"),
        "endpoints": list(merged.values()),
    }
    if truncated:
        out["truncated"] = truncated
    return out


def fetch_bundle(
    endpoint: Optional[str] = None,
    *,
    samples: Optional[Union[int, str]] = None,
    api_url: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetch a replay bundle from the API and return it, without touching disk.

    The supported way to get a bundle at test-collection time, for a suite that
    should exercise current recordings rather than a committed snapshot::

        import stubsmith

        BUNDLE = stubsmith.fetch_bundle("GET /admin/orders", samples="all")

        def test_every_recorded_response():
            for attempt in stubsmith.replay_all(BUNDLE):
                with attempt:
                    connector.list_orders()

    Fetch once at module level, not per test: this is a blocking HTTP call.

    A live API key is needed wherever the tests run, which is the trade against
    ``stubsmith pull`` plus a committed bundle. Live recordings also roll as the
    sample window rolls, so a failure seen today may not reproduce next week.
    Prefer this for local iteration and a committed bundle for CI.

    Parameters
    ----------
    endpoint:
        ``"METHOD /path"``, e.g. ``"GET /admin/orders"``. The path may be the
        concrete one your code calls; the server resolves it against your
        recorded path patterns. ``None`` fetches the whole project, which is
        subject to the server's stub cap - check ``truncated`` in the result.
    samples:
        Recordings to fetch per response. ``None`` (default) is one, the
        newest. A positive integer or ``"all"`` fetches the rolling window so
        :func:`~stubsmith.replay_all` has something to loop. Above one an
        *endpoint* is required.
    api_url:
        Backend base URL. Defaults to ``$STUBSMITH_API_URL``, then
        ``$STUBSMITH_BACKEND_URL``, then the hosted service.
    api_key:
        Project key. Defaults to ``$STUBSMITH_API_KEY``.

    Returns
    -------
    dict
        The parsed bundle, ready to hand to :func:`~stubsmith.replay` or
        :func:`~stubsmith.replay_all`.

    Raises
    ------
    ValueError
        When *endpoint* is malformed, *samples* is not a positive integer or
        ``"all"``, or ``samples > 1`` without an *endpoint*.
    RuntimeError
        When no API key is available, or on any HTTP or network failure.
    """
    key = api_key or os.environ.get("STUBSMITH_API_KEY", "")
    if not key:
        raise RuntimeError(
            "No API key: pass api_key= or set $STUBSMITH_API_KEY."
        )

    ep_method: Optional[str] = None
    ep_path: Optional[str] = None
    if endpoint is not None:
        parts = endpoint.split(" ", 1)
        if len(parts) != 2 or not parts[0].strip() or not parts[1].strip():
            raise ValueError(
                f'endpoint must be "METHOD /path" (e.g. "GET /api/orders"), got: {endpoint!r}'
            )
        ep_method = parts[0].strip().upper()
        ep_path = parts[1].strip()

    normalised: Optional[str] = None
    if samples is not None:
        raw = str(samples).strip().lower()
        if raw != "all" and not raw.isdigit():
            raise ValueError(
                f"samples must be a positive integer or 'all', got: {samples!r}"
            )
        if raw.isdigit() and int(raw) < 1:
            raise ValueError(f"samples must be at least 1, got: {samples!r}")
        # Raised locally rather than waiting for the server's 400 so the
        # message names the argument the caller passed.
        if (raw == "all" or int(raw) > 1) and endpoint is None:
            raise ValueError(
                "samples greater than 1 requires an endpoint. Fetching every "
                'recording for a whole project is not supported; scope it, e.g. '
                'fetch_bundle("GET /api/orders", samples="all").'
            )
        normalised = raw

    return _fetch_bundle(
        api_url or _resolve_api_url(),
        key,
        method=ep_method,
        path=ep_path,
        samples=normalised,
    )
