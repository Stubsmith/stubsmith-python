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
from typing import Any, Dict, List, Optional

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
    ep_method: Optional[str] = None
    ep_path:   Optional[str] = None
    if args.endpoint:
        parts = args.endpoint.split(" ", 1)
        if len(parts) != 2 or not parts[0].strip() or not parts[1].strip():
            print(
                f"Error: --endpoint must be \"METHOD /path\" (e.g. \"GET /api/users\"), "
                f"got: {args.endpoint!r}",
                file=sys.stderr,
            )
            return 1
        ep_method = parts[0].strip().upper()
        ep_path   = parts[1].strip()

    # ── Fetch ─────────────────────────────────────────────────────────────
    try:
        raw_data = _fetch_bundle(api_url, api_key, method=ep_method, path=ep_path)
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

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
        default=None,
        metavar="\"METHOD /path/template\"",
        help=(
            'Filter to a single endpoint, e.g. "GET /api/users/{id}". '
            "Passes method= and path= query parameters to the server."
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
