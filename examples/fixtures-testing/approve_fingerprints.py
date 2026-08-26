#!/usr/bin/env python3
"""Approve this example's pending fingerprints with the documented keep rules.

The Review screen is the normal way to approve a fingerprint, but clicking
through nine fingerprints and thirty rules is tedious and - more importantly -
not reproducible.  A CI job that starts from an empty project cannot click.
This script applies exactly the rule set documented in README.md "Step 3" via
``POST /v1/review/<id>/decision``, so the example is a single command end to
end.

Run order matters, for two reasons.  Ingest writes no capture row for a pending
fingerprint (only approved fingerprints may produce captures), so a fingerprint
approved after its traffic ran has nothing recorded and comes back from
``stubsmith pull`` marked ``degraded``.  And masking happens at the SDK edge:
values are replaced before upload, so the server never holds the originals and a
keep rule cannot recover a value from a capture already stored under a stricter
rule set.  Both mean the traffic script must run again after approving:

    python generate_traffic.py      # 1. produce captures (fully masked)
    python approve_fingerprints.py  # 2. approve with keep rules
    python generate_traffic.py      # 3. recapture, now honouring the rules
    python -m stubsmith pull ...    # 4. build the bundle
    python -m pytest tests/         # 5. replay offline

Requires an org API key with the ``review:read`` and ``review:approve`` scopes.
A project key is not sufficient - those authenticate capture upload only.

Read from ``STUBSMITH_ORG_API_KEY`` in preference to ``STUBSMITH_API_KEY``,
because ``generate_traffic.py`` needs the *project* key in the latter: the two
run in sequence, so sharing one variable would mean swapping its value back and
forth between steps. Export both once and every step finds the key it needs.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

import _sdk_path  # noqa: F401  (sys.path side effect - must precede stubsmith)
import stubsmith

# Read at import time, not inside main(). Reading it lazily meant a stale SDK
# winning the import went unnoticed until the one code path that touches it ran
# - and any test that sets STUBSMITH_API_URL short-circuits past it, so no
# hermetic test could catch the wrong SDK being loaded. Eager is testable.
_SDK_DEFAULT_API_URL = stubsmith.DEFAULT_API_URL

# ---------------------------------------------------------------------------
# The documented rule set
#
# Keyed on the composite (method, path_template, fingerprint) rather than the
# fingerprint alone.  The fingerprint hashes body key-paths, query names and
# content-type, not the host or path, so the same hash recurs across
# endpoints with the same request shape.  fc552c95a0bb0d3e below is exactly
# that case: two body-less GETs, different endpoints, different rules.
#
# Keep this table identical to README.md "Step 3"; the committed bundle and the
# test assertions depend on this precise rule set.
# ---------------------------------------------------------------------------

_RuleKey = Tuple[str, str, str]

KEEP_RULES: Dict[_RuleKey, List[str]] = {
    ("GET", "/api/users/{id}", "fc552c95a0bb0d3e"): [
        "resp.id",
        "resp.plan",
        "resp.active",
    ],
    ("POST", "/api/users", "90dc0baeeee2ad16"): [
        "resp.id",
        "resp.created",
    ],
    ("POST", "/api/auth/login", "88a4c74a696c6e89"): [
        "resp.expires_in",
        "resp.user_id",
    ],
    ("POST", "/api/orders", "67193bd52728bfbb"): [
        "resp.order_id",
        "resp.status",
        "resp.total_cents",
        "resp.items.[].sku",
        "resp.items.[].qty",
        "resp.items.[].price_cents",
    ],
    ("GET", "/api/orders/{id}", "fc552c95a0bb0d3e"): [
        "resp.order_id",
        "resp.status",
        "resp.total_cents",
        "resp.items.[].sku",
        "resp.items.[].qty",
        "resp.items.[].price_cents",
    ],
    ("GET", "/api/orders", "15d2fd0d27a9595f"): [
        "resp.total",
        "resp.orders.[].order_id",
        "resp.orders.[].status",
        "query.status",
        "query.limit",
    ],
    ("PUT", "/api/orders/{id}", "e314d5b772be48b5"): [
        "resp.order_id",
        "resp.status",
    ],
    # POST /api/payments/charges carries two fingerprints: the request body with
    # idempotency_key (201) and without it (402).  Same endpoint, different
    # shape, so different hashes and different rules.
    ("POST", "/api/payments/charges", "79148562d5fb5ae8"): [
        "resp.charge_id",
        "resp.status",
        "resp.amount_cents",
        "resp.currency",
        "resp.card.last4",
        "resp.card.brand",
    ],
    ("POST", "/api/payments/charges", "4a17ca4d93dddd7d"): [
        "resp.charge_id",
        "resp.code",
    ],
}


# ---------------------------------------------------------------------------
# Rule assembly
# ---------------------------------------------------------------------------

def build_field_rules(
    keep_paths: List[str],
    fingerprint_value_paths: Optional[List[str]] = None,
) -> List[Dict[str, str]]:
    """Return field_rules for *keep_paths*, plus any required value-path keeps.

    When an endpoint has ``fingerprint_value_paths``, the backend refuses the
    approval unless every one of those bare body paths has an explicit keep
    rule at ``"body." + path`` (privacy-helpers.js ``validateValuePathsKept``).
    Absence counts as masked, so a missing rule is a 400, not a warning.
    """
    paths = list(keep_paths)
    for vp in fingerprint_value_paths or []:
        if not isinstance(vp, str):
            continue
        namespaced = "body." + vp
        if namespaced not in paths:
            paths.append(namespaced)
    return [{"path": p, "action": "keep"} for p in paths]


def rules_for(row: Dict[str, Any]) -> Optional[List[Dict[str, str]]]:
    """Return field_rules for a queue *row*, or None when it is not in the table."""
    key = (
        (row.get("method") or "").upper(),
        row.get("path_template") or "",
        row.get("fingerprint") or "",
    )
    keep_paths = KEEP_RULES.get(key)
    if keep_paths is None:
        return None
    return build_field_rules(keep_paths, row.get("fingerprint_value_paths"))


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

Opener = Callable[[urllib.request.Request], Any]


def _request_json(
    method: str,
    url: str,
    api_key: str,
    payload: Optional[Dict[str, Any]] = None,
    opener: Optional[Opener] = None,
) -> Dict[str, Any]:
    """Issue a JSON request and return the parsed response body.

    *opener* is injectable so the tests can exercise this without a network.
    """
    data = None
    headers = {"authorization": f"Bearer {api_key}", "accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["content-type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with (opener or urllib.request.urlopen)(req) as resp:
        body = resp.read().decode("utf-8")
    return json.loads(body) if body else {}


def fetch_queue(
    api_url: str,
    api_key: str,
    project_id: Optional[str] = None,
    opener: Optional[Opener] = None,
) -> List[Dict[str, Any]]:
    """Return the pending review queue."""
    url = f"{api_url.rstrip('/')}/v1/review/queue"
    if project_id:
        url = f"{url}?{urllib.parse.urlencode({'projectId': project_id})}"
    return _request_json("GET", url, api_key, opener=opener).get("queue") or []


def approve(
    api_url: str,
    api_key: str,
    fingerprint_id: str,
    field_rules: List[Dict[str, str]],
    opener: Optional[Opener] = None,
) -> None:
    """Approve one fingerprint. Raises urllib.error.HTTPError on rejection."""
    url = f"{api_url.rstrip('/')}/v1/review/{fingerprint_id}/decision"
    _request_json(
        "POST",
        url,
        api_key,
        payload={"decision": "approve", "field_rules": field_rules},
        opener=opener,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="approve_fingerprints",
        description=(
            "Approve this example's pending fingerprints with the keep rules "
            "documented in README.md."
        ),
    )
    parser.add_argument(
        "--project-id",
        default=os.environ.get("STUBSMITH_PROJECT_ID"),
        metavar="UUID",
        help=(
            "Project to approve in. Required unless --all-projects is given. "
            "Also read from $STUBSMITH_PROJECT_ID."
        ),
    )
    parser.add_argument(
        "--all-projects",
        action="store_true",
        help=(
            "Approve across every project the key can see. Rarely what you "
            "want: fingerprints are matched on (method, path_template, "
            "fingerprint), which is not project-specific, so another project "
            "with the same request shape gets this example's keep rules."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be approved without approving anything.",
    )
    parser.add_argument(
        "--ignore-unknown",
        action="store_true",
        help=(
            "Approve the documented fingerprints even when the queue contains "
            "others. Without this, an unrecognised fingerprint aborts the run "
            "before anything is approved, on the assumption that it means the "
            "wrong project."
        ),
    )
    args = parser.parse_args(argv)

    key_var = next(
        (
            v
            for v in ("STUBSMITH_ORG_API_KEY", "STUBSMITH_API_KEY")
            if os.environ.get(v, "").strip()
        ),
        None,
    )
    api_key = os.environ.get(key_var, "").strip() if key_var else ""
    if not api_key:
        print(
            "Error: no API key found. Set STUBSMITH_ORG_API_KEY to an org API "
            "key with the review:read and review:approve scopes.",
            file=sys.stderr,
        )
        return 2
    api_url = (
        os.environ.get("STUBSMITH_API_URL")
        or os.environ.get("STUBSMITH_BACKEND_URL")
        or _SDK_DEFAULT_API_URL
    )

    if not args.project_id and not args.all_projects:
        # An org API key sees every project in the org, and the queue does not
        # report which project a fingerprint came from -- so an unscoped run can
        # approve a same-shaped fingerprint in an unrelated project and cannot
        # even say that it did. Refuse rather than guess.
        print(
            "Error: no project selected. Pass --project-id <uuid> (or set "
            "$STUBSMITH_PROJECT_ID); the id is in the project's dashboard URL.\n"
            "An org API key can see every project in the org, and this script "
            "matches fingerprints on (method, path_template, fingerprint), which "
            "is not project-specific -- so an unscoped run can approve a "
            "same-shaped fingerprint belonging to a different project.\n"
            "Pass --all-projects if that is genuinely what you want.",
            file=sys.stderr,
        )
        return 2

    try:
        queue = fetch_queue(api_url, api_key, args.project_id)
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:400]
        print(f"Error: review queue returned HTTP {e.code}: {detail}", file=sys.stderr)
        if e.code in (401, 403):
            # The commonest cause is the wrong *kind* of key rather than a bad
            # one. Naming the variable the key came from turns an opaque
            # "invalid token" into something actionable, and matters most when
            # the key came from the STUBSMITH_API_KEY fallback -- that variable
            # holds the project key for generate_traffic.py, which this endpoint
            # rejects.
            print(
                f"\nThe key came from ${key_var}. This endpoint needs an *org* "
                f"API key with the review:read and review:approve scopes; a "
                f"project key authenticates capture upload only and is rejected "
                f"here. Put the org key in $STUBSMITH_ORG_API_KEY.",
                file=sys.stderr,
            )
        return 1
    except OSError as e:
        print(f"Error: could not reach {api_url}: {e}", file=sys.stderr)
        return 1

    if not queue:
        print("No pending fingerprints. Nothing to approve.")
        return 0

    # Partition before approving anything. A queue holding fingerprints this
    # example does not document almost always means the wrong project: these
    # rules are written for the shop service, and applying them elsewhere keeps
    # response fields that project's operator never chose to keep. Approving the
    # recognised ones first and reporting the rest afterwards would already have
    # written the rules by the time anyone reads the warning.
    matched: List[Tuple[Dict[str, Any], List[Dict[str, str]]]] = []
    unknown: List[str] = []
    for row in queue:
        label = f"{row.get('method')} {row.get('path_template')} {row.get('fingerprint')}"
        field_rules = rules_for(row)
        if field_rules is None:
            unknown.append(label)
        else:
            matched.append((row, field_rules))

    if unknown and not args.ignore_unknown:
        scope = "every project the key can see" if args.all_projects else f"project {args.project_id}"
        print(
            f"Error: {len(unknown)} of {len(queue)} pending fingerprints are not "
            f"in this example's rule set, in {scope}.\n"
            f"Nothing was approved. This example documents 9 fingerprints across "
            f"8 endpoints; anything else suggests the wrong project, and its keep "
            f"rules must not be applied to another project's traffic.\n"
            f"Pass --ignore-unknown to approve the {len(matched)} recognised "
            f"fingerprint(s) anyway.\n",
            file=sys.stderr,
        )
        for label in unknown:
            print(f"  {label}", file=sys.stderr)
        return 2

    approved = 0
    failed: List[str] = []

    for row, field_rules in matched:
        label = f"{row.get('method')} {row.get('path_template')} {row.get('fingerprint')}"
        if args.dry_run:
            kept = ", ".join(r["path"] for r in field_rules)
            print(f"would approve  {label}\n               keep: {kept}")
            approved += 1
            continue
        try:
            approve(api_url, api_key, row["id"], field_rules)
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:200]
            print(f"FAILED  {label}: HTTP {e.code}: {detail}", file=sys.stderr)
            failed.append(label)
            continue
        except OSError as e:
            print(f"FAILED  {label}: {e}", file=sys.stderr)
            failed.append(label)
            continue
        print(f"approved  {label}  ({len(field_rules)} keep rules)")
        approved += 1

    verb = "would approve" if args.dry_run else "approved"
    scope = "all projects" if args.all_projects else f"project {args.project_id}"
    print(f"\n{verb}: {approved}  (in {scope})")

    if unknown:
        # Not in the table means the traffic generator produced a shape this
        # example does not document. Silently skipping would leave the field
        # masked and fail a test later with no explanation.
        print(
            f"\nNOT in the documented rule set ({len(unknown)}) - left pending:",
            file=sys.stderr,
        )
        for label in unknown:
            print(f"  {label}", file=sys.stderr)
    if failed:
        print(f"\nfailed: {len(failed)}", file=sys.stderr)

    return 1 if (unknown or failed) else 0


if __name__ == "__main__":
    sys.exit(main())
