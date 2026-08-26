#!/usr/bin/env python3
"""
generate_traffic.py - instrument ShopClient with the Stubsmith SDK and drive
traffic against the shop service (your local application stand-in).

Step 2 of the demo loop::

    export STUBSMITH_API_KEY=<your-project-api-key>
    python3 examples/fixtures-testing/generate_traffic.py [--base-url http://localhost:8081]

The shop service must be running first::

    python3 examples/fixtures-testing/shop_service/server.py

The SDK captures each request and sends it to the Stubsmith ingest service
(https://ingest.stubsmith.dev by default - no override needed for the hosted
service).  The backend that serves the review UI and issues API keys is a
separate host (https://app.stubsmith.dev).  Raw field values are masked at
the edge before anything leaves this process.

This script calls all eight routes and drives the 401 (wrong-password login)
and 402 (card declined) error paths explicitly.  The 422 validation paths
documented in server.py are not driven here.

After running, open your project at https://app.stubsmith.dev, approve the
fingerprints in the Review screen, then pull the bundle::

    stubsmith pull --out examples/fixtures-testing/.stubsmith/bundle.json

Environment variables::

    STUBSMITH_API_KEY      Required.  Project API key.
    STUBSMITH_API_URL      Backend base URL.  Default: https://app.stubsmith.dev/api
                           For a self-hosted instance set this to the backend
                           URL (e.g. http://localhost:3005/api).  The rules-cache
                           poll (GET /v1/sdk/sync) appends to this value directly,
                           so include any path prefix the server requires.
    STUBSMITH_INGEST_URL   Ingest URL.  Defaults to the SDK's built-in default
                           (stubsmith.DEFAULT_INGEST_URL).  Set this when ingest
                           runs on a different host or port than the backend -
                           e.g. a self-hosted split deployment with ingest on
                           port 8087.
"""
from __future__ import annotations

import argparse
import os
import pathlib
import sys
import urllib.error
import urllib.request as _urlreq

# Prefer the SDK checkout over site-packages when this example sits inside it.
import _sdk_path  # noqa: F401  (sys.path side effect - must precede stubsmith)

# SDK import - must be installed ('pip install -e ".[requests]"' from repo root)
# unless this file is being run from inside the checkout.
try:
    import stubsmith
except ImportError:
    sys.exit(
        "Error: stubsmith not importable.  Install it first:\n"
        "  pip install -e '.[requests]'  # from the repo root"
    )

# ShopClient - import from alongside this script.
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from shopclient.client import ShopClient
from shopclient.errors import CardDeclined, InvalidCredentials, ShopApiError

_API_KEY = os.environ.get("STUBSMITH_API_KEY", "").strip()
_API_URL = (
    os.environ.get("STUBSMITH_API_URL")
    or os.environ.get("STUBSMITH_BACKEND_URL")
    or stubsmith.DEFAULT_API_URL
).rstrip("/")

# Backend base URL for the rules-cache poll (GET /v1/sdk/sync).
# The SDK appends /v1/sdk/sync directly, so _API_URL is passed verbatim -
# no path stripping.  For the hosted service this means:
#   https://app.stubsmith.dev/api + /v1/sdk/sync → https://app.stubsmith.dev/api/v1/sdk/sync
# For a local stack without a prefix:
#   http://localhost:3000 + /v1/sdk/sync → http://localhost:3000/v1/sdk/sync
_BACKEND_URL = _API_URL

# Ingest URL.  STUBSMITH_INGEST_URL wins when set - use it for split-port
# deployments where ingest runs on a different host or port than the backend.
# Otherwise the SDK's public default is used.  The hosted service and any
# self-hosted deployment that does not split ingest onto a separate port rely
# on that default; a deployment that does split ingest sets STUBSMITH_INGEST_URL.
# There is no ingest-from-backend derivation here: guessing deployment topology
# from a backend URL is fragile, and an explicit env var is unambiguous.
_INGEST_URL = os.environ.get("STUBSMITH_INGEST_URL") or stubsmith.DEFAULT_INGEST_URL


def _preflight_probe() -> None:
    """POST an empty body to the ingest URL and fail loudly on a 404.

    This script is a capture driver, not production instrumentation.  The SDK
    swallows send failures by design (never break the caller), which is correct
    for long-running services but leaves this script with no signal when the
    ingest URL is wrong.  A quick pre-flight check catches misconfiguration
    before all captures silently 404.

    A 401 means the endpoint exists and the key will be checked on real sends -
    treat that as a reachability success.  A 404 is fatal: it means the URL
    resolves to a host that does not speak the ingest protocol at all.
    """
    # The ingest URL may already include /v1/captures (the default does).
    # If not, append the captures path so we hit an endpoint the server knows.
    probe_url = (
        _INGEST_URL
        if _INGEST_URL.endswith("/v1/captures")
        else _INGEST_URL.rstrip("/") + "/v1/captures"
    )

    print(f"[preflight] POST {probe_url} ...", end="  ", flush=True)
    try:
        req = _urlreq.Request(
            probe_url,
            data=b"{}",
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with _urlreq.urlopen(req, timeout=10) as resp:
            status = resp.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    except Exception as exc:
        print(f"FAIL (connection error: {exc})")
        sys.exit(
            f"\nPreflight failed: could not connect to the ingest service.\n"
            f"URL tried: {probe_url}\n"
            f"Set STUBSMITH_INGEST_URL to point at the ingest host, or unset it "
            f"to use the hosted default (https://ingest.stubsmith.dev/v1/captures)."
        )

    if status == 404:
        print(f"FAIL (HTTP 404)")
        sys.exit(
            f"\nPreflight failed: POST {probe_url} returned HTTP 404.\n"
            f"The ingest service is not at this URL.\n"
            f"For the hosted service the ingest URL is https://ingest.stubsmith.dev/v1/captures\n"
            f"(separate from the backend at https://app.stubsmith.dev/api).\n"
            f"Set STUBSMITH_INGEST_URL explicitly, or unset STUBSMITH_API_URL to use the defaults."
        )

    if status == 401:
        # Endpoint exists; the real API key will be sent on actual captures.
        print(f"ok (HTTP 401 - endpoint reachable, key checked on real sends)")
        return

    print(f"ok (HTTP {status})")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate ShopClient traffic with SDK instrumentation"
    )
    parser.add_argument(
        "--base-url",
        default="http://localhost:8081",
        help="Shop service base URL (default: http://localhost:8081)",
    )
    args = parser.parse_args()
    base_url: str = args.base_url.rstrip("/")

    if not _API_KEY:
        sys.exit(
            "Error: STUBSMITH_API_KEY is required.\n"
            "Export it before running:\n  export STUBSMITH_API_KEY=<your-key>"
        )

    _preflight_probe()
    print()

    print(f"[traffic] backend:  {_BACKEND_URL}")
    print(f"[traffic] ingest:   {_INGEST_URL}")
    print(f"[traffic] shop:     {base_url}")
    print()

    # Reset the shop service before generating traffic.  On a second run the
    # PUT /api/orders/5234 → "cancelled" from the first run would cause the
    # GET to return "cancelled", contradicting the captured "shipped" response.
    # The reset endpoint restores the initial order set and sequence counters.
    try:
        req = _urlreq.Request(f"{base_url}/admin/reset", data=b"", method="POST")
        with _urlreq.urlopen(req, timeout=5):
            pass
        print("[traffic] shop service reset to initial state")
    except Exception as exc:
        print(f"[traffic] WARNING: reset failed ({exc}) - continuing anyway")
    print()

    # Install the SDK.  This patches requests.Session.request so every call
    # made by ShopClient is captured, masked, and forwarded to Stubsmith.
    #
    # backend_url is derived from _API_URL so the rules-cache poll reaches the
    # same host as STUBSMITH_API_URL - no separate STUBSMITH_BACKEND_URL needed.
    #
    # wait_for_rules blocks until the backend has delivered its first set of
    # approved field rules (up to 5 s).  Without this, a short script that
    # finishes in ~50 ms races the background sync (~74 ms on localhost) and
    # every capture lands as novel=True with every field masked.  Long-running
    # services do not need wait_for_rules because the rules cache has time to
    # warm up before real traffic arrives.
    _WAIT_SECS = 5.0
    sdk = stubsmith.install(
        url=_INGEST_URL,  # None → SDK uses its default (https://ingest.stubsmith.dev/v1/captures)
        api_key=_API_KEY,
        backend_url=_BACKEND_URL,
        wait_for_rules=_WAIT_SECS,
    )
    if not sdk.rules_synced:
        _sync_url = _BACKEND_URL.rstrip("/") + "/v1/sdk/sync"
        print(
            f"[traffic] WARNING: rules did not sync within {_WAIT_SECS:.0f}s; "
            "captures will be fail-closed and every field masked.\n"
            f"[traffic]          Check that the backend is reachable at {_sync_url}"
        )
        print()

    client = ShopClient(base_url, "sk-demo-key")

    # ── GET /api/users/{id} - happy path ───────────────────────────────────
    _run("GET /api/users/4821", lambda: client.get_user(4821))

    # ── GET /api/users/{id} - 404 ──────────────────────────────────────────
    _run("GET /api/users/9042 (404)", lambda: client.get_user(9042),
         expect=(ShopApiError,))

    # ── POST /api/users ─────────────────────────────────────────────────────
    _run("POST /api/users", lambda: client.create_user(
        name="Sam Example",
        email="sam@example.invalid",
        password="s3cr3t",
        phone="+1 555 0001",
    ))

    # ── POST /api/auth/login - success ─────────────────────────────────────
    _run("POST /api/auth/login (200)", lambda: client.login(
        "casey@example.invalid", "hunter2"
    ))

    # ── POST /api/auth/login - wrong password ──────────────────────────────
    _run("POST /api/auth/login (401)", lambda: client.login(
        "casey@example.invalid", "wrongpass"
    ), expect=(InvalidCredentials,))

    # ── POST /api/orders ────────────────────────────────────────────────────
    _run("POST /api/orders", lambda: client.create_order(
        "widget-pro", 3, "4242424242424242", "leave at door"
    ))

    # ── GET /api/orders/{id} ────────────────────────────────────────────────
    _run("GET /api/orders/5234", lambda: client.get_order(5234))

    # ── GET /api/orders?status=shipped&limit=20 ─────────────────────────────
    _run("GET /api/orders?status=shipped&limit=20", lambda: client.list_orders(
        status="shipped", limit=20
    ))

    # ── PUT /api/orders/{id} ────────────────────────────────────────────────
    _run("PUT /api/orders/5234", lambda: client.update_order(5234, "cancelled"))

    # ── POST /api/payments/charges - 201 (with idempotency_key) ────────────
    _run("POST /api/payments/charges (201, with idem)", lambda: client.create_charge(
        amount_cents=4250,
        currency="EUR",
        card={"number": "4242424242424242", "exp_month": 5, "exp_year": 2028,
               "cvc": "359", "holder": "Casey Example"},
        customer={"email": "casey@example.invalid", "name": "Casey Example",
                   "phone": "+44 7700 900000"},
        idempotency_key="idem-traffic-gen-0001",
    ))

    # ── POST /api/payments/charges - 402 (no idempotency_key, large amount) ─
    _run("POST /api/payments/charges (402, no idem)", lambda: client.create_charge(
        amount_cents=950_000,
        currency="USD",
        card={"number": "5500005555555559", "exp_month": 9, "exp_year": 2027,
               "cvc": "737", "holder": "Jordan Example"},
        customer={"email": "jordan@example.invalid", "name": "Jordan Example",
                   "phone": "+1 555 7731"},
    ), expect=(CardDeclined,))

    # Flush all in-flight background sends and stop the SDK worker cleanly.
    sdk.close()

    print()
    print("[traffic] Done.  Review fingerprints in the Stubsmith UI, then run:")
    print("  stubsmith pull --out examples/fixtures-testing/.stubsmith/bundle.json")


def _run(label: str, fn, expect=()) -> None:
    """Run *fn*, print the result.  *expect* is a tuple of exception types that are OK."""
    print(f"  {label} ...", end="  ", flush=True)
    try:
        result = fn()
        print(f"ok  {list(result.keys()) if isinstance(result, dict) else result!r}")
    except tuple(expect) as exc:
        print(f"expected {type(exc).__name__}")
    except Exception as exc:
        print(f"UNEXPECTED ERROR: {exc}")
        raise


if __name__ == "__main__":
    main()
