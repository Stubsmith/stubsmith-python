#!/usr/bin/env python3
"""
shop_service/server.py - standalone shop API for the fixtures-testing example.

Run from the repo root::

    python3 examples/fixtures-testing/shop_service/server.py [--port 8081]

Stop with Ctrl-C.

Routes
------
GET  /api/users/{id}            200 user object | 404 USER_NOT_FOUND
POST /api/users                  201 created user | 422 validation error
POST /api/auth/login             200 token | 401 invalid credentials
POST /api/orders                 201 created order | 422 validation error
GET  /api/orders/{id}            200 order with items
GET  /api/orders?status=&limit=  200 filtered page
PUT  /api/orders/{id}            200 updated order | 422 invalid status
POST /api/payments/charges       201 charge succeeded | 402 card declined
POST /admin/reset                200 reset all mutable state to startup defaults

Business rules (fixed to produce deterministic captures)
---------------------------------------------------------
- User 9042 does not exist → 404.
- Login with password "wrongpass" → 401.
- Charges with amount_cents > 500000 → 402 INSUFFICIENT_FUNDS.
- PUT with an unrecognised status string → 422 INVALID_STATUS.
- POST /api/orders without both "item" and "qty" → 422.
- POST /api/users without "name" or "email" → 422.

Response bodies contain nested objects (address, card, items array) and fields
that masking has something real to do with (email, card last4, address).  The
server always returns real field values; it is the Stubsmith SDK's masking layer
that redacts them before storage.

Portability note
----------------
This server is stdlib-only (http.server, socketserver, threading, json, re).
Any language that can serve JSON over HTTP can provide an equivalent.  A port
needs: the same eight route shapes, the same four business rules, and the same
response-body key structure.  It does not need to reproduce the exact test data.
"""

from __future__ import annotations

import argparse
import json
import re
import socketserver
import sys
import threading
from http.server import BaseHTTPRequestHandler
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse

# ---------------------------------------------------------------------------
# In-memory store
# ---------------------------------------------------------------------------

_LOCK = threading.Lock()

_USERS: Dict[int, dict] = {
    4821: {
        "id": 4821,
        "name": "Casey Example",
        "email": "casey@example.invalid",
        "plan": "pro",
        "active": True,
        "address": {
            "line1": "12 Anvil Road",
            "city": "Irontown",
            "postcode": "EC1A 1AA",
        },
        "created_at": "2026-03-15T09:22:00Z",
        "last_login": "2026-08-21T22:41:00Z",
    },
    5512: {
        "id": 5512,
        "name": "Jordan Example",
        "email": "jordan@example.invalid",
        "plan": "starter",
        "active": True,
        "address": {
            "line1": "99 Copper Lane",
            "city": "Millsburg",
            "postcode": "W1A 0AX",
        },
        "created_at": "2026-06-01T14:00:00Z",
        "last_login": "2026-08-20T18:30:00Z",
    },
}
_NEXT_USER_ID = 6000

# Valid credentials: email → (password, user_id)
_CREDENTIALS: Dict[str, Tuple[str, int]] = {
    "casey@example.invalid": ("hunter2", 4821),
    "jordan@example.invalid": ("correct", 5512),
}

# Order IDs are bare integers so the SDK templates /api/orders/5234 →
# /api/orders/{id} (entirely numeric segment → {id}).
_INITIAL_ORDERS: Dict[int, dict] = {
    5234: {
        "order_id": 5234,
        "status": "shipped",
        "items": [{"sku": "widget-pro", "qty": 3, "price_cents": 2933}],
        "total_cents": 8799,
        "customer_email": "casey@example.invalid",
        "created_at": "2026-08-14T08:17:00Z",
    },
    6102: {
        "order_id": 6102,
        "status": "shipped",
        "items": [{"sku": "gadget-mini", "qty": 1, "price_cents": 1499}],
        "total_cents": 1499,
        "customer_email": "jordan@example.invalid",
        "created_at": "2026-08-18T11:00:00Z",
    },
    6350: {
        "order_id": 6350,
        "status": "pending",
        "items": [{"sku": "widget-pro", "qty": 1, "price_cents": 2933}],
        "total_cents": 2933,
        "customer_email": "jordan@example.invalid",
        "created_at": "2026-08-21T09:00:00Z",
    },
}
_ORDERS: Dict[int, dict] = dict(_INITIAL_ORDERS)
_NEXT_ORDER_SEQ = 7000

_CHARGES: Dict[str, dict] = {}
_NEXT_CHARGE_SEQ = 100000

_CARD_DECLINED_LIMIT = 500_000  # > EUR 5 000 → declined

_VALID_ORDER_STATUSES = {"pending", "confirmed", "shipped", "cancelled", "refunded"}

# ---------------------------------------------------------------------------
# Route patterns
# ---------------------------------------------------------------------------

_RE_USER_DETAIL = re.compile(r"^/api/users/([^/?#]+)$")
_RE_ORDER_DETAIL = re.compile(r"^/api/orders/([^/?#]+)$")

# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------


class ShopHandler(BaseHTTPRequestHandler):
    """Request handler for the shop service."""

    # Suppress access log to stdout to avoid confusing the capture terminal.
    def log_request(self, code="-", size="-") -> None:  # type: ignore[override]
        pass

    def log_error(self, fmt: str, *args: Any) -> None:
        sys.stderr.write(f"[shop] ERROR: {fmt % args}\n")

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def _parsed(self) -> Tuple[str, str, Dict[str, str]]:
        """Return (path, query_string, query_params)."""
        parsed = urlparse(self.path)
        qs = parsed.query or ""
        params = {k: v[0] for k, v in parse_qs(qs).items()}
        return parsed.path, qs, params

    def do_GET(self) -> None:
        path, qs, params = self._parsed()

        m = _RE_USER_DETAIL.match(path)
        if m:
            self._handle_get_user(m.group(1))
            return

        if path == "/api/orders":
            self._handle_list_orders(params)
            return

        m = _RE_ORDER_DETAIL.match(path)
        if m:
            self._handle_get_order(m.group(1))
            return

        if path == "/health":
            self._respond(200, {"ok": True})
            return

        self._respond(404, {"error": "not found"})

    def do_POST(self) -> None:
        path, _, _ = self._parsed()
        body = self._read_body()

        if path == "/api/users":
            self._handle_create_user(body)
        elif path == "/api/auth/login":
            self._handle_login(body)
        elif path == "/api/orders":
            self._handle_create_order(body)
        elif path == "/api/payments/charges":
            self._handle_create_charge(body)
        elif path == "/admin/reset":
            self._handle_reset()
        else:
            self._respond(404, {"error": "not found"})

    def do_PUT(self) -> None:
        path, _, _ = self._parsed()
        body = self._read_body()

        m = _RE_ORDER_DETAIL.match(path)
        if m:
            self._handle_update_order(m.group(1), body)
        else:
            self._respond(404, {"error": "not found"})

    # ------------------------------------------------------------------
    # Route handlers
    # ------------------------------------------------------------------

    def _handle_get_user(self, raw_id: str) -> None:
        try:
            user_id = int(raw_id)
        except ValueError:
            self._respond(404, {"error": "user not found", "code": "USER_NOT_FOUND"})
            return
        with _LOCK:
            user = _USERS.get(user_id)
        if user is None:
            self._respond(404, {"error": "user not found", "code": "USER_NOT_FOUND"})
        else:
            self._respond(200, user)

    def _handle_create_user(self, body: Optional[dict]) -> None:
        if not body or "name" not in body or "email" not in body:
            self._respond(422, {"error": "name and email are required", "code": "VALIDATION_ERROR"})
            return
        global _NEXT_USER_ID
        with _LOCK:
            uid = _NEXT_USER_ID
            _NEXT_USER_ID += 1
            user: dict = {
                "id": uid,
                "name": body["name"],
                "email": body["email"],
                "plan": "free",
                "active": True,
                "address": {},
                "created_at": "2026-08-21T12:00:00Z",
                "last_login": None,
            }
            _USERS[uid] = user
        self._respond(201, {"id": uid, "name": user["name"], "email": user["email"],
                             "created": True, "created_at": user["created_at"]})

    def _handle_login(self, body: Optional[dict]) -> None:
        if not body:
            self._respond(400, {"error": "request body required"})
            return
        email = body.get("email", "")
        password = body.get("password", "")
        # A literal "wrongpass" password always fails, regardless of email.
        creds = _CREDENTIALS.get(email)
        if password == "wrongpass" or creds is None or creds[0] != password:
            self._respond(401, {"error": "invalid credentials"})
            return
        user_id = creds[1]
        self._respond(200, {
            "token": "tok_live_abcdef1234567890",
            "expires_in": 7200,
            "user_id": user_id,
            "session_token": "sess_xyz987654321",
        })

    def _handle_create_order(self, body: Optional[dict]) -> None:
        if not body or "item" not in body or "qty" not in body:
            self._respond(422, {"error": "item and qty are required", "code": "VALIDATION_ERROR"})
            return
        try:
            qty = int(body["qty"])
        except (TypeError, ValueError):
            self._respond(422, {"error": "qty must be an integer", "code": "VALIDATION_ERROR"})
            return
        global _NEXT_ORDER_SEQ
        with _LOCK:
            seq = _NEXT_ORDER_SEQ
            _NEXT_ORDER_SEQ += 1
            order_id = seq  # bare integer; SDK templates /api/orders/{int} → {id}
            unit_price = 2933  # fixed for demo
            order: dict = {
                "order_id": order_id,
                "status": "confirmed",
                "items": [{"sku": body["item"], "qty": qty, "price_cents": unit_price}],
                "total_cents": unit_price * qty,
                "customer_email": "casey@example.invalid",
                "created_at": "2026-08-21T10:12:16Z",
            }
            _ORDERS[order_id] = order
        self._respond(201, order)

    def _handle_get_order(self, raw_id: str) -> None:
        try:
            order_id = int(raw_id)
        except ValueError:
            self._respond(404, {"error": "order not found"})
            return
        with _LOCK:
            order = _ORDERS.get(order_id)
        if order is None:
            self._respond(404, {"error": "order not found"})
        else:
            self._respond(200, order)

    def _handle_list_orders(self, params: Dict[str, str]) -> None:
        status_filter = params.get("status")
        try:
            limit = int(params.get("limit", "20"))
        except ValueError:
            limit = 20
        with _LOCK:
            orders = list(_ORDERS.values())
        if status_filter:
            orders = [o for o in orders if o["status"] == status_filter]
        orders = orders[:limit]
        summaries = [{"order_id": o["order_id"], "status": o["status"]} for o in orders]
        self._respond(200, {"orders": summaries, "total": len(summaries)})

    def _handle_update_order(self, raw_id: str, body: Optional[dict]) -> None:
        new_status = (body or {}).get("status", "")
        if new_status not in _VALID_ORDER_STATUSES:
            self._respond(422, {"error": f"invalid status: {new_status!r}",
                                 "code": "INVALID_STATUS"})
            return
        try:
            order_id = int(raw_id)
        except ValueError:
            self._respond(404, {"error": "order not found"})
            return
        with _LOCK:
            order = _ORDERS.get(order_id)
            if order is None:
                self._respond(404, {"error": "order not found"})
                return
            order = dict(order)
            order["status"] = new_status
            _ORDERS[order_id] = order
        self._respond(200, {"order_id": order_id, "status": new_status})

    def _handle_reset(self) -> None:
        """Reset all mutable state to startup defaults.

        Called by ``generate_traffic.py`` at the start of each run so that a
        second traffic run produces the same captured responses as the first.
        Without this, PUT /api/orders/5234 → "cancelled" on the first run
        makes a subsequent GET return "cancelled", corrupting the capture.
        """
        global _ORDERS, _CHARGES, _NEXT_ORDER_SEQ, _NEXT_CHARGE_SEQ, _NEXT_USER_ID
        with _LOCK:
            _ORDERS = dict(_INITIAL_ORDERS)
            _CHARGES = {}
            _NEXT_ORDER_SEQ = 7000
            _NEXT_CHARGE_SEQ = 100000
            _NEXT_USER_ID = 6000
        self._respond(200, {"ok": True, "reset": True})

    def _handle_create_charge(self, body: Optional[dict]) -> None:
        if not body:
            self._respond(400, {"error": "request body required"})
            return
        try:
            amount_cents = int(body.get("amount_cents", 0))
        except (TypeError, ValueError):
            self._respond(422, {"error": "amount_cents must be an integer", "code": "VALIDATION_ERROR"})
            return
        currency = body.get("currency", "EUR")
        card = body.get("card", {})
        last4 = str(card.get("number", "0000"))[-4:]

        if amount_cents > _CARD_DECLINED_LIMIT:
            global _NEXT_CHARGE_SEQ
            with _LOCK:
                seq = _NEXT_CHARGE_SEQ
                _NEXT_CHARGE_SEQ += 1
            charge_id = f"ch_{seq}"
            self._respond(402, {
                "error": "card declined",
                "code": "INSUFFICIENT_FUNDS",
                "charge_id": charge_id,
            })
            return

        with _LOCK:
            seq = _NEXT_CHARGE_SEQ
            _NEXT_CHARGE_SEQ += 1
        charge_id = f"ch_{seq}"
        brand = "visa" if str(card.get("number", "")).startswith("4") else "mc"
        charge: dict = {
            "charge_id": charge_id,
            "status": "succeeded",
            "amount_cents": amount_cents,
            "currency": currency,
            "card": {"last4": last4, "brand": brand},
            "created_at": "2026-08-21T10:12:28Z",
        }
        with _LOCK:
            _CHARGES[charge_id] = charge
        self._respond(201, charge)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _read_body(self) -> Optional[dict]:
        length = int(self.headers.get("Content-Length", 0) or 0)
        if not length:
            return None
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return None

    def _respond(self, status: int, body: dict) -> None:
        encoded = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


class _ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(port: int = 8081) -> None:
    """Start the shop service on *port* and block until Ctrl-C."""
    with _ThreadedServer(("", port), ShopHandler) as srv:
        print(f"[shop] listening on http://localhost:{port}")
        print("[shop] routes: GET/POST /api/users, POST /api/auth/login, "
              "*/api/orders*, POST /api/payments/charges")
        print("[shop] Ctrl-C to stop")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\n[shop] shutting down")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Shop service for fixtures-testing example")
    parser.add_argument("--port", type=int, default=8081, help="Port to listen on (default 8081)")
    args = parser.parse_args()
    serve(args.port)
