"""
ShopClient - a plain requests-based client for the fixtures-testing example's synthetic API.

This file has no knowledge of Stubsmith.  It is ordinary application code;
the separation between the client under test and the fixture glue is the
whole point of the example.
"""
import urllib.parse

import requests

from .errors import CardDeclined, InvalidCredentials, ShopApiError, UserNotFound


class ShopClient:
    """Client for the shop API.

    Args:
        base_url: Root URL, e.g. ``http://localhost:8000`` or the production host.
        api_key: Bearer token sent on every request.
        session: Optional :class:`requests.Session` to use (useful for injection
            in tests, though the ``responses`` library intercepts at a lower level
            so this is mostly cosmetic).
    """

    def __init__(self, base_url: str, api_key: str, session=None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._session = session or requests.Session()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.api_key}"}

    def _raise_for_status(self, resp: requests.Response) -> None:
        if resp.ok:
            return
        body: dict = {}
        try:
            body = resp.json()
        except Exception:
            pass
        if resp.status_code == 404 and body.get("code") == "USER_NOT_FOUND":
            raise UserNotFound(resp.status_code, body)
        if resp.status_code == 401:
            raise InvalidCredentials(resp.status_code, body)
        if resp.status_code == 402:
            raise CardDeclined(resp.status_code, body)
        raise ShopApiError(resp.status_code, body)

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    def get_user(self, user_id: int) -> dict:
        resp = self._session.get(
            f"{self.base_url}/api/users/{user_id}",
            headers=self._headers(),
        )
        self._raise_for_status(resp)
        return resp.json()

    def create_user(self, name: str, email: str, password: str, phone: str) -> dict:
        resp = self._session.post(
            f"{self.base_url}/api/users",
            json={"name": name, "email": email, "password": password, "phone": phone},
            headers=self._headers(),
        )
        self._raise_for_status(resp)
        return resp.json()

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    def login(self, email: str, password: str) -> dict:
        resp = self._session.post(
            f"{self.base_url}/api/auth/login",
            json={"email": email, "password": password},
            headers=self._headers(),
        )
        self._raise_for_status(resp)
        return resp.json()

    # ------------------------------------------------------------------
    # Orders
    # ------------------------------------------------------------------

    def create_order(self, item: str, qty: int, card_number: str, note: str) -> dict:
        resp = self._session.post(
            f"{self.base_url}/api/orders",
            json={"item": item, "qty": qty, "card_number": card_number, "note": note},
            headers=self._headers(),
        )
        self._raise_for_status(resp)
        return resp.json()

    def get_order(self, order_id) -> dict:
        resp = self._session.get(
            f"{self.base_url}/api/orders/{order_id}",
            headers=self._headers(),
        )
        self._raise_for_status(resp)
        return resp.json()

    def list_orders(self, status: str = None, limit: int = 20) -> dict:
        # Query parameters are baked into the URL (not passed via params=) so the
        # Stubsmith SDK fingerprints them as part of the URL it sees.  Using params=
        # here would produce a different fingerprint in production because the SDK
        # patches Session.request before requests merges params into the URL.
        params: dict = {}
        if status is not None:
            params["status"] = status
        params["limit"] = limit
        qs = urllib.parse.urlencode(params)
        resp = self._session.get(
            f"{self.base_url}/api/orders?{qs}",
            headers=self._headers(),
        )
        self._raise_for_status(resp)
        return resp.json()

    def update_order(self, order_id, status: str) -> dict:
        resp = self._session.put(
            f"{self.base_url}/api/orders/{order_id}",
            json={"status": status},
            headers=self._headers(),
        )
        self._raise_for_status(resp)
        return resp.json()

    # ------------------------------------------------------------------
    # Payments
    # ------------------------------------------------------------------

    def create_charge(
        self,
        amount_cents: int,
        currency: str,
        card: dict,
        customer: dict,
        idempotency_key: str = None,
    ) -> dict:
        payload = {
            "amount_cents": amount_cents,
            "currency": currency,
            "card": card,
            "customer": customer,
        }
        if idempotency_key is not None:
            payload["idempotency_key"] = idempotency_key
        resp = self._session.post(
            f"{self.base_url}/api/payments/charges",
            json=payload,
            headers=self._headers(),
        )
        self._raise_for_status(resp)
        return resp.json()
