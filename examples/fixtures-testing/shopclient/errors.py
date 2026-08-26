"""Typed exceptions raised by ShopClient on non-2xx responses."""


class ShopApiError(Exception):
    """Base error for all non-2xx responses from the shop API."""

    def __init__(self, status: int, body: dict):
        self.status = status
        self.body = body
        super().__init__(f"HTTP {status}: {body}")


class UserNotFound(ShopApiError):
    """404 with code USER_NOT_FOUND."""


class InvalidCredentials(ShopApiError):
    """401 on login."""


class CardDeclined(ShopApiError):
    """402 on charge creation - carries charge_id and code from the response."""

    def __init__(self, status: int, body: dict):
        super().__init__(status, body)
        self.charge_id = body.get("charge_id")
        self.code = body.get("code")
