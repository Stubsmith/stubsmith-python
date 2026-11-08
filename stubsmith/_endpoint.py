"""
The SDK's own traffic (captures, rules sync, bundle and fixture fetches) goes
over https only. Plain http is accepted for a backend on this machine
(``localhost``, ``127.0.0.1``, ``::1``) so local development keeps working.
"""

from __future__ import annotations

import urllib.parse
import urllib.request
from typing import Any, Optional

_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


class InsecureEndpointError(ValueError):
    """Raised for a StubSmith URL the SDK will not send to."""


def check_endpoint(url: str) -> None:
    """Raise :class:`InsecureEndpointError` unless *url* is https or local http.

    The message names only the scheme and host, so credentials in the URL are
    never echoed into logs.
    """
    try:
        parts = urllib.parse.urlsplit(url)
        scheme = parts.scheme.lower()
        host = parts.hostname or ""
    except (TypeError, ValueError, AttributeError):
        raise InsecureEndpointError(
            "stubsmith: the StubSmith URL is not a valid URL; "
            "the SDK sends only to an https URL."
        ) from None
    if scheme == "https" and host:
        return
    if scheme == "http" and host in _LOCAL_HOSTS:
        return
    shown = f"{scheme}://{host}" if scheme else repr(host or "")
    raise InsecureEndpointError(
        f"stubsmith: refusing to send to {shown}. The SDK sends only over "
        "https; plain http is allowed only for localhost, 127.0.0.1 and ::1."
    )


class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: the 3xx surfaces as an ``HTTPError``.

    urllib re-sends the ``Authorization`` header to the redirect target, which
    could be a plaintext or foreign host. None of StubSmith's endpoints redirect.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


# Built once; its own handler chain, so the host application's global opener
# (urllib.request.install_opener) is neither used nor changed.
_OPENER = urllib.request.build_opener(_RefuseRedirect)


def urlopen(req: urllib.request.Request, timeout: Optional[float] = None) -> Any:
    """Open *req* after :func:`check_endpoint`, without following redirects."""
    check_endpoint(req.full_url)
    return _OPENER.open(req, timeout=timeout)
