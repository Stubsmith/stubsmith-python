"""
StubSmith fixtures helper - fetch recorded response variants for a request type.

Quickstart::

    import stubsmith

    fxs = stubsmith.fixtures("POST /v1/charges/{id}", distinct="status")
    for fx in fxs:
        print(fx)               # <Fixture POST /v1/charges/ch_abc -> 201>
        print(fx.response.json())

Requires ``STUBSMITH_API_URL`` and ``STUBSMITH_API_KEY`` environment variables
(or pass them directly as keyword arguments).
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, List, Optional

_DEFAULT_API_URL = "https://app.stubsmith.dev/api"


class _Side:
    """Headers and body for one side (request or response) of a :class:`Fixture`."""

    def __init__(self, headers: Dict, body: Optional[str]) -> None:
        self.headers: Dict = headers or {}
        self.body: Optional[str] = body

    def json(self):
        """
        Parse ``body`` as JSON and return the result.

        Raises :exc:`ValueError` if the body is ``None`` or not valid JSON.
        """
        if self.body is None:
            raise ValueError("body is None - cannot parse as JSON")
        return json.loads(self.body)


class Fixture:
    """
    A single recorded HTTP exchange returned by the StubSmith ``/v1/fixtures`` endpoint.

    Attributes
    ----------
    id:
        Unique identifier of the underlying capture.
    captured_at:
        ISO-8601 timestamp string when the traffic was recorded.
    method:
        HTTP method in upper case (e.g. ``"POST"``).
    path:
        Request path as stored.  For non-ID segments the path is literal
        (e.g. ``"/v1/charges/ch_abc"``).  For numeric, UUID, or 16+-hex
        segments the SDK substitutes ``{id}`` before storage
        (e.g. ``"/v1/charges/{id}"`` for ``/v1/charges/12345``).  See
        ``stubsmith/privacy/templating.py`` for the heuristic rules.  For
        dynamic routes the stored path will therefore contain literal braces.
    status:
        HTTP response status code (integer).
    duration_ms:
        Observed round-trip time in milliseconds, or ``None`` when not recorded.
    request:
        A :class:`_Side` object with ``.headers`` (dict), ``.body`` (str | None),
        and ``.json()`` for parsing the body as JSON.
    response:
        Same as ``request`` but for the response side.
    """

    def __init__(
        self,
        id: str,
        captured_at: str,
        method: str,
        path: str,
        status: int,
        duration_ms: Optional[int],
        request: _Side,
        response: _Side,
    ) -> None:
        self.id = id
        self.captured_at = captured_at
        self.method = method
        self.path = path
        self.status = status
        self.duration_ms = duration_ms
        self.request = request
        self.response = response

    @classmethod
    def _from_dict(cls, d: dict) -> "Fixture":
        req = d.get("request") or {}
        resp = d.get("response") or {}
        return cls(
            id=d["id"],
            captured_at=d["captured_at"],
            method=d["method"],
            path=d["path"],
            status=d["status"],
            duration_ms=d.get("duration_ms"),
            request=_Side(req.get("headers") or {}, req.get("body")),
            response=_Side(resp.get("headers") or {}, resp.get("body")),
        )

    def __repr__(self) -> str:
        return f"<Fixture {self.method} {self.path} -> {self.status}>"


class FixtureBundle:
    """
    The full ``/v1/fixtures`` response envelope.

    Holds the resolved ``request_type`` metadata alongside the list of
    :class:`Fixture` objects.  Use :meth:`by_status` to pick a specific
    response variant, then pass the bundle (or individual fixture) to the
    helpers in :mod:`stubsmith.testing`.

    Attributes
    ----------
    request_type:
        Dict with ``id``, ``method``, ``path_pattern``, and ``is_dynamic``
        from the resolved request type, or ``None`` when the pattern was not
        recognised by the server.
    fixtures:
        List of :class:`Fixture` objects, newest-first.
    count:
        Number of fixtures returned (matches ``len(fixtures)``).
    """

    def __init__(self, data: dict) -> None:
        # ``ok`` defaults to True so a hand-written vendored bundle without the
        # field does not spuriously fail a ``bundle.ok is True`` assertion.
        self.ok: bool = data.get("ok", True)
        self.request_type: Optional[dict] = data.get("request_type")
        self.fixtures: List[Fixture] = [
            Fixture._from_dict(f) for f in data.get("fixtures", [])
        ]
        self.count: int = data.get("count", len(self.fixtures))

    def by_status(self, status: int) -> Fixture:
        """Return the :class:`Fixture` for a given HTTP status code.

        Raises :exc:`ValueError` that names the statuses which are present
        when the requested status is not found - a fixture set that silently
        drifts is worse than a quiet failure.

        Parameters
        ----------
        status:
            HTTP status code to look up (e.g. ``200``, ``404``).

        Raises
        ------
        ValueError
            When no fixture with the requested status exists in this bundle.
        """
        for f in self.fixtures:
            if f.status == status:
                return f
        present = sorted({f.status for f in self.fixtures})
        raise ValueError(
            f"No fixture with status {status} in bundle (present: {present})"
        )


def fixtures_bundle(
    pattern: str,
    *,
    api_url: Optional[str] = None,
    api_key: Optional[str] = None,
    distinct: Optional[str] = None,
    limit: Optional[int] = None,
) -> FixtureBundle:
    """
    Fetch the full ``/v1/fixtures`` envelope for a request type pattern.

    This is the lower-level accessor that returns a :class:`FixtureBundle`
    including the ``request_type`` metadata (``path_pattern``, ``is_dynamic``).
    :func:`fixtures` delegates to this function and returns only the
    ``.fixtures`` list.

    Parameters
    ----------
    pattern:
        A string of the form ``"METHOD /path/pattern"`` - for example
        ``"POST /v1/charges/{id}"`` or ``"GET /v1/users"``.  The method and
        path are split on the first space.

        The path is forwarded to the API as-is and resolved server-side by
        comparing it against stored ``path_pattern`` values using a
        segment-level matcher (see ``backend/src/fixtures.js``): ``{param}``
        tokens in the *stored* pattern act as wildcards, so passing the pattern
        string ``/v1/charges/{id}`` will correctly resolve a configured request
        type with that same path pattern.

        **Limitation:** an unrecognised pattern returns an empty bundle rather
        than an error.  The server resolves a request type by comparing the
        supplied path against stored ``path_pattern`` values using the
        segment-level ``segmentMatch`` function: ``{param}`` tokens in the
        *stored* pattern act as wildcards, so passing ``/v1/charges/{id}``
        resolves correctly against a configured type with that pattern.  If no
        request type resolves, the server falls back to exact path equality
        against capture records.  Because the SDK templates numeric, UUID, and
        16+-hex segments before storage (see ``stubsmith/privacy/templating.py``),
        captures for those routes are stored at the templated path (e.g.
        ``/v1/charges/{id}``), so querying with the templated form still finds
        them.  Always configure your request types (with a ``path_pattern``) to
        receive structured ``request_type`` metadata in the bundle; without a
        configured type the ``request_type`` field is ``None``.

    api_url:
        Base URL of the StubSmith API (no trailing slash).  Defaults to the
        ``STUBSMITH_API_URL`` environment variable, then
        ``https://app.stubsmith.dev/api``.

        Note: the fixtures-testing example uses ``STUBSMITH_BACKEND_URL`` for
        the same value; that name is non-authoritative and kept for compatibility.
        ``STUBSMITH_API_URL`` is the SDK's canonical variable.
    api_key:
        Bearer token (project API key).  Defaults to the ``STUBSMITH_API_KEY``
        environment variable.  A :exc:`RuntimeError` is raised when no key is
        available.
    distinct:
        Pass ``"status"`` to receive at most one fixture per distinct HTTP
        status code (newest-first).
    limit:
        Maximum number of fixtures to return (1-100).  Server default is 20.

    Returns
    -------
    FixtureBundle
        Envelope with ``request_type`` metadata and the list of fixtures.

    Raises
    ------
    RuntimeError
        When the API key is missing or the server returns a non-2xx response.
    ValueError
        When *pattern* cannot be split into method and path.
    """
    url = api_url or os.environ.get("STUBSMITH_API_URL", _DEFAULT_API_URL)
    key = api_key or os.environ.get("STUBSMITH_API_KEY", "")
    if not key:
        raise RuntimeError(
            "StubSmith API key is required. "
            "Pass api_key= or set the STUBSMITH_API_KEY environment variable."
        )

    parts = pattern.split(" ", 1)
    if len(parts) != 2 or not parts[0].strip() or not parts[1].strip():
        raise ValueError(
            "pattern must be 'METHOD /path' (e.g. 'POST /v1/charges/{id}'), "
            f"got: {pattern!r}"
        )
    method, path = parts[0].strip().upper(), parts[1].strip()

    params: dict = {"method": method, "path": path}
    if distinct is not None:
        params["distinct"] = distinct
    if limit is not None:
        params["limit"] = str(limit)

    endpoint = url.rstrip("/") + "/v1/fixtures?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {key}"},
        method="GET",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"StubSmith API returned HTTP {exc.code}: {body}"
        ) from exc

    return FixtureBundle(data)


def fixtures(
    pattern: str,
    *,
    api_url: Optional[str] = None,
    api_key: Optional[str] = None,
    distinct: Optional[str] = None,
    limit: Optional[int] = None,
) -> List[Fixture]:
    """
    Fetch recorded fixture captures for a request type pattern.

    Parameters
    ----------
    pattern:
        A string of the form ``"METHOD /path/pattern"`` - for example
        ``"POST /v1/charges/{id}"`` or ``"GET /v1/users"``.  The method and
        path are split on the first space.

        The path is forwarded to the API as-is and resolved server-side by
        comparing it against stored ``path_pattern`` values using a
        segment-level matcher (see ``backend/src/fixtures.js``): ``{param}``
        tokens in the *stored* pattern act as wildcards, so passing the pattern
        string ``/v1/charges/{id}`` will correctly resolve a configured request
        type with that same path pattern.

        **Limitation:** an unrecognised pattern returns an empty list rather
        than an error.  The server resolves a request type by comparing the
        supplied path against stored ``path_pattern`` values using the
        segment-level ``segmentMatch`` function: ``{param}`` tokens in the
        *stored* pattern act as wildcards, so passing ``/v1/charges/{id}``
        resolves correctly against a configured type with that pattern.  If no
        request type resolves, the server falls back to exact path equality
        against capture records.  Because the SDK templates numeric, UUID, and
        16+-hex segments before storage (see ``stubsmith/privacy/templating.py``),
        captures for those routes are stored at the templated path (e.g.
        ``/v1/charges/{id}``), so querying with the templated form still finds
        them.  Always configure your request types (with a ``path_pattern``) to
        receive structured ``request_type`` metadata; without a configured type
        the ``request_type`` in the bundle is ``None``.

    api_url:
        Base URL of the StubSmith API (no trailing slash).  Defaults to the
        ``STUBSMITH_API_URL`` environment variable, then
        ``https://app.stubsmith.dev/api``.

        Note: the fixtures-testing example uses ``STUBSMITH_BACKEND_URL`` for
        the same value; that name is non-authoritative and kept for compatibility.
        ``STUBSMITH_API_URL`` is the SDK's canonical variable.
    api_key:
        Bearer token (project API key).  Defaults to the ``STUBSMITH_API_KEY``
        environment variable.  A :exc:`RuntimeError` is raised when no key is
        available.
    distinct:
        Pass ``"status"`` to receive at most one fixture per distinct HTTP
        status code (newest-first).
    limit:
        Maximum number of fixtures to return (1-100).  Server default is 20.

    Returns
    -------
    list[Fixture]
        Fixture objects ordered newest-first.

    Raises
    ------
    RuntimeError
        When the API key is missing or the server returns a non-2xx response.
    ValueError
        When *pattern* cannot be split into method and path.
    """
    return fixtures_bundle(
        pattern,
        api_url=api_url,
        api_key=api_key,
        distinct=distinct,
        limit=limit,
    ).fixtures
