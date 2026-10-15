"""
Background rules cache - polls ``GET /v1/sdk/sync`` and maintains a
thread-safe mapping of ``(endpoint_id, fingerprint)`` → compiled field rules.

Endpoint ID
-----------
``{domain}|{METHOD}|{path_template}`` - composed from the ``request_type``
object returned by the sync endpoint.

Sync not found (404)
--------------------
A 404 from ``/v1/sdk/sync`` almost always means ``backend_url`` points at the
wrong host or path.  The cache does not fall back to any other rules source:
it keeps whatever rules it already holds, so an unknown fingerprint still
misses and the pipeline masks every value (fail closed).  One WARNING naming
the 404 and the configured ``backend_url`` is logged per cache.

Network errors
--------------
On any network-level error (timeout, connection refused, unexpected exception)
the previous cache is kept and a DEBUG-level log entry is written.  No
exception propagates to the background thread caller.

Test injection
--------------
Override :meth:`RulesCache._http_get` to inject fake responses without a
real HTTP server::

    class FakeCache(RulesCache):
        def _http_get(self, url):
            if "sync" in url:
                return 200, {"ok": True, "cursor": "1", "rules": [...], ...}
            return 404, None
"""

from __future__ import annotations

import json
import logging
import threading
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional, Tuple

from .._version import __version__
from .field_rules import CompiledFieldRules, compile_field_rules
from .masking import CompiledRules, compile_rules
from .templating import CuratedTemplate, load_curated_templates

_SDK_USER_AGENT = f"stubsmith-sdk/{__version__}"

logger = logging.getLogger("stubsmith")

# Stored when the synced project_defaults cannot be used at all: no field or
# regex masks, and every kept string is masked.
_UNUSABLE_PROJECT_RULES = CompiledRules(field_masks=frozenset(), regex_masks=(), unusable=True)

_SYNC_TIMEOUT = 10   # seconds for each HTTP request in the poll loop


class RulesCache:
    """Thread-safe, background-polling rules cache.

    Parameters
    ----------
    api_key:
        Bearer token sent in ``Authorization`` headers.
    backend_url:
        Base URL of the backend including any path prefix required by the
        server (no trailing slash).  The sync path ``/v1/sdk/sync`` is
        appended directly, so this must be the full base up to that prefix.
        Examples: ``https://app.stubsmith.dev/api`` (hosted service),
        ``http://localhost:3000`` (local dev without a prefix).
    poll_interval:
        Seconds between sync polls (float).  Default ``60.0``.
    """

    def __init__(
        self,
        api_key: str,
        backend_url: str,
        poll_interval: float = 60.0,
        debug: bool = False,
    ) -> None:
        self._api_key = api_key
        self._backend_url = backend_url.rstrip("/")
        self._poll_interval = poll_interval
        self._debug = debug

        # Protected by _lock
        self._lock = threading.RLock()
        # (endpoint_id, fingerprint) → CompiledFieldRules
        self._rules: Dict[Tuple[str, str], CompiledFieldRules] = {}
        self._sync_404_warned: bool = False
        self._cursor: str = "0"
        # Synced project-level defaults (merged enabled named sets from backend)
        # None until the first successful sync that includes project_defaults.
        self._project_defaults: Optional[CompiledRules] = None
        # Email placeholder domain for format-preserving email generation.
        # Defaults to "stub.invalid".
        self._email_placeholder_domain: str = "stub.invalid"
        self._curated_templates: List[CuratedTemplate] = []
        # The project's "Group IDs in paths automatically" setting, from
        # project_settings in the sync response.  On until a sync says otherwise,
        # which is the behaviour from before the setting existed.
        self._group_ids_in_paths: bool = True
        # Per-endpoint value-discriminator paths (keyed by endpoint_id).
        # Full replacement on every sync response that includes the key.
        self._value_config: Dict[str, List[str]] = {}

        # Set once after the first successful _apply_sync_response call.
        # Used by wait_for_first_sync() to block short capture scripts until
        # field rules are loaded.  Never cleared once set.
        self._first_sync_done = threading.Event()

        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background poll thread (idempotent)."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._poll_loop,
                daemon=True,
                name="stubsmith-rules-cache",
            )
            self._thread.start()

    def stop(self) -> None:
        """Signal the poll thread to stop (idempotent, non-blocking)."""
        self._stop.set()

    # ------------------------------------------------------------------
    # Query interface
    # ------------------------------------------------------------------

    def lookup(
        self, endpoint_id: str, fp: str
    ) -> Optional[CompiledFieldRules]:
        """Look up compiled rules for *(endpoint_id, fp)*.

        Returns
        -------
        None
            Unknown fingerprint → novel request; caller should use
            :func:`~stubsmith.privacy.masking.mask_all`.
        CompiledFieldRules
            Cloud-synced per-fingerprint field rules; caller should use
            :func:`~stubsmith.privacy.field_rules.apply_field_rules`.
        """
        with self._lock:
            return self._rules.get((endpoint_id, fp))

    def get_curated_templates(self) -> List[CuratedTemplate]:
        """Return the current curated path templates (snapshot)."""
        with self._lock:
            return list(self._curated_templates)

    def get_project_defaults(self) -> Optional[CompiledRules]:
        """Return the project-level default masking rules from the last sync.

        Returns ``None`` when no sync has delivered ``project_defaults`` with
        at least one rule.
        """
        with self._lock:
            return self._project_defaults

    def get_email_placeholder_domain(self) -> str:
        """Return the email placeholder domain synced from the backend.

        Defaults to ``"stub.invalid"`` until a sync response provides
        ``project_defaults.email_placeholder_domain``.  The SDK uses it when
        generating format-preserving email addresses.
        """
        with self._lock:
            return self._email_placeholder_domain

    def get_group_ids_in_paths(self) -> bool:
        """Return whether path segments that look like IDs become ``{id}``.

        True until a sync response sets ``project_settings.group_ids_in_paths``
        to false.  When false, only curated templates group paths.
        """
        with self._lock:
            return self._group_ids_in_paths

    def get_value_paths(self, endpoint_id: str) -> List[str]:
        """Return the configured value-discriminator paths for *endpoint_id*.

        Returns an empty list when no paths are configured for this endpoint.
        Thread-safe snapshot - the caller may modify the returned list freely.
        """
        with self._lock:
            return list(self._value_config.get(endpoint_id, []))

    def get_cursor(self) -> str:
        """Return the current sync cursor value."""
        with self._lock:
            return self._cursor

    def wait_for_first_sync(self, timeout: float) -> bool:
        """Block until the first successful sync completes or *timeout* expires.

        Returns ``True`` when the sync completed within the timeout, ``False``
        when the timeout expired first.  Never raises.

        Intended for short capture scripts that finish before the background
        sync thread completes its first poll.  Long-running services do not
        need this because the cache has time to warm up before real traffic
        arrives.
        """
        try:
            return self._first_sync_done.wait(timeout=timeout)
        except Exception:
            return False

    # ------------------------------------------------------------------
    # HTTP helper (overridable for tests)
    # ------------------------------------------------------------------

    def _http_get(self, url: str) -> Tuple[int, Optional[Dict[str, Any]]]:
        """Perform a GET request with bearer auth.

        Returns
        -------
        tuple[int, dict | None]
            ``(status_code, parsed_json_body)`` where body is ``None`` on
            parse failure or non-2xx without a JSON body.  Status ``0``
            indicates a network-level error.

        This method is intentionally overridable so tests can inject fake
        responses without a real HTTP server.
        """
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "User-Agent": _SDK_USER_AGENT,
                },
            )
            with urllib.request.urlopen(req, timeout=_SYNC_TIMEOUT) as resp:
                raw = resp.read()
                content_type = resp.headers.get("content-type", "") if resp.headers else ""
                try:
                    return resp.status, json.loads(raw.decode("utf-8"))
                except Exception:
                    if self._debug:
                        if "text/html" in content_type:
                            logger.warning(
                                "stubsmith rules-cache: %s returned content-type %r "
                                "(not JSON). Is this the UI "
                                "host instead of the backend?",
                                url,
                                content_type,
                            )
                        else:
                            logger.warning(
                                "stubsmith rules-cache: %s returned non-JSON response "
                                "(content-type=%r status=%d)",
                                url,
                                content_type,
                                resp.status,
                            )
                    return resp.status, None
        except urllib.error.HTTPError as exc:
            try:
                content_type = (
                    exc.headers.get("content-type", "")
                    if exc.headers is not None
                    else ""
                )
                if self._debug:
                    if "text/html" in content_type:
                        logger.warning(
                            "stubsmith rules-cache: %s HTTP %d - response is not JSON "
                            "(content-type=%r) - is this the UI host instead of the backend?",
                            url,
                            exc.code,
                            content_type,
                        )
                    else:
                        logger.warning(
                            "stubsmith rules-cache: %s HTTP %d (%s)",
                            url,
                            exc.code,
                            exc.reason,
                        )
                return exc.code, None
            except Exception:
                return 0, None
        except Exception as exc:
            if self._debug:
                logger.warning(
                    "stubsmith rules-cache: network error fetching %s - %s: %s",
                    url,
                    type(exc).__name__,
                    exc,
                )
            else:
                logger.debug("stubsmith rules-cache network error: %s", exc)
            return 0, None

    # ------------------------------------------------------------------
    # Poll loop
    # ------------------------------------------------------------------

    def _poll_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._poll_once()
            except Exception as exc:
                logger.debug("stubsmith rules-cache poll error: %s", exc)
            self._stop.wait(timeout=self._poll_interval)

    def _poll_once(self) -> None:
        """One poll cycle: fetch sync and merge a successful response."""
        with self._lock:
            cursor = self._cursor

        sync_url = f"{self._backend_url}/v1/sdk/sync?cursor={cursor}"
        status, body = self._http_get(sync_url)

        if status == 404:
            self._warn_sync_not_found(sync_url)
            return

        if status == 0:
            # Network error - keep previous cache
            return

        if status != 200 or not isinstance(body, dict):
            if self._debug:
                logger.warning(
                    "stubsmith rules-cache: unexpected sync response status=%d url=%s",
                    status,
                    sync_url,
                )
            else:
                logger.debug(
                    "stubsmith rules-cache: unexpected sync response status=%d", status
                )
            return

        self._apply_sync_response(body)

    def _apply_sync_response(self, body: Dict[str, Any]) -> None:
        """Merge a successful sync response into the cache (under lock)."""
        new_cursor = str(body.get("cursor") or "0")
        rules_list = body.get("rules") or []
        path_templates_raw = body.get("path_templates") or []

        # Build incremental rules update
        additions: Dict[Tuple[str, str], CompiledFieldRules] = {}
        for rule in rules_list:
            if not isinstance(rule, dict):
                continue
            rt = rule.get("request_type") or {}
            domain = rt.get("domain") or ""
            method = (rt.get("method") or "").upper()
            path_template = rt.get("path_template") or ""
            fp = rule.get("fingerprint") or ""
            field_rules = rule.get("field_rules") or []
            if not fp:
                continue
            endpoint_id = f"{domain}|{method}|{path_template}"
            additions[(endpoint_id, fp)] = compile_field_rules(field_rules)

        curated = load_curated_templates(
            [t for t in path_templates_raw if isinstance(t, str)]
        )

        # project_defaults: merged enabled global rules served by the backend.
        # Present when the backend populates it (plan v2 delta 6); absent fields
        # are treated as empty lists so compile_rules gets well-typed inputs.
        # Two safety rules:
        #   (a) Empty result (no field masks, no regex masks, nothing unusable)
        #       → store None, which apply_field_rules treats the same way.  A
        #       set whose only pattern failed to compile is NOT empty: it is
        #       stored so that every kept string is masked.
        #   (b) Malformed server data cannot abort the rest of
        #       _apply_sync_response and block cursor/rules/template updates
        #       for that poll cycle.  It fails closed instead: project_defaults
        #       that are present but not an object, or that fail to compile,
        #       are stored as an unusable rule set, so every kept string is
        #       masked.  Absent or null project_defaults stay None.
        project_defaults: Optional[CompiledRules] = None
        new_email_domain: Optional[str] = None
        pd_raw = body.get("project_defaults")
        if pd_raw is not None and not isinstance(pd_raw, dict):
            logger.warning(
                "stubsmith: synced project_defaults is not an object; every kept "
                "string will be masked until a sync delivers valid rules"
            )
            project_defaults = _UNUSABLE_PROJECT_RULES
        if isinstance(pd_raw, dict):
            try:
                compiled_pd = compile_rules(
                    pd_raw.get("field_masks") or [],
                    pd_raw.get("regex_masks") or [],
                )
                # Only store when there is at least one rule, counting one that
                # failed to compile (see (a) above).
                if compiled_pd.field_masks or compiled_pd.regex_masks or compiled_pd.unusable:
                    project_defaults = compiled_pd
            except Exception as exc:
                logger.warning(
                    "stubsmith: synced project_defaults cannot be used (%s); every "
                    "kept string will be masked until a sync delivers valid rules",
                    exc,
                )
                project_defaults = _UNUSABLE_PROJECT_RULES
            # Extract email placeholder domain for format-preserving generation.
            # A non-empty string overrides the default; absent or empty keeps the
            # current value so a server that does not yet send the field is safe.
            raw_domain = pd_raw.get("email_placeholder_domain")
            if isinstance(raw_domain, str) and raw_domain:
                new_email_domain = raw_domain

        # project_settings: settings the SDK acts on.  A missing key or a
        # non-boolean value leaves the current setting as it is.
        new_group_ids: Optional[bool] = None
        ps_raw = body.get("project_settings")
        if isinstance(ps_raw, dict) and isinstance(ps_raw.get("group_ids_in_paths"), bool):
            new_group_ids = ps_raw["group_ids_in_paths"]

        # request_type_value_config: optional sparse map of endpoint_id → list of
        # body key-paths whose values should be folded into the request fingerprint.
        # Full replacement under lock on every sync response that contains the key
        # as a dict.  Non-string endpoint_ids and non-list / non-string path entries
        # are skipped defensively.
        new_value_config: Optional[Dict[str, List[str]]] = None
        vc_raw = body.get("request_type_value_config")
        if isinstance(vc_raw, dict):
            built: Dict[str, List[str]] = {}
            for eid, paths in vc_raw.items():
                if not isinstance(eid, str):
                    continue
                if not isinstance(paths, list):
                    continue
                built[eid] = [p for p in paths if isinstance(p, str)]
            new_value_config = built

        with self._lock:
            if additions:
                new_rules = dict(self._rules)
                new_rules.update(additions)
                self._rules = new_rules  # atomic swap
            if new_cursor != "0":
                self._cursor = new_cursor
            self._curated_templates = curated
            if project_defaults is not None:
                self._project_defaults = project_defaults
            if new_email_domain is not None:
                self._email_placeholder_domain = new_email_domain
            if new_group_ids is not None:
                self._group_ids_in_paths = new_group_ids
            # Full replacement when the key was present (absent key → no change).
            if new_value_config is not None:
                self._value_config = new_value_config
            # A later 404 is a new outage, so it gets its own warning, worded
            # for the rules this sync just delivered.
            self._sync_404_warned = False

        # Signal after releasing the lock so waiters can acquire it immediately.
        self._first_sync_done.set()

    def _warn_sync_not_found(self, sync_url: str) -> None:
        """Log one WARNING for a 404 from sync.  Rules are left as they are.

        There is deliberately no fallback rules source here.  The old fallback
        to ``/v1/anonymizer/rules`` treated every request as known and masked
        only named fields, so a mistyped ``backend_url`` sent bodies and query
        values in cleartext.  Without synced rules every lookup misses and the
        pipeline masks everything.
        """
        with self._lock:
            if self._sync_404_warned:
                return
            self._sync_404_warned = True
        # After an earlier successful sync the cached rules are real and stay
        # in use, so saying "every value is masked" would be wrong: only
        # traffic those rules do not cover is masked in full.
        if self._first_sync_done.is_set():
            consequence = (
                "Rules from the last successful sync stay in effect; anything they "
                "do not cover is masked in full until sync succeeds again."
            )
        else:
            consequence = "Every captured value is masked until sync succeeds."
        logger.warning(
            "stubsmith: rules sync returned HTTP 404 from %s - check backend_url "
            "(configured: %r). %s",
            sync_url,
            self._backend_url,
            consequence,
        )
