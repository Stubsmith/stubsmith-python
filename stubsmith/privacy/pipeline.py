"""
PrivacyPipeline - edge-agent orchestrator.

:meth:`PrivacyPipeline.process` is the single entry-point called by the
instrumentation layer for every captured request/response pair.  It:

1. Replaces image bodies with canonical 1×1 placeholders before any other
   processing (real pixel data / EXIF metadata must never leave the edge).
2. Templates the URL path and computes the endpoint_id.
3. Looks up per-endpoint value-discriminator paths from the
   :class:`~stubsmith.privacy.rules_cache.RulesCache`.
4. Fingerprints the (post-image-replacement) request and response bodies,
   optionally folding configured scalar values into the request fingerprint.
5. Looks up the :class:`~stubsmith.privacy.rules_cache.RulesCache` for a
   matching set of compiled field rules.
6. Applies masking:
   - Known fingerprint → :func:`~stubsmith.privacy.field_rules.apply_field_rules`
     (or :func:`~stubsmith.privacy.masking.mask_known` in legacy mode).
   - Unknown fingerprint → :func:`~stubsmith.privacy.masking.mask_all`
     (fail-closed) + ``novel=True``.
7. (Bodies are never truncated. A body is recorded faithfully or not at all;
   see :meth:`PrivacyPipeline.build_payload`.) Historically truncated to
   *max_body_bytes* **after** masking (fingerprint is on
   the pre-truncation body).
8. Assembles and returns the canonical wire-format payload dict, including
   four path-name arrays (names only, never values) for paths-only review.

Fail-closed contract
---------------------
- Any error inside the masking phase degrades to ``mask_all`` + ``novel=True``.
- Any more catastrophic failure (URL parse, unexpected exception) causes
  ``process()`` to return ``None``; the client silently drops the capture
  rather than sending raw data.
- ``process()`` never raises.
"""

from __future__ import annotations

import base64
import urllib.parse
import logging
from typing import Any, Dict, List, Optional, Tuple

from .binary import is_image, placeholder_for
from .field_rules import CompiledFieldRules, apply_field_rules, apply_resp_field_rules
from .fingerprint import extract_keypaths, extract_value_types, fingerprint, resp_fingerprint, unique_query_names
from .masking import CompiledRules, mask_all, mask_known
from .rules_cache import RulesCache
from .templating import template_path
from .._version import __version__

logger = logging.getLogger("stubsmith")

_SDK_VERSION = __version__
_MAX_BODY_BYTES_DEFAULT = 64 * 1024   # 64 KiB


class PrivacyPipeline:
    """Orchestrates the full edge-privacy processing for one captured exchange.

    Parameters
    ----------
    rules_cache:
        A :class:`~stubsmith.privacy.rules_cache.RulesCache` instance (already
        started).
    max_body_bytes:
        Retained for compatibility and no longer truncates anything. Bodies are
        recorded whole or omitted whole; the size decision is made against
        *max_payload_bytes* on the assembled payload. Historically masked bodies
        were truncated to this many bytes before being placed in
        the outbound payload.  ``0`` disables truncation.
    sdk_version:
        Override the ``sdk_version`` field in every payload.  Defaults to the
        current package version string.
    """

    def __init__(
        self,
        rules_cache: RulesCache,
        max_body_bytes: int = _MAX_BODY_BYTES_DEFAULT,
        sdk_version: str = _SDK_VERSION,
    ) -> None:
        self._cache = rules_cache
        self._max_body_bytes = max_body_bytes
        self._sdk_version = sdk_version

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def process(
        self,
        method: str,
        raw_url: str,
        req_headers: Dict[str, Any],
        req_body: str,
        resp_status: int,
        resp_headers: Dict[str, Any],
        resp_body: str,
    ) -> Optional[Dict[str, Any]]:
        """Process one captured exchange and return a privacy-safe payload.

        Parameters
        ----------
        method:
            HTTP method (any case; normalised to upper-case internally).
        raw_url:
            Full outbound URL including scheme, host, path, and query string.
        req_headers:
            Dict of request header name → value.
        req_body:
            Raw request body string (may be empty).
        resp_status:
            HTTP response status code.
        resp_headers:
            Dict of response header name → value.
        resp_body:
            Raw response body string (may be empty).

        Returns
        -------
        dict
            Privacy-processed canonical wire-format payload, ready to be
            JSON-serialised and POSTed to the ingest endpoint.
        None
            Returned only on catastrophic failure; the caller should drop this
            capture silently rather than sending raw data.
        """
        try:
            return self._process_inner(
                method, raw_url, req_headers, req_body,
                resp_status, resp_headers, resp_body,
            )
        except Exception as exc:
            logger.debug("stubsmith pipeline catastrophic failure: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Internal implementation
    # ------------------------------------------------------------------

    def _process_inner(
        self,
        method: str,
        raw_url: str,
        req_headers: Dict[str, Any],
        req_body: str,
        resp_status: int,
        resp_headers: Dict[str, Any],
        resp_body: str,
    ) -> Dict[str, Any]:
        method_upper = method.upper()

        # -- 1. Parse URL -----------------------------------------------
        parsed = urllib.parse.urlparse(raw_url)
        domain = parsed.netloc or ""
        path = parsed.path or "/"
        query_string = parsed.query or ""

        # -- 2. Resolve content-types -----------------------------------
        req_ct = _get_header(req_headers, "content-type", "")
        resp_ct = _get_header(resp_headers, "content-type", "")

        # -- 3. Image body replacement (must happen before fingerprinting) --
        req_body, req_body_encoding = _maybe_replace_image(req_body, req_ct)
        resp_body, resp_body_encoding = _maybe_replace_image(resp_body, resp_ct)

        # -- 4. Path template -------------------------------------------
        curated = self._cache.get_curated_templates()
        path_template = template_path(path, curated)
        endpoint_id = f"{domain}|{method_upper}|{path_template}"

        # -- 5. Value-discriminator paths (per endpoint, from sync) -----
        value_paths = self._cache.get_value_paths(endpoint_id) or None

        # -- 6. Fingerprint and key-paths (on post-image, pre-truncation bodies) --
        req_fp = fingerprint(req_body, query_string, req_ct, value_paths=value_paths)
        resp_fp = resp_fingerprint(resp_status, resp_body, query_string, resp_ct)
        key_paths = extract_keypaths(req_body, req_ct)
        resp_key_paths = extract_keypaths(resp_body, resp_ct)
        # Observed value types: classified from raw values at the edge, before masking.
        # A type label is not a value - sending the type name does not erode the
        # paths-only invariant.  Only recognizable formats are classified (uuid, email,
        # iso8601, …); character composition is never inspected, so the label carries no
        # content-derived metadata beyond the format itself.
        req_value_types = extract_value_types(req_body, req_ct)
        resp_value_types = extract_value_types(resp_body, resp_ct)
        req_header_names = sorted(k.lower() for k in req_headers)
        resp_header_names = sorted(k.lower() for k in resp_headers)
        query_names = unique_query_names(query_string)

        # -- 7. Lookup rules cache --------------------------------------
        lookup = self._cache.lookup(endpoint_id, req_fp)

        # -- 8. Masking (wrapped for fail-closed degradation) -----------
        try:
            mb, mh, mq, resp_mb, resp_mh, novel = self._apply_masking(
                lookup, req_body, req_headers, query_string, req_ct,
                resp_body, resp_headers, resp_ct, resp_status,
            )
        except Exception as exc:
            logger.debug("stubsmith pipeline masking error (degrading): %s", exc)
            novel = True
            try:
                mb, mh, mq = mask_all(req_body, req_headers, query_string, req_ct)
                resp_mb, resp_mh, _ = mask_all(resp_body, resp_headers, "", resp_ct)
            except Exception:
                raise  # catastrophic - outer handler returns None

        # -- 9. Image placeholder bodies must not be further masked --------
        # After replacement, the body is a base64 string (the placeholder).
        # Masking passes (mask_all / apply_field_rules) would treat it as
        # opaque non-JSON text and replace it with "<masked>".  Restore the
        # placeholder so the encoding + original bytes are preserved.
        if req_body_encoding:
            mb = req_body   # req_body is already the base64 placeholder
        if resp_body_encoding:
            resp_mb = resp_body  # same for response

        # -- 10. Truncate bodies (after masking, after placeholder restore) --
        # Bodies are passed through whole.
        #
        # This used to truncate to max_body_bytes, which for JSON meant slicing
        # mid-token and storing a document that cannot parse, with nothing in
        # the payload to say so. A truncated capture was indistinguishable from
        # an API that had genuinely returned malformed JSON, so a replayed
        # sample raised JSONDecodeError and consumers attributed it upstream.
        #
        # There is no byte count at which a JSON document is still a JSON
        # document, so the size question is answered at the payload level in
        # client.enqueue(): under the ceiling the capture is sent whole, over it
        # the bodies are dropped together and the omission is declared. Never a
        # mutilated middle.
        mb_out = mb
        resp_mb_out = resp_mb

        # -- 11. Assemble payload ---------------------------------------
        cursor = self._cache.get_cursor()
        masked_path = path_template + (f"?{mq}" if mq else "")
        payload: Dict[str, Any] = {
            "sdk_version": self._sdk_version,
            "sdk_masked": True,
            "sdk_rule_version": cursor,
            "domain": domain,
            "path_template": path_template,
            "path": masked_path,
            "method": method_upper,
            "status": resp_status,
            "req_fingerprint": req_fp,
            "resp_fingerprint": resp_fp,
            "key_paths": key_paths,
            "resp_key_paths": resp_key_paths,
            "req_header_names": req_header_names,
            "resp_header_names": resp_header_names,
            "query_names": query_names,
            "headers": mh,
            "req_body": mb_out,
            "resp_headers": resp_mh,
            "resp_body": resp_mb_out,
            "novel": novel,
        }
        if req_body_encoding:
            payload["req_body_encoding"] = req_body_encoding
        if resp_body_encoding:
            payload["resp_body_encoding"] = resp_body_encoding
        # Path names only - values are never sent cleartext.
        if value_paths:
            payload["fingerprint_value_paths"] = value_paths
        # Observed value types: omit keys entirely when empty (no structured body
        # or all scalars were booleans/nulls), matching the optional-field pattern
        # used by fingerprint_value_paths and req_body_encoding above.
        if req_value_types:
            payload["req_value_types"] = req_value_types
        if resp_value_types:
            payload["resp_value_types"] = resp_value_types

        return payload

    # ------------------------------------------------------------------
    # Masking dispatch
    # ------------------------------------------------------------------

    def _apply_masking(
        self,
        lookup: Any,
        req_body: str,
        req_headers: Dict[str, Any],
        query_string: str,
        req_ct: str,
        resp_body: str,
        resp_headers: Dict[str, Any],
        resp_ct: str,
        resp_status: int,
    ) -> Tuple[str, Dict[str, Any], str, str, Dict[str, Any], bool]:
        """Return (mb, mh, mq, resp_mb, resp_mh, novel)."""
        if lookup is None:
            # Unknown fingerprint → fail-closed
            novel = True
            mb, mh, mq = mask_all(req_body, req_headers, query_string, req_ct)
            resp_mb, resp_mh, _ = mask_all(resp_body, resp_headers, "", resp_ct)
        elif isinstance(lookup, CompiledRules):
            # Legacy mode - mask_known with global project rules
            novel = False
            mb, mh, mq = mask_known(req_body, req_headers, query_string, req_ct, lookup)
            resp_mb, resp_mh, _ = mask_known(resp_body, resp_headers, "", resp_ct, lookup)
        elif isinstance(lookup, CompiledFieldRules):
            # Modern mode - per-fingerprint field rules.
            # Pass synced project defaults as the belt-and-suspenders regex
            # source so the backend's custom patterns are honoured on kept
            # strings; falls back to field_rules._EMBEDDED_REGEX_MASKS when
            # no project_defaults have been synced yet (returns None).
            novel = False
            project_defaults = self._cache.get_project_defaults()
            email_domain = self._cache.get_email_placeholder_domain()
            mb, mh, mq = apply_field_rules(
                req_body, req_headers, query_string, req_ct, lookup,
                extra_rules=project_defaults,
                email_domain=email_domain,
            )
            # Response body uses keep_resp (not keep_body) - identical
            # fail-closed semantics: every response scalar masked unless its
            # response-body-relative path is explicitly kept via resp. rules.
            # resp_status is threaded through so that status-scoped rules
            # (resp:NNN. and resp_header:NNN.) are resolved for this response.
            resp_mb, resp_mh = apply_resp_field_rules(
                resp_body, resp_headers, resp_ct, lookup,
                extra_rules=project_defaults,
                resp_status=resp_status,
                email_domain=email_domain,
            )
        else:
            # Unknown return type from cache - treat as unknown, fail-closed
            novel = True
            mb, mh, mq = mask_all(req_body, req_headers, query_string, req_ct)
            resp_mb, resp_mh, _ = mask_all(resp_body, resp_headers, "", resp_ct)

        return mb, mh, mq, resp_mb, resp_mh, novel

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def body_exceeds(self, s: str) -> bool:
        """Report whether *s* is larger than *max_body_bytes*.

        Reports; never modifies. Replaces the former ``_truncate``, which
        sliced bytes and returned a document that could not parse.
        """
        if not s or self._max_body_bytes <= 0:
            return False
        return len(s.encode("utf-8", errors="replace")) > self._max_body_bytes


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _get_header(headers: Dict[str, Any], name: str, default: str = "") -> str:
    """Case-insensitive header lookup."""
    for k, v in headers.items():
        if k.lower() == name.lower():
            return str(v)
    return default


def _maybe_replace_image(
    body: str, content_type: str
) -> Tuple[str, Optional[str]]:
    """Replace image body with base64-encoded 1×1 placeholder.

    Returns
    -------
    tuple[str, str | None]
        ``(body_string, encoding_flag)`` where ``encoding_flag`` is
        ``"base64"`` when replacement occurred, else ``None``.
    """
    if is_image(content_type):
        placeholder_bytes, _ = placeholder_for(content_type)
        return base64.b64encode(placeholder_bytes).decode("ascii"), "base64"
    return body, None
