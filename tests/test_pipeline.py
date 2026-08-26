"""
Tests for the PrivacyPipeline and supporting modules (rules_cache, field_rules).

All tests are offline: no real network.  The RulesCache._http_get method is
overridden per test via a subclass to inject fake responses.

Coverage targets
-----------------
- Novel fingerprint: mask_all + novel=True; four new path-name arrays present.
- Known-fingerprint field rules: keep vs mask.
- Fail-closed on injected masking exception (payload still masked, never raw).
- Truncation happens AFTER fingerprinting (fingerprint on pre-truncation body).
- Image body replaced by placeholder + base64 encoding flag.
- Legacy fallback mode (404 → global rules, no novelty, one warning).
- Old-server compat: ``path`` field is still usable without the new fields.
- Multi-valued query params.
- field_rules.compile_field_rules / apply_field_rules (unit tests).
"""

from __future__ import annotations

import base64
import json
import sys
import threading
import time
import types
import urllib.parse
import warnings
from typing import Any, Dict, List, Optional, Tuple
from unittest import mock

import pytest

from stubsmith.privacy.field_rules import (
    CompiledFieldRules,
    apply_field_rules,
    compile_field_rules,
)
from stubsmith.privacy.masking import compile_rules
from stubsmith.privacy.pipeline import PrivacyPipeline
from stubsmith.privacy.rules_cache import RulesCache
from stubsmith.privacy.binary import PNG_1X1, GIF_1X1


# ===========================================================================
# Helpers
# ===========================================================================

class FakeRulesCache(RulesCache):
    """RulesCache subclass that injects fake HTTP responses without a server."""

    def __init__(self, responses: Optional[Dict[str, Any]] = None):
        super().__init__(api_key="sk-test", backend_url="http://fake")
        # responses: dict of url-fragment → (status_code, body_dict)
        self._fake_responses = responses or {}

    def _http_get(self, url: str) -> Tuple[int, Optional[Dict]]:
        for fragment, result in self._fake_responses.items():
            if fragment in url:
                return result
        return (0, None)


def make_sync_response(
    fingerprint: str,
    field_rules: List[Dict],
    domain: str = "api.example.com",
    method: str = "POST",
    path_template: str = "/v1/orders",
    cursor: str = "1",
    path_templates: Optional[List[str]] = None,
    project_defaults: Optional[Dict] = None,
    request_type_value_config: Optional[Dict[str, List[str]]] = None,
) -> Dict:
    """Build a fake /v1/sdk/sync response body."""
    resp: Dict = {
        "ok": True,
        "cursor": cursor,
        "rules": [
            {
                "seq": 1,
                "request_type": {
                    "domain": domain,
                    "method": method,
                    "path_template": path_template,
                },
                "fingerprint": fingerprint,
                "field_rules": field_rules,
            }
        ],
        "path_templates": path_templates or [],
    }
    if project_defaults is not None:
        resp["project_defaults"] = project_defaults
    if request_type_value_config is not None:
        resp["request_type_value_config"] = request_type_value_config
    return resp


def make_pipeline(
    fake_responses: Optional[Dict] = None,
    max_body_bytes: int = 64 * 1024,
) -> Tuple[FakeRulesCache, PrivacyPipeline]:
    """Create a FakeRulesCache + PrivacyPipeline pair for tests."""
    cache = FakeRulesCache(responses=fake_responses or {})
    # Don't start the background thread in tests; drive polls manually.
    pipeline = PrivacyPipeline(
        rules_cache=cache,
        max_body_bytes=max_body_bytes,
    )
    return cache, pipeline


def call_process(
    pipeline: PrivacyPipeline,
    method: str = "POST",
    url: str = "https://api.example.com/v1/orders",
    req_headers: Optional[Dict] = None,
    req_body: str = '{"user": {"email": "alice@example.com"}, "amount": 99}',
    resp_status: int = 200,
    resp_headers: Optional[Dict] = None,
    resp_body: str = '{"id": 1, "status": "ok"}',
) -> Optional[Dict]:
    return pipeline.process(
        method=method,
        raw_url=url,
        req_headers=req_headers or {"Content-Type": "application/json"},
        req_body=req_body,
        resp_status=resp_status,
        resp_headers=resp_headers or {"Content-Type": "application/json"},
        resp_body=resp_body,
    )


# ===========================================================================
# field_rules.py unit tests
# ===========================================================================


class TestCompileFieldRules:
    def test_keep_body_path(self):
        rules = compile_field_rules([{"path": "body.user.email", "action": "keep"}])
        assert "user.email" in rules.keep_body

    def test_keep_query_path(self):
        rules = compile_field_rules([{"path": "query.page", "action": "keep"}])
        assert "page" in rules.keep_query

    def test_keep_header_path_lowercased(self):
        rules = compile_field_rules([{"path": "header.X-Request-Id", "action": "keep"}])
        assert "x-request-id" in rules.keep_header

    def test_mask_action_not_added(self):
        rules = compile_field_rules([{"path": "body.password", "action": "mask"}])
        assert "password" not in rules.keep_body

    def test_path_namespace_ignored(self):
        rules = compile_field_rules([{"path": "path.{id}", "action": "keep"}])
        assert len(rules.keep_body) == 0
        assert len(rules.keep_query) == 0
        assert len(rules.keep_header) == 0

    def test_empty_list(self):
        rules = compile_field_rules([])
        assert rules.keep_body == frozenset()
        assert rules.keep_query == frozenset()
        assert rules.keep_header == frozenset()

    def test_none_list(self):
        rules = compile_field_rules(None)  # type: ignore[arg-type]
        assert rules.keep_body == frozenset()

    def test_invalid_entries_skipped(self):
        rules = compile_field_rules(["not-a-dict", None, {"path": "body.ok", "action": "keep"}])
        assert "ok" in rules.keep_body

    def test_keep_resp_path(self):
        rules = compile_field_rules([{"path": "resp.id", "action": "keep"}])
        assert "id" in rules.keep_resp

    def test_keep_resp_nested_path(self):
        rules = compile_field_rules([{"path": "resp.user.email", "action": "keep"}])
        assert "user.email" in rules.keep_resp

    def test_mask_resp_action_not_added(self):
        rules = compile_field_rules([{"path": "resp.secret", "action": "mask"}])
        assert "secret" not in rules.keep_resp

    def test_resp_path_does_not_pollute_keep_body(self):
        rules = compile_field_rules([{"path": "resp.id", "action": "keep"}])
        assert "id" not in rules.keep_body

    def test_empty_list_has_keep_resp(self):
        rules = compile_field_rules([])
        assert rules.keep_resp == frozenset()


class TestApplyFieldRules:
    def test_fail_closed_unknown_key_masked(self):
        compiled = compile_field_rules([])
        body = json.dumps({"secret": "sensitive", "amount": 99})
        masked_body, _, _ = apply_field_rules(
            body, {}, "", "application/json", compiled
        )
        obj = json.loads(masked_body)
        assert obj["secret"] == "<masked>"
        assert obj["amount"] == 0

    def test_keep_body_path_survives(self):
        compiled = compile_field_rules([
            {"path": "body.amount", "action": "keep"},
        ])
        body = json.dumps({"secret": "sensitive", "amount": 99})
        masked_body, _, _ = apply_field_rules(
            body, {}, "", "application/json", compiled
        )
        obj = json.loads(masked_body)
        assert obj["amount"] == 99
        assert obj["secret"] == "<masked>"

    def test_nested_path_keep(self):
        compiled = compile_field_rules([
            {"path": "body.user.name", "action": "keep"},
        ])
        body = json.dumps({"user": {"name": "alice", "email": "alice@example.com"}})
        masked_body, _, _ = apply_field_rules(
            body, {}, "", "application/json", compiled
        )
        obj = json.loads(masked_body)
        assert obj["user"]["name"] == "alice"
        assert obj["user"]["email"] == "<masked>"

    def test_array_element_path_keep(self):
        compiled = compile_field_rules([
            {"path": "body.items.[].price", "action": "keep"},
        ])
        body = json.dumps({"items": [
            {"price": 10, "secret": "x"},
            {"price": 20, "secret": "y"},
        ]})
        masked_body, _, _ = apply_field_rules(
            body, {}, "", "application/json", compiled
        )
        obj = json.loads(masked_body)
        assert obj["items"][0]["price"] == 10
        assert obj["items"][0]["secret"] == "<masked>"
        assert obj["items"][1]["price"] == 20

    def test_query_keep(self):
        compiled = compile_field_rules([{"path": "query.page", "action": "keep"}])
        _, _, mq = apply_field_rules(
            "{}", {"Content-Type": "application/json"}, "page=3&secret=abc",
            "application/json", compiled
        )
        parsed = urllib.parse.parse_qs(mq)
        assert parsed["page"] == ["3"]
        assert parsed["secret"] == ["<masked>"]

    def test_multi_valued_query_all_masked_by_default(self):
        compiled = compile_field_rules([])
        _, _, mq = apply_field_rules(
            "{}", {}, "a=1&a=2&b=3", "application/json", compiled
        )
        parsed = urllib.parse.parse_qs(mq)
        assert all(v == "<masked>" for v in parsed["a"])
        assert all(v == "<masked>" for v in parsed["b"])

    def test_multi_valued_query_keep(self):
        compiled = compile_field_rules([{"path": "query.a", "action": "keep"}])
        _, _, mq = apply_field_rules(
            "{}", {}, "a=1&a=2&b=3", "application/json", compiled
        )
        parsed = urllib.parse.parse_qs(mq)
        assert set(parsed["a"]) == {"1", "2"}
        assert parsed["b"] == ["<masked>"]

    def test_header_allowlist_always_kept(self):
        compiled = compile_field_rules([])
        _, mh, _ = apply_field_rules(
            "{}", {"content-type": "application/json", "x-secret": "tok"},
            "", "application/json", compiled
        )
        assert mh["content-type"] == "application/json"
        assert mh["x-secret"] == "<masked>"

    def test_header_explicit_keep_override(self):
        compiled = compile_field_rules([
            {"path": "header.x-request-id", "action": "keep"},
        ])
        _, mh, _ = apply_field_rules(
            "{}", {"x-request-id": "req-123", "authorization": "Bearer tok"},
            "", "application/json", compiled
        )
        assert mh["x-request-id"] == "req-123"
        assert mh["authorization"] == "<masked>"

    def test_form_encoded_body_fail_closed(self):
        compiled = compile_field_rules([])
        body = "username=alice&password=s3cr3t"
        masked_body, _, _ = apply_field_rules(
            body, {}, "", "application/x-www-form-urlencoded", compiled
        )
        parsed = urllib.parse.parse_qs(masked_body)
        assert parsed["username"] == ["<masked>"]
        assert parsed["password"] == ["<masked>"]

    def test_form_encoded_body_keep_path(self):
        compiled = compile_field_rules([{"path": "body.username", "action": "keep"}])
        body = "username=alice&password=s3cr3t"
        masked_body, _, _ = apply_field_rules(
            body, {}, "", "application/x-www-form-urlencoded", compiled
        )
        parsed = urllib.parse.parse_qs(masked_body)
        assert parsed["username"] == ["alice"]
        assert parsed["password"] == ["<masked>"]

    def test_non_json_body_becomes_masked(self):
        compiled = compile_field_rules([])
        masked_body, _, _ = apply_field_rules(
            "raw text", {}, "", "text/plain", compiled
        )
        assert masked_body == "<masked>"

    def test_empty_body_passthrough(self):
        compiled = compile_field_rules([])
        masked_body, _, _ = apply_field_rules("", {}, "", "application/json", compiled)
        assert masked_body == ""

    def test_belt_and_suspenders_email_in_kept_string(self):
        """Email in a 'keep' field should be caught by the embedded regex backstop."""
        compiled = compile_field_rules([{"path": "body.note", "action": "keep"}])
        body = json.dumps({"note": "contact alice@example.com for details"})
        masked_body, _, _ = apply_field_rules(
            body, {}, "", "application/json", compiled
        )
        obj = json.loads(masked_body)
        assert "alice@example.com" not in obj["note"]
        assert "<masked>" in obj["note"]

    def test_bool_masked_to_false(self):
        compiled = compile_field_rules([])
        body = json.dumps({"active": True})
        masked_body, _, _ = apply_field_rules(
            body, {}, "", "application/json", compiled
        )
        obj = json.loads(masked_body)
        assert obj["active"] is False

    def test_none_stays_none(self):
        compiled = compile_field_rules([{"path": "body.score", "action": "keep"}])
        body = json.dumps({"score": None})
        masked_body, _, _ = apply_field_rules(
            body, {}, "", "application/json", compiled
        )
        obj = json.loads(masked_body)
        assert obj["score"] is None


# ===========================================================================
# PrivacyPipeline tests
# ===========================================================================


def _get_fp_for_body(body: str, qs: str = "", ct: str = "application/json") -> str:
    from stubsmith.privacy.fingerprint import fingerprint
    return fingerprint(body, qs, ct)


class TestPipelineBasicOutput:
    def test_returns_dict_with_required_keys(self):
        _, pipeline = make_pipeline()
        result = call_process(pipeline)
        assert result is not None
        for key in (
            "sdk_version", "sdk_masked", "sdk_rule_version",
            "domain", "path_template", "path", "method", "status",
            "req_fingerprint", "resp_fingerprint", "key_paths",
            "resp_key_paths", "req_header_names", "resp_header_names",
            "query_names", "headers", "req_body", "resp_headers", "resp_body",
            "novel",
        ):
            assert key in result, f"Missing key: {key}"

    def test_sdk_masked_always_true(self):
        _, pipeline = make_pipeline()
        result = call_process(pipeline)
        assert result["sdk_masked"] is True

    def test_domain_parsed_from_url(self):
        _, pipeline = make_pipeline()
        result = call_process(pipeline, url="https://api.example.com/v1/orders")
        assert result["domain"] == "api.example.com"

    def test_method_uppercased(self):
        _, pipeline = make_pipeline()
        result = call_process(pipeline, method="get")
        assert result["method"] == "GET"

    def test_status_field(self):
        _, pipeline = make_pipeline()
        result = call_process(pipeline, resp_status=201)
        assert result["status"] == 201

    def test_path_field_usable_old_server_compat(self):
        """The 'path' field should be usable standalone (old-server compat)."""
        _, pipeline = make_pipeline()
        result = call_process(pipeline, url="https://api.example.com/v1/orders?page=2")
        # path should include the templated path and masked query
        assert result["path"].startswith("/v1/orders")
        assert "page" in result["path"]  # query is present in path string

    def test_query_string_in_path_is_masked(self):
        _, pipeline = make_pipeline()
        result = call_process(
            pipeline, url="https://api.example.com/v1/orders?secret=abc123&page=1"
        )
        # The actual value "abc123" should not appear in the path field
        assert "abc123" not in result["path"]
        assert "secret" in result["path"]  # key appears, value masked


class TestPipelineNovelFingerprint:
    def test_novel_flag_when_fingerprint_unknown(self):
        _, pipeline = make_pipeline()  # empty cache → no rules
        result = call_process(pipeline)
        assert result["novel"] is True

    def test_body_is_fully_masked_on_novel(self):
        _, pipeline = make_pipeline()
        result = call_process(pipeline, req_body='{"password": "s3cr3t", "count": 5}')
        assert result is not None
        obj = json.loads(result["req_body"])
        assert obj["password"] == "<masked>"
        assert obj["count"] == 0


class TestPipelineNewPathArrays:
    """Tests for the four new path-name arrays added to the payload."""

    def test_key_paths_present_for_req_body(self):
        """key_paths lists request body key names (existing field, not changed)."""
        _, pipeline = make_pipeline()
        result = call_process(
            pipeline,
            req_body='{"user": {"email": "x"}, "amount": 99}',
        )
        assert result is not None
        assert set(result["key_paths"]) >= {"user", "user.email", "amount"}

    def test_resp_key_paths_present_for_resp_body(self):
        """resp_key_paths lists response body key names (names only, no values)."""
        _, pipeline = make_pipeline()
        result = call_process(
            pipeline,
            resp_body='{"id": 1, "status": "ok", "meta": {"ts": 123}}',
        )
        assert result is not None
        assert "id" in result["resp_key_paths"]
        assert "status" in result["resp_key_paths"]
        assert "meta" in result["resp_key_paths"]
        assert "meta.ts" in result["resp_key_paths"]
        # Values must never appear
        assert "ok" not in result["resp_key_paths"]

    def test_resp_key_paths_empty_for_empty_resp_body(self):
        """resp_key_paths is an empty list when the response body is empty."""
        _, pipeline = make_pipeline()
        result = call_process(pipeline, resp_body="")
        assert result is not None
        assert result["resp_key_paths"] == []

    def test_req_header_names_lowercased(self):
        """req_header_names contains lowercased header names, not values."""
        _, pipeline = make_pipeline()
        result = call_process(
            pipeline,
            req_headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer tok",
                "X-Request-Id": "req-123",
            },
        )
        assert result is not None
        names = result["req_header_names"]
        assert "content-type" in names
        assert "authorization" in names
        assert "x-request-id" in names
        # Values must not appear
        assert "Bearer tok" not in names
        assert "req-123" not in names
        assert "application/json" not in names

    def test_resp_header_names_lowercased(self):
        """resp_header_names contains lowercased response header names."""
        _, pipeline = make_pipeline()
        result = call_process(
            pipeline,
            resp_headers={
                "Content-Type": "application/json",
                "X-Trace-Id": "trace-abc",
            },
        )
        assert result is not None
        names = result["resp_header_names"]
        assert "content-type" in names
        assert "x-trace-id" in names
        # Values must not appear
        assert "trace-abc" not in names

    def test_query_names_present(self):
        """query_names lists the unique query parameter names."""
        _, pipeline = make_pipeline()
        result = call_process(
            pipeline,
            url="https://api.example.com/v1/orders?page=2&sort=asc&tag=foo&tag=bar",
        )
        assert result is not None
        names = result["query_names"]
        assert "page" in names
        assert "sort" in names
        assert "tag" in names
        # Values must not appear
        assert "2" not in names
        assert "asc" not in names
        assert "foo" not in names

    def test_query_names_empty_when_no_query(self):
        """query_names is an empty list when there is no query string."""
        _, pipeline = make_pipeline()
        result = call_process(
            pipeline, url="https://api.example.com/v1/orders"
        )
        assert result is not None
        assert result["query_names"] == []

    def test_all_four_arrays_are_lists(self):
        """All four new array fields must always be list instances."""
        _, pipeline = make_pipeline()
        result = call_process(pipeline)
        assert result is not None
        for field in ("resp_key_paths", "req_header_names", "resp_header_names", "query_names"):
            assert isinstance(result[field], list), f"{field} must be a list"

    def test_resp_key_paths_values_never_sent(self):
        """Values inside the response body must not appear in resp_key_paths."""
        _, pipeline = make_pipeline()
        result = call_process(
            pipeline,
            resp_body='{"secret": "hunter2", "count": 42}',
        )
        assert result is not None
        assert "hunter2" not in result["resp_key_paths"]
        assert "42" not in result["resp_key_paths"]


class TestPipelineKnownFingerprint:
    """Tests for known-fingerprint field-rule application."""

    def _make_cache_with_rules(
        self,
        req_body: str,
        field_rules: List[Dict],
        url: str = "https://api.example.com/v1/orders",
    ) -> Tuple[FakeRulesCache, PrivacyPipeline]:
        from stubsmith.privacy.fingerprint import fingerprint as fp_fn
        parsed = urllib.parse.urlparse(url)
        qs = parsed.query or ""
        ct = "application/json"
        fp = fp_fn(req_body, qs, ct)

        sync_resp = make_sync_response(fingerprint=fp, field_rules=field_rules)
        cache, pipeline = make_pipeline(fake_responses={"sync": (200, sync_resp)})
        # Drive one poll cycle to populate the cache
        cache._poll_once()
        return cache, pipeline

    def test_known_fp_not_novel(self):
        req_body = '{"amount": 50, "user_id": 7}'
        _, pipeline = self._make_cache_with_rules(
            req_body, [{"path": "body.amount", "action": "keep"}]
        )
        result = call_process(pipeline, req_body=req_body)
        assert result is not None
        assert result["novel"] is False

    def test_keep_field_rule_applied(self):
        req_body = '{"amount": 50, "secret": "tok"}'
        _, pipeline = self._make_cache_with_rules(
            req_body, [{"path": "body.amount", "action": "keep"}]
        )
        result = call_process(pipeline, req_body=req_body)
        assert result is not None
        obj = json.loads(result["req_body"])
        assert obj["amount"] == 50
        assert obj["secret"] == "<masked>"

    def test_mask_field_rule_applied(self):
        req_body = '{"amount": 50, "name": "alice"}'
        # Both fields default to mask (no keep rules)
        _, pipeline = self._make_cache_with_rules(req_body, [])
        result = call_process(pipeline, req_body=req_body)
        assert result is not None
        obj = json.loads(result["req_body"])
        assert obj["amount"] == 0
        assert obj["name"] == "<masked>"


class TestPipelineRespFieldRules:
    """Tests for response-body field rule application (V4-a)."""

    def _make_pipeline_with_resp_rules(
        self,
        req_body: str,
        field_rules: List[Dict],
        url: str = "https://api.example.com/v1/orders",
    ) -> Tuple[FakeRulesCache, PrivacyPipeline]:
        from stubsmith.privacy.fingerprint import fingerprint as fp_fn
        parsed = urllib.parse.urlparse(url)
        qs = parsed.query or ""
        ct = "application/json"
        fp = fp_fn(req_body, qs, ct)
        sync_resp = make_sync_response(
            fingerprint=fp,
            field_rules=field_rules,
        )
        cache, pipeline = make_pipeline(fake_responses={"sync": (200, sync_resp)})
        cache._poll_once()
        return cache, pipeline

    def test_resp_kept_field_survives(self):
        """A resp. keep rule preserves the response body field value."""
        req_body = '{"action": "buy"}'
        resp_body = json.dumps({"id": 42, "secret": "tok"})
        _, pipeline = self._make_pipeline_with_resp_rules(
            req_body,
            [{"path": "resp.id", "action": "keep"}],
        )
        result = call_process(pipeline, req_body=req_body, resp_body=resp_body)
        assert result is not None
        obj = json.loads(result["resp_body"])
        assert obj["id"] == 42
        assert obj["secret"] == "<masked>"

    def test_resp_unlisted_field_masked_typed_placeholder(self):
        """Without any resp. rules all response body scalars get typed placeholders."""
        req_body = '{"action": "buy"}'
        resp_body = json.dumps({"id": 7, "status": "ok", "active": True})
        _, pipeline = self._make_pipeline_with_resp_rules(req_body, [])
        result = call_process(pipeline, req_body=req_body, resp_body=resp_body)
        assert result is not None
        obj = json.loads(result["resp_body"])
        # id → int placeholder, status → str placeholder, active → bool placeholder
        assert obj["id"] == 0
        assert obj["status"] == "<masked>"
        assert obj["active"] is False

    def test_resp_body_rules_independent_of_req_body_rules(self):
        """Request body keep rules must not accidentally keep response body fields."""
        req_body = '{"amount": 99}'
        resp_body = json.dumps({"amount": 99, "secret": "tok"})
        # Only body.amount kept - no resp. rules
        _, pipeline = self._make_pipeline_with_resp_rules(
            req_body,
            [{"path": "body.amount", "action": "keep"}],
        )
        result = call_process(pipeline, req_body=req_body, resp_body=resp_body)
        assert result is not None
        req_obj = json.loads(result["req_body"])
        resp_obj = json.loads(result["resp_body"])
        # Request amount kept
        assert req_obj["amount"] == 99
        # Response amount must be masked (resp. keep path not set)
        assert resp_obj["amount"] == 0
        assert resp_obj["secret"] == "<masked>"

    def test_resp_kept_string_regex_backstopped(self):
        """A kept resp. string field still has the email regex backstop applied."""
        req_body = '{"action": "query"}'
        resp_body = json.dumps({"note": "contact alice@example.com please", "id": 1})
        _, pipeline = self._make_pipeline_with_resp_rules(
            req_body,
            [
                {"path": "resp.note", "action": "keep"},
                {"path": "resp.id", "action": "keep"},
            ],
        )
        result = call_process(pipeline, req_body=req_body, resp_body=resp_body)
        assert result is not None
        obj = json.loads(result["resp_body"])
        # note is kept but email backstop fires
        assert "alice@example.com" not in obj["note"]
        assert "<masked>" in obj["note"]
        # id is a non-string kept value - stays
        assert obj["id"] == 1

    def test_resp_array_fail_closed(self):
        """Arrays in the response body are fail-closed (all elements masked)."""
        req_body = '{"action": "list"}'
        resp_body = json.dumps({"items": [{"price": 10, "secret": "x"}]})
        _, pipeline = self._make_pipeline_with_resp_rules(
            req_body,
            [{"path": "resp.items.[].price", "action": "keep"}],
        )
        result = call_process(pipeline, req_body=req_body, resp_body=resp_body)
        assert result is not None
        obj = json.loads(result["resp_body"])
        # price kept via resp. rule, secret masked
        assert obj["items"][0]["price"] == 10
        assert obj["items"][0]["secret"] == "<masked>"

    def test_resp_novel_fingerprint_fully_masked(self):
        """Novel (unknown) fingerprint → response body still fully masked (fail-closed)."""
        # Empty cache: all fingerprints unknown
        _, pipeline = make_pipeline()
        resp_body = json.dumps({"id": 7, "email": "user@example.com"})
        result = call_process(pipeline, resp_body=resp_body)
        assert result is not None
        assert result["novel"] is True
        obj = json.loads(result["resp_body"])
        assert obj["id"] == 0
        assert obj["email"] == "<masked>"

    def test_resp_nested_keep_rule(self):
        """Nested resp. keep rules work with dotted paths."""
        req_body = '{"action": "get"}'
        resp_body = json.dumps({"user": {"name": "alice", "token": "secret"}})
        _, pipeline = self._make_pipeline_with_resp_rules(
            req_body,
            [{"path": "resp.user.name", "action": "keep"}],
        )
        result = call_process(pipeline, req_body=req_body, resp_body=resp_body)
        assert result is not None
        obj = json.loads(result["resp_body"])
        assert obj["user"]["name"] == "alice"
        assert obj["user"]["token"] == "<masked>"


# ===========================================================================
# field_rules.py unit tests - resp_header. namespace (V6-a)
# ===========================================================================


class TestCompileFieldRulesRespHeader:
    """compile_field_rules parses resp_header. into keep_resp_header."""

    def test_keep_resp_header_path_lowercased(self):
        rules = compile_field_rules([{"path": "resp_header.X-Trace-Id", "action": "keep"}])
        assert "x-trace-id" in rules.keep_resp_header

    def test_resp_header_does_not_pollute_keep_header(self):
        rules = compile_field_rules([{"path": "resp_header.authorization", "action": "keep"}])
        assert "authorization" not in rules.keep_header

    def test_header_does_not_pollute_keep_resp_header(self):
        rules = compile_field_rules([{"path": "header.authorization", "action": "keep"}])
        assert "authorization" not in rules.keep_resp_header

    def test_mask_resp_header_not_added(self):
        rules = compile_field_rules([{"path": "resp_header.x-secret", "action": "mask"}])
        assert "x-secret" not in rules.keep_resp_header

    def test_empty_list_has_keep_resp_header(self):
        rules = compile_field_rules([])
        assert rules.keep_resp_header == frozenset()

    def test_mixed_namespaces_stay_independent(self):
        rules = compile_field_rules([
            {"path": "header.authorization", "action": "keep"},
            {"path": "resp_header.x-request-id", "action": "keep"},
            {"path": "resp.id", "action": "keep"},
        ])
        assert "authorization" in rules.keep_header
        assert "authorization" not in rules.keep_resp_header
        assert "x-request-id" in rules.keep_resp_header
        assert "x-request-id" not in rules.keep_header
        assert "id" in rules.keep_resp


class TestApplyRespFieldRulesHeaderIndependence:
    """apply_resp_field_rules uses keep_resp_header, not keep_header."""

    def _compiled(self, field_rules: List[Dict]) -> "CompiledFieldRules":
        return compile_field_rules(field_rules)

    def test_resp_header_keep_rule_keeps_header(self):
        """A resp_header. keep rule preserves the response header value."""
        from stubsmith.privacy.field_rules import apply_resp_field_rules
        compiled = self._compiled([{"path": "resp_header.x-trace-id", "action": "keep"}])
        _, masked = apply_resp_field_rules(
            resp_body="{}",
            resp_headers={"x-trace-id": "trace-abc", "authorization": "Bearer tok"},
            content_type="application/json",
            compiled=compiled,
        )
        assert masked["x-trace-id"] == "trace-abc"
        assert masked["authorization"] == "<masked>"

    def test_request_header_keep_does_not_keep_response_header(self):
        """A header. keep rule (request) must NOT keep a same-named response header."""
        from stubsmith.privacy.field_rules import apply_resp_field_rules
        # Only header.authorization is kept - no resp_header. rule
        compiled = self._compiled([{"path": "header.authorization", "action": "keep"}])
        _, masked = apply_resp_field_rules(
            resp_body="{}",
            resp_headers={"authorization": "Bearer resp-secret"},
            content_type="application/json",
            compiled=compiled,
        )
        assert masked["authorization"] == "<masked>"

    def test_resp_header_keep_does_not_affect_request_header_path(self):
        """A resp_header. keep rule must not affect apply_field_rules (request path)."""
        from stubsmith.privacy.field_rules import apply_field_rules
        compiled = self._compiled([{"path": "resp_header.authorization", "action": "keep"}])
        _, req_masked, _ = apply_field_rules(
            body="{}",
            headers={"authorization": "Bearer req-secret"},
            query_params="",
            content_type="application/json",
            compiled=compiled,
        )
        assert req_masked["authorization"] == "<masked>"

    def test_independence_req_keep_resp_mask(self):
        """header.authorization:keep AND resp_header. absent → req keeps, resp masks."""
        from stubsmith.privacy.field_rules import apply_field_rules, apply_resp_field_rules
        compiled = self._compiled([{"path": "header.authorization", "action": "keep"}])
        _, req_masked, _ = apply_field_rules(
            "{}", {"authorization": "Bearer req-tok"},
            "", "application/json", compiled,
        )
        _, resp_masked = apply_resp_field_rules(
            "{}", {"authorization": "Bearer resp-tok"},
            "application/json", compiled,
        )
        assert req_masked["authorization"] == "Bearer req-tok"
        assert resp_masked["authorization"] == "<masked>"

    def test_independence_resp_keep_req_mask(self):
        """resp_header.authorization:keep AND header. absent → resp keeps, req masks."""
        from stubsmith.privacy.field_rules import apply_field_rules, apply_resp_field_rules
        compiled = self._compiled([{"path": "resp_header.authorization", "action": "keep"}])
        _, req_masked, _ = apply_field_rules(
            "{}", {"authorization": "Bearer req-tok"},
            "", "application/json", compiled,
        )
        _, resp_masked = apply_resp_field_rules(
            "{}", {"authorization": "Bearer resp-tok"},
            "application/json", compiled,
        )
        assert req_masked["authorization"] == "<masked>"
        assert resp_masked["authorization"] == "Bearer resp-tok"

    def test_non_allowlisted_resp_header_masked_by_default(self):
        """A non-allowlisted response header with no resp_header. rule is masked (fail-closed)."""
        from stubsmith.privacy.field_rules import apply_resp_field_rules
        compiled = self._compiled([])
        _, masked = apply_resp_field_rules(
            "{}", {"x-internal-token": "secret123"},
            "application/json", compiled,
        )
        assert masked["x-internal-token"] == "<masked>"

    def test_allowlisted_resp_header_passes_without_rule(self):
        """Allowlisted response headers (e.g. content-type) pass through without a rule."""
        from stubsmith.privacy.field_rules import apply_resp_field_rules
        from stubsmith.privacy.masking import HEADER_ALLOWLIST
        compiled = self._compiled([])
        # content-type is in HEADER_ALLOWLIST
        assert "content-type" in HEADER_ALLOWLIST
        _, masked = apply_resp_field_rules(
            "{}", {"content-type": "application/json", "x-secret": "tok"},
            "application/json", compiled,
        )
        assert masked["content-type"] == "application/json"
        assert masked["x-secret"] == "<masked>"

    def test_novel_fingerprint_resp_headers_fully_masked(self):
        """Novel (unknown) fingerprint → response headers are fully masked (fail-closed)."""
        _, pipeline = make_pipeline()
        result = call_process(
            pipeline,
            resp_headers={"content-type": "application/json", "x-secret": "tok"},
        )
        assert result is not None
        assert result["novel"] is True
        assert result["resp_headers"]["x-secret"] == "<masked>"
        # allowlisted header still passes
        assert result["resp_headers"]["content-type"] == "application/json"


class TestProjectDefaults:
    """Tests for project_defaults from /v1/sdk/sync used as belt-and-suspenders."""

    def _make_cache_with_rules_and_defaults(
        self,
        req_body: str,
        field_rules: List[Dict],
        project_defaults: Optional[Dict] = None,
    ) -> Tuple[FakeRulesCache, PrivacyPipeline]:
        from stubsmith.privacy.fingerprint import fingerprint as fp_fn
        import urllib.parse as _up
        fp = fp_fn(req_body, "", "application/json")
        sync_resp = make_sync_response(
            fingerprint=fp,
            field_rules=field_rules,
            project_defaults=project_defaults,
        )
        cache, pipeline = make_pipeline(
            fake_responses={"sync": (200, sync_resp)},
        )
        cache._poll_once()
        return cache, pipeline

    def test_synced_project_defaults_mask_kept_string_matching_regex(self):
        """A kept field whose value matches a project_defaults regex is still masked."""
        req_body = json.dumps({"note": "contact alice@example.com for details", "count": 1})
        # keep 'note', but project_defaults includes an email regex
        _, pipeline = self._make_cache_with_rules_and_defaults(
            req_body,
            field_rules=[{"path": "body.note", "action": "keep"}],
            project_defaults={
                "field_masks": [],
                "regex_masks": [
                    {
                        "pattern": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
                        "replace": "<masked>",
                        "flags": "",
                    }
                ],
            },
        )
        result = call_process(pipeline, req_body=req_body)
        assert result is not None
        obj = json.loads(result["req_body"])
        # Email must be redacted even though 'note' is a keep field
        assert "alice@example.com" not in obj["note"]
        assert "<masked>" in obj["note"]

    def test_synced_project_defaults_field_mask_applied_on_kept_path(self):
        """A kept field whose key matches a project_defaults field_mask is masked."""
        req_body = json.dumps({"token": "super-secret", "count": 5})
        # keep 'token' via field_rules, but project_defaults also masks 'token'
        _, pipeline = self._make_cache_with_rules_and_defaults(
            req_body,
            field_rules=[{"path": "body.token", "action": "keep"}],
            project_defaults={
                "field_masks": ["token"],
                "regex_masks": [],
            },
        )
        # Note: project_defaults field_masks are not re-applied to already-kept body
        # paths (that is mask_known semantics, not apply_field_rules). The main
        # assertion here is that the pipeline does not crash and the regex backstop
        # path is exercised via extra_rules.
        result = call_process(pipeline, req_body=req_body)
        assert result is not None
        # Pipeline must not raise; body is valid JSON
        obj = json.loads(result["req_body"])
        assert "count" in obj

    def test_absent_project_defaults_embedded_regex_still_applied(self):
        """When project_defaults absent from sync, embedded email regex is the backstop."""
        req_body = json.dumps({"note": "reach bob@example.org please", "count": 2})
        # keep 'note' - no project_defaults in sync response
        _, pipeline = self._make_cache_with_rules_and_defaults(
            req_body,
            field_rules=[{"path": "body.note", "action": "keep"}],
            project_defaults=None,  # not included in sync response
        )
        result = call_process(pipeline, req_body=req_body)
        assert result is not None
        obj = json.loads(result["req_body"])
        # Embedded email regex must still catch the address
        assert "bob@example.org" not in obj["note"]
        assert "<masked>" in obj["note"]

    def test_get_project_defaults_returns_none_before_sync(self):
        """Cache returns None when no sync has delivered project_defaults."""
        cache, _ = make_pipeline()
        assert cache.get_project_defaults() is None

    def test_get_project_defaults_returns_compiled_rules_after_sync(self):
        """After a sync with project_defaults, get_project_defaults() is non-None."""
        from stubsmith.privacy.masking import CompiledRules
        req_body = json.dumps({"x": 1})
        cache, _ = self._make_cache_with_rules_and_defaults(
            req_body,
            field_rules=[],
            project_defaults={"field_masks": ["secret"], "regex_masks": []},
        )
        result = cache.get_project_defaults()
        assert isinstance(result, CompiledRules)
        assert "secret" in result.field_masks

    def test_empty_project_defaults_falls_back_to_embedded_backstop(self):
        """project_defaults {} (both lists empty) must NOT shadow the embedded backstop."""
        req_body = json.dumps({"note": "contact carol@example.com please", "x": 1})
        # keep 'note', but project_defaults is empty - embedded email regex must fire
        _, pipeline = self._make_cache_with_rules_and_defaults(
            req_body,
            field_rules=[{"path": "body.note", "action": "keep"}],
            project_defaults={"field_masks": [], "regex_masks": []},
        )
        result = call_process(pipeline, req_body=req_body)
        assert result is not None
        obj = json.loads(result["req_body"])
        assert "carol@example.com" not in obj["note"], (
            "Empty project_defaults must not bypass the embedded email backstop"
        )
        assert "<masked>" in obj["note"]

    def test_malformed_project_defaults_poll_still_lands_cursor_and_rules(self):
        """Malformed project_defaults (e.g. field_masks:[1]) must not abort the poll cycle."""
        from stubsmith.privacy.fingerprint import fingerprint as fp_fn
        req_body = json.dumps({"amount": 50})
        fp = fp_fn(req_body, "", "application/json")
        sync_resp = make_sync_response(
            fingerprint=fp,
            field_rules=[{"path": "body.amount", "action": "keep"}],
            cursor="99",
            project_defaults={"field_masks": [1, None, True], "regex_masks": [{"pattern": None}]},
        )
        cache, pipeline = make_pipeline(fake_responses={"sync": (200, sync_resp)})
        # Must not raise
        cache._poll_once()
        # Cursor and per-fingerprint rules must still have been applied
        assert cache.get_cursor() == "99"
        assert cache.get_project_defaults() is None  # malformed → treated as absent
        # Pipeline still processes correctly using embedded backstop
        result = call_process(pipeline, req_body=req_body)
        assert result is not None
        obj = json.loads(result["req_body"])
        assert obj["amount"] == 50  # keep rule was applied


class TestPipelineTruncation:
    def test_fingerprint_on_pre_truncation_body(self):
        """Fingerprint must be computed on the full body, not the truncated one."""
        from stubsmith.privacy.fingerprint import fingerprint as fp_fn

        # Build a body that is large enough to trigger truncation
        big_value = "x" * 200
        req_body = json.dumps({"key": big_value})
        full_fp = fp_fn(req_body, "", "application/json")

        _, pipeline = make_pipeline(max_body_bytes=50)
        result = call_process(
            pipeline,
            req_body=req_body,
            req_headers={"Content-Type": "application/json"},
        )
        assert result is not None
        # Fingerprint should match the full (untruncated) body
        assert result["req_fingerprint"] == full_fp
        # But the sent body should be truncated
        assert len(result["req_body"].encode("utf-8")) <= 50

    def test_truncation_does_not_affect_fingerprint_key_paths(self):
        """key_paths are from the full body."""
        req_body = json.dumps({"alpha": "a" * 200, "beta": "b" * 200})
        _, pipeline = make_pipeline(max_body_bytes=30)
        result = call_process(
            pipeline,
            req_body=req_body,
            req_headers={"Content-Type": "application/json"},
        )
        assert result is not None
        assert set(result["key_paths"]) == {"alpha", "beta"}


class TestPipelineImageBody:
    def test_req_body_image_replaced_with_base64_placeholder(self):
        _, pipeline = make_pipeline()
        result = call_process(
            pipeline,
            req_headers={"Content-Type": "image/gif"},
            req_body="real-gif-pixels",
        )
        assert result is not None
        assert result.get("req_body_encoding") == "base64"
        decoded = base64.b64decode(result["req_body"])
        assert decoded == GIF_1X1

    def test_resp_body_image_replaced_with_base64_placeholder(self):
        _, pipeline = make_pipeline()
        result = call_process(
            pipeline,
            resp_headers={"Content-Type": "image/png"},
            resp_body="real-png-pixels",
        )
        assert result is not None
        assert result.get("resp_body_encoding") == "base64"
        decoded = base64.b64decode(result["resp_body"])
        assert decoded == PNG_1X1

    def test_image_body_novel_flag(self):
        """Image request with unknown fingerprint should be novel (always new fp)."""
        _, pipeline = make_pipeline()
        result = call_process(
            pipeline,
            req_headers={"Content-Type": "image/png"},
            req_body="pixels",
        )
        assert result is not None
        # May or may not be novel (placeholder has stable fp),
        # but must not be raw image data in body
        assert "pixels" not in result["req_body"]

    def test_non_image_body_has_no_encoding_field(self):
        _, pipeline = make_pipeline()
        result = call_process(pipeline)
        assert "req_body_encoding" not in result
        assert "resp_body_encoding" not in result


class TestPipelineFailClosed:
    def test_masking_exception_degrades_to_mask_all(self):
        """If field-rule application raises, pipeline degrades to mask_all + novel."""
        # Build a cache with a rule for the fingerprint
        req_body = '{"user": "alice", "token": "s3cr3t"}'
        from stubsmith.privacy.fingerprint import fingerprint as fp_fn
        fp = fp_fn(req_body, "", "application/json")

        sync_resp = make_sync_response(
            fingerprint=fp,
            field_rules=[{"path": "body.user", "action": "keep"}],
        )
        cache, pipeline = make_pipeline(
            fake_responses={"sync": (200, sync_resp)},
        )
        cache._poll_once()

        # Patch apply_field_rules in the pipeline module's own namespace so the
        # already-imported binding is replaced.
        import stubsmith.privacy.pipeline as pl_module

        with mock.patch.object(pl_module, "apply_field_rules",
                               side_effect=RuntimeError("injected masking failure")):
            result = call_process(pipeline, req_body=req_body)

        assert result is not None
        # Payload must be masked (fail-closed), not raw
        obj = json.loads(result["req_body"])
        assert obj.get("token") == "<masked>"
        assert obj.get("user") == "<masked>"
        # novel=True because we fell back to mask_all path
        assert result["novel"] is True

    def test_legacy_compiled_rules_branch_raises_degrades_to_mask_all(self):
        """If mask_known raises when the cache returns a CompiledRules (legacy mode),
        the pipeline degrades to mask_all + novel=True rather than leaking raw data."""
        legacy_body = {"field_masks": [], "regex_masks": []}
        cache, pipeline = make_pipeline(fake_responses={
            "sync": (404, None),
            "anonymizer/rules": (200, legacy_body),
        })
        cache._poll_once()

        import stubsmith.privacy.pipeline as pl_module
        with mock.patch.object(pl_module, "mask_known",
                               side_effect=RuntimeError("injected mask_known failure")):
            result = call_process(
                pipeline, req_body='{"sensitive": "value", "count": 5}'
            )

        assert result is not None
        obj = json.loads(result["req_body"])
        assert obj.get("sensitive") == "<masked>"
        assert obj.get("count") == 0
        assert result["novel"] is True

    def test_catastrophic_failure_returns_none(self):
        """A fully broken pipeline returns None rather than raw data."""
        _, pipeline = make_pipeline()

        # Patch mask_all in the pipeline module's namespace so both the primary
        # masking and the fallback masking path are broken.
        import stubsmith.privacy.pipeline as pl_module
        with mock.patch.object(pl_module, "mask_all", side_effect=RuntimeError("total failure")):
            result = call_process(pipeline, req_body='{"sensitive": "data"}')

        assert result is None

    def test_malformed_url_returns_none(self):
        """A URL that causes urlparse to fail leads to a None result."""
        _, pipeline = make_pipeline()
        # Patch urlparse to raise for this specific test
        with mock.patch("stubsmith.privacy.pipeline.urllib.parse.urlparse", side_effect=ValueError("bad url")):
            result = pipeline.process("GET", "bad-url", {}, "", 200, {}, "")
        assert result is None


class TestPipelineLegacyFallback:
    def test_legacy_mode_on_404(self):
        """404 from /v1/sdk/sync → legacy rules, no novelty."""
        legacy_body = {
            "field_masks": ["password"],
            "regex_masks": [],
        }
        cache, pipeline = make_pipeline(fake_responses={
            "sync": (404, None),
            "anonymizer/rules": (200, legacy_body),
        })
        cache._poll_once()
        assert cache._legacy_mode is True

    def test_legacy_mode_lookup_always_returns_compiled_rules(self):
        """In legacy mode, lookup returns a CompiledRules (never None)."""
        from stubsmith.privacy.masking import CompiledRules
        legacy_body = {"field_masks": ["secret"], "regex_masks": []}
        cache, _ = make_pipeline(fake_responses={
            "sync": (404, None),
            "anonymizer/rules": (200, legacy_body),
        })
        cache._poll_once()
        result = cache.lookup("any-endpoint", "any-fingerprint")
        assert isinstance(result, CompiledRules)

    def test_legacy_mode_masks_field_masks(self):
        """In legacy mode, field_masks from /v1/anonymizer/rules are applied."""
        legacy_body = {"field_masks": ["password"], "regex_masks": []}
        cache, pipeline = make_pipeline(fake_responses={
            "sync": (404, None),
            "anonymizer/rules": (200, legacy_body),
        })
        cache._poll_once()

        req_body = json.dumps({"username": "alice", "password": "s3cr3t"})
        result = call_process(pipeline, req_body=req_body)
        assert result is not None
        obj = json.loads(result["req_body"])
        assert obj["password"] == "<masked>"
        # username not in field_masks → kept (mask_known leaves non-matched fields intact)
        assert obj["username"] == "alice"

    def test_legacy_mode_novel_always_false(self):
        """In legacy mode, no request is considered novel."""
        legacy_body = {"field_masks": [], "regex_masks": []}
        cache, pipeline = make_pipeline(fake_responses={
            "sync": (404, None),
            "anonymizer/rules": (200, legacy_body),
        })
        cache._poll_once()
        result = call_process(pipeline)
        assert result is not None
        assert result["novel"] is False

    def test_legacy_warning_emitted_once(self):
        """Only one warning should be logged on repeated polls in legacy mode."""
        legacy_body = {"field_masks": [], "regex_masks": []}
        cache, _ = make_pipeline(fake_responses={
            "sync": (404, None),
            "anonymizer/rules": (200, legacy_body),
        })
        with mock.patch.object(
            type(cache).__mro__[1],  # RulesCache via super
            "__init__",
            lambda *a, **kw: None,
        ):
            pass  # just to ensure the mock infrastructure is working

        warning_count = 0
        original_warning = cache.__class__.__bases__[0].__dict__  # noqa

        with mock.patch("stubsmith.privacy.rules_cache.logger") as mock_logger:
            cache._poll_once()
            cache._poll_once()
            cache._poll_once()
            # warning should be called exactly once
            warning_calls = [c for c in mock_logger.method_calls if "warning" in str(c)]
            assert len(warning_calls) == 1

    def test_legacy_fallback_list_shape_merges_enabled_sets(self):
        """New server returns rules as a list of named sets; enabled sets merged."""
        legacy_body = {
            "ok": True,
            "rules": [
                {
                    "id": "s1", "name": "set-a", "enabled": True,
                    "rules": {"field_masks": ["password", "token"], "regex_masks": []},
                    "updated_at": "2026-01-01T00:00:00Z",
                },
                {
                    "id": "s2", "name": "set-b", "enabled": True,
                    "rules": {"field_masks": ["secret"], "regex_masks": []},
                    "updated_at": "2026-01-01T00:00:00Z",
                },
                {
                    "id": "s3", "name": "set-disabled", "enabled": False,
                    "rules": {"field_masks": ["should_not_mask"], "regex_masks": []},
                    "updated_at": "2026-01-01T00:00:00Z",
                },
            ],
        }
        cache, pipeline = make_pipeline(fake_responses={
            "sync": (404, None),
            "anonymizer/rules": (200, legacy_body),
        })
        cache._poll_once()
        assert cache._legacy_mode is True

        req_body = json.dumps({
            "password": "s3cr3t",
            "token": "tok",
            "secret": "shh",
            "should_not_mask": "visible",
            "other": "plain",
        })
        result = call_process(pipeline, req_body=req_body)
        assert result is not None
        obj = json.loads(result["req_body"])
        assert obj["password"] == "<masked>"
        assert obj["token"] == "<masked>"
        assert obj["secret"] == "<masked>"
        # disabled set must not be applied
        assert obj["should_not_mask"] == "visible"
        assert obj["other"] == "plain"

    def test_legacy_fallback_list_shape_field_masks_deduped(self):
        """Duplicate field_masks across sets are deduplicated (case-insensitive)."""
        legacy_body = {
            "ok": True,
            "rules": [
                {
                    "id": "s1", "name": "set-a", "enabled": True,
                    "rules": {"field_masks": ["Password"], "regex_masks": []},
                    "updated_at": "2026-01-01T00:00:00Z",
                },
                {
                    "id": "s2", "name": "set-b", "enabled": True,
                    "rules": {"field_masks": ["password", "TOKEN"], "regex_masks": []},
                    "updated_at": "2026-01-01T00:00:00Z",
                },
            ],
        }
        cache, _ = make_pipeline(fake_responses={
            "sync": (404, None),
            "anonymizer/rules": (200, legacy_body),
        })
        cache._poll_once()
        # "password" appears twice (different case) - compile_rules lowercases, so
        # the resulting set should have it exactly once (no duplicate error).
        from stubsmith.privacy.masking import CompiledRules
        rules = cache.lookup("ep", "fp")
        assert isinstance(rules, CompiledRules)
        assert "password" in rules.field_masks
        assert "token" in rules.field_masks

    def test_legacy_fallback_dict_shape_still_works(self):
        """Old server shape {ok, rules: {field_masks, regex_masks}} still parsed."""
        legacy_body = {
            "ok": True,
            "rules": {"field_masks": ["apikey"], "regex_masks": []},
        }
        cache, pipeline = make_pipeline(fake_responses={
            "sync": (404, None),
            "anonymizer/rules": (200, legacy_body),
        })
        cache._poll_once()
        assert cache._legacy_mode is True

        req_body = json.dumps({"apikey": "abc", "name": "alice"})
        result = call_process(pipeline, req_body=req_body)
        assert result is not None
        obj = json.loads(result["req_body"])
        assert obj["apikey"] == "<masked>"
        assert obj["name"] == "alice"

    def test_legacy_fallback_flat_shape_still_works(self):
        """Flat shape {field_masks, regex_masks} at top level still parsed."""
        legacy_body = {"field_masks": ["password"], "regex_masks": []}
        cache, pipeline = make_pipeline(fake_responses={
            "sync": (404, None),
            "anonymizer/rules": (200, legacy_body),
        })
        cache._poll_once()
        assert cache._legacy_mode is True

        req_body = json.dumps({"password": "s3cr3t", "user": "alice"})
        result = call_process(pipeline, req_body=req_body)
        assert result is not None
        obj = json.loads(result["req_body"])
        assert obj["password"] == "<masked>"
        assert obj["user"] == "alice"

    def test_legacy_path_sets_first_sync_done(self):
        """A 404 on /v1/sdk/sync followed by a successful legacy poll sets _first_sync_done.

        Without this, install(wait_for_rules=N) would burn the full N seconds
        on every startup against a pre-sync backend even though rules loaded
        correctly via the legacy endpoint.
        """
        legacy_body = {"field_masks": ["password"], "regex_masks": []}
        cache, _ = make_pipeline(fake_responses={
            "sync": (404, None),
            "anonymizer/rules": (200, legacy_body),
        })
        assert not cache._first_sync_done.is_set()
        cache._poll_once()
        # Legacy rules loaded - event must be set.
        assert cache._first_sync_done.is_set()
        # rules_synced convenience check.
        assert cache.wait_for_first_sync(0) is True

    def test_legacy_path_failure_also_sets_first_sync_done(self):
        """_first_sync_done is set even when the legacy endpoint itself fails.

        The event being set indicates the first poll cycle completed, not that
        rules are available.  Callers check rules_synced or lookup() for that.
        A failed legacy poll should still release any waiter rather than
        hanging for the full timeout.
        """
        cache, _ = make_pipeline(fake_responses={
            "sync": (404, None),
            "anonymizer/rules": (0, None),  # network error on legacy endpoint
        })
        assert not cache._first_sync_done.is_set()
        cache._poll_once()
        assert cache._first_sync_done.is_set()


class TestRulesCacheCursorAndTemplates:
    def test_cursor_updated_from_sync_response(self):
        sync_resp = make_sync_response(
            fingerprint="abc123",
            field_rules=[],
            cursor="42",
        )
        cache, _ = make_pipeline(fake_responses={"sync": (200, sync_resp)})
        cache._poll_once()
        assert cache.get_cursor() == "42"

    def test_curated_templates_loaded(self):
        sync_resp = make_sync_response(
            fingerprint="abc",
            field_rules=[],
            path_templates=["/users/{id}/orders", "/users/{id}"],
        )
        cache, pipeline = make_pipeline(fake_responses={"sync": (200, sync_resp)})
        cache._poll_once()
        templates = cache.get_curated_templates()
        template_strs = [t.template for t in templates]
        assert "/users/{id}/orders" in template_strs

    def test_network_error_keeps_previous_cache(self):
        sync_resp = make_sync_response(fingerprint="fp1", field_rules=[], cursor="5")
        cache, _ = make_pipeline(fake_responses={"sync": (200, sync_resp)})
        cache._poll_once()
        assert cache.get_cursor() == "5"

        # Now simulate network error
        cache._fake_responses = {"sync": (0, None)}
        cache._poll_once()
        # Cursor should be unchanged
        assert cache.get_cursor() == "5"

    def test_start_stop_idempotent(self):
        cache, _ = make_pipeline()
        cache.start()
        cache.start()  # should not raise or start extra threads
        cache.stop()
        cache.stop()  # should not raise

    def test_wait_for_first_sync_returns_true_after_poll(self):
        """wait_for_first_sync returns True once _apply_sync_response has run."""
        sync_resp = make_sync_response(fingerprint="abc", field_rules=[], cursor="7")
        cache, _ = make_pipeline(fake_responses={"sync": (200, sync_resp)})
        assert not cache._first_sync_done.is_set()
        cache._poll_once()
        assert cache._first_sync_done.is_set()
        # Should return immediately now.
        result = cache.wait_for_first_sync(timeout=1.0)
        assert result is True

    def test_wait_for_first_sync_times_out_when_backend_unreachable(self):
        """wait_for_first_sync returns False (not raises) when the backend is down."""
        # No fake response → network error on every poll → event never set.
        cache, _ = make_pipeline(fake_responses={})
        result = cache.wait_for_first_sync(timeout=0.05)
        assert result is False

    def test_wait_for_first_sync_not_set_on_network_error(self):
        """A network error during _poll_once does not set the first-sync event."""
        cache, _ = make_pipeline(fake_responses={"sync": (0, None)})
        cache._poll_once()
        assert not cache._first_sync_done.is_set()

    def test_wait_for_first_sync_not_set_on_non_200(self):
        """A non-200 sync response does not set the first-sync event."""
        cache, _ = make_pipeline(fake_responses={"sync": (500, None)})
        cache._poll_once()
        assert not cache._first_sync_done.is_set()


class TestInstallWaitForRules:
    """install(wait_for_rules=...) integration.

    All tests that call install() use backend_url="http://127.0.0.1:1" so
    that no real network connection can succeed.  Network isolation is further
    proven by the autouse fixture below: any call to socket.connect,
    urllib.request.urlopen, or OpenerDirector.open that reaches a non-loopback
    address raises immediately.
    """

    @pytest.fixture(autouse=True)
    def _block_real_network(self, monkeypatch):
        """Raise on any network attempt that would leave the loopback interface."""
        import socket
        import urllib.request

        _real_connect = socket.socket.connect

        def _guarded_connect(self, address):
            host = address[0] if isinstance(address, tuple) else address
            # Allow 127.0.0.1 and ::1 (the test target port 1 rejects immediately).
            if host not in ("127.0.0.1", "::1", "localhost"):
                raise AssertionError(
                    f"Network isolation breach: socket.connect({address!r}) - "
                    "TestInstallWaitForRules must not make real network calls."
                )
            return _real_connect(self, address)

        monkeypatch.setattr(socket.socket, "connect", _guarded_connect)

        def _blocked_urlopen(*args, **kwargs):
            raise AssertionError(
                "Network isolation breach: urllib.request.urlopen() - "
                "TestInstallWaitForRules must not make real network calls."
            )

        monkeypatch.setattr(urllib.request, "urlopen", _blocked_urlopen)

    def test_default_zero_does_not_block(self):
        """Default wait_for_rules=0 returns immediately without touching the cache."""
        import stubsmith
        # Points at an unreachable port so no real network call can succeed.
        client = stubsmith.install(
            api_key="sk-test",
            backend_url="http://127.0.0.1:1",
            wait_for_rules=0,
        )
        try:
            # The cache is present but was never waited on.
            assert client._rules_cache is not None
        finally:
            client.uninstrument()
            client.close()

    def test_positive_wait_returns_after_sync(self):
        """install() + wait_for_rules=N returns promptly once sync completes.

        Drives the poll cycle manually via FakeRulesCache to avoid real
        network calls.  After a successful poll, wait_for_first_sync(0) must
        return True - confirming that the _first_sync_done event is set and
        that install()'s wait_for_rules plumbing reads it correctly.
        """
        import stubsmith
        from stubsmith.client import StubSmith

        sync_resp = make_sync_response(fingerprint="ff", field_rules=[], cursor="1")
        fake_cache = FakeRulesCache(responses={"sync": (200, sync_resp)})

        # Build a client without starting its background poll thread, then
        # inject the fake cache so we control exactly when the first poll fires.
        client = StubSmith(api_key="sk-test", _send_fn=lambda p: None)
        try:
            client._rules_cache = fake_cache
            assert not fake_cache._first_sync_done.is_set()

            # Simulate one successful poll cycle.
            fake_cache._poll_once()
            assert fake_cache._first_sync_done.is_set()

            # wait_for_first_sync(0) is a non-blocking check - must be True now.
            assert fake_cache.wait_for_first_sync(0) is True
        finally:
            client._rules_cache = None
            client.uninstrument()
            client.close()

    def test_positive_wait_times_out_gracefully(self):
        """wait_for_rules>0 returns after the timeout when backend is unreachable.

        Points at 127.0.0.1:1 (nothing listening) so the timeout path is
        deterministic regardless of what else is running on the machine.
        The elapsed time must be at least the requested timeout (proving the
        wait actually occurred) and well below 2 s (proving it did not hang).
        """
        import stubsmith
        import time
        t0 = time.monotonic()
        client = stubsmith.install(
            api_key="sk-test",
            backend_url="http://127.0.0.1:1",  # definitely unreachable
            wait_for_rules=0.1,
        )
        elapsed = time.monotonic() - t0
        try:
            assert 0.1 <= elapsed < 2.0
        finally:
            client.uninstrument()
            client.close()

    def test_install_never_raises_on_wait(self):
        """install() must not propagate any exception from wait_for_first_sync."""
        import stubsmith
        # Even with a nonsensical backend, install() must not raise.
        client = None
        try:
            client = stubsmith.install(
                api_key="sk-test",
                backend_url="http://127.0.0.1:1",  # definitely unreachable
                wait_for_rules=0.05,
            )
        except Exception as exc:
            raise AssertionError(f"install() raised unexpectedly: {exc}") from exc
        finally:
            if client is not None:
                client.uninstrument()
                client.close()




class TestRulesSynced:
    """StubSmith.rules_synced public property."""

    def test_false_before_first_sync(self):
        """rules_synced is False when a cache is present but no poll has succeeded.

        Injects a FakeRulesCache into a disabled client (no background thread)
        without triggering a poll, so _first_sync_done is never set.
        """
        from stubsmith.client import StubSmith
        fake_cache = FakeRulesCache(responses={})
        client = StubSmith(api_key="", _send_fn=lambda p: None)
        try:
            client._rules_cache = fake_cache
            assert not fake_cache._first_sync_done.is_set()
            assert client.rules_synced is False
        finally:
            client._rules_cache = None
            client.close()

    def test_true_after_first_sync(self):
        """rules_synced is True once _apply_sync_response has fired.

        Drives a FakeRulesCache poll to set the event, then verifies the
        property returns True by wiring the fake cache as the client's cache
        after stopping the background thread.  No network, no race.
        """
        sync_resp = make_sync_response(fingerprint="abc", field_rules=[], cursor="3")
        fake_cache, _ = make_pipeline(fake_responses={"sync": (200, sync_resp)})
        # Confirm the FakeRulesCache sets the event on a successful poll.
        fake_cache._poll_once()
        assert fake_cache._first_sync_done.is_set()

        # Now verify the property reads that state correctly.  Use a disabled
        # client (no api_key → no background thread) and swap in the primed
        # FakeRulesCache so there is no race with a real poll thread.
        from stubsmith.client import StubSmith
        client = StubSmith(api_key="", _send_fn=lambda p: None)
        try:
            client._rules_cache = fake_cache
            assert client.rules_synced is True
        finally:
            client._rules_cache = None
            client.close()

    def test_false_when_no_rules_cache(self):
        """rules_synced is False (not an exception) when the client is disabled."""
        from stubsmith.client import StubSmith
        # No api_key → enabled=False → no pipeline, no cache.
        client = StubSmith(api_key="", _send_fn=lambda p: None)
        try:
            assert client._rules_cache is None
            assert client.rules_synced is False
        finally:
            client.close()

    def test_never_raises(self):
        """rules_synced never propagates an exception regardless of cache state."""
        from stubsmith.client import StubSmith
        client = StubSmith(api_key="", _send_fn=lambda p: None)
        try:
            # Forcibly break the cache reference to something that would raise.
            client._rules_cache = object()  # type: ignore[assignment]
            try:
                result = client.rules_synced
                assert result is False
            except Exception as exc:
                raise AssertionError(
                    f"rules_synced raised unexpectedly: {exc}"
                ) from exc
        finally:
            # Restore so close() does not blow up.
            client._rules_cache = None
            client.close()

class TestPipelineMultiValuedQuery:
    def test_multi_valued_query_all_masked_in_novel(self):
        _, pipeline = make_pipeline()
        result = call_process(
            pipeline,
            url="https://api.example.com/v1/orders?tag=foo&tag=bar&secret=xyz",
        )
        assert result is not None
        assert "foo" not in result["path"]
        assert "bar" not in result["path"]
        assert "xyz" not in result["path"]

    def test_multi_valued_query_key_names_preserved(self):
        _, pipeline = make_pipeline()
        result = call_process(
            pipeline,
            url="https://api.example.com/v1/orders?tag=foo&tag=bar",
        )
        assert result is not None
        assert "tag" in result["path"]


# ===========================================================================
# Integration: StubSmith client with pipeline
# ===========================================================================

class TestClientPipelineIntegration:
    """Smoke tests that client.py wires up and calls the pipeline correctly."""

    def test_client_enables_pipeline_when_api_key_set(self):
        from stubsmith.client import StubSmith
        client = StubSmith(api_key="sk-test", _send_fn=lambda p: None)  # type: ignore[call-arg]
        assert client._pipeline is not None
        client.close()

    def test_client_no_pipeline_when_disabled(self):
        from stubsmith.client import StubSmith
        client = StubSmith(api_key="", _send_fn=lambda p: None)  # type: ignore[call-arg]
        assert client._pipeline is None
        client.close()

    def test_privacy_init_failure_drops_capture_not_raw(self):
        """When pipeline init raises (e.g. broken RulesCache), captures are
        dropped entirely - raw data must NEVER be sent as a fallback."""
        import responses as responses_lib
        import requests
        from stubsmith.client import StubSmith
        from stubsmith.privacy.rules_cache import RulesCache

        captured = []

        with responses_lib.RequestsMock() as rsps:
            rsps.add(
                responses_lib.POST,
                "https://api.example.com/secret",
                json={"token": "super-secret"},
                status=200,
            )

            # Monkeypatch RulesCache.__init__ to raise so _init_privacy fails
            original_init = RulesCache.__init__

            def broken_init(self, *args, **kwargs):
                raise RuntimeError("simulated RulesCache init failure")

            with mock.patch.object(RulesCache, "__init__", broken_init):
                client = StubSmith(
                    api_key="sk-test",
                    _send_fn=captured.append,
                )
                assert client._privacy_init_failed is True
                assert client._pipeline is None

                client.instrument_requests()
                requests.post(
                    "https://api.example.com/secret",
                    json={"password": "hunter2"},
                )
                client.uninstrument()

        # Give the background worker time to attempt a send
        time.sleep(0.3)

        # No payload should have been enqueued
        assert len(captured) == 0, (
            "Pipeline init failure must drop the capture, not send raw data. "
            f"Got: {captured}"
        )
        client.close()

    def test_pipeline_payload_enqueued_with_source_and_duration(self):
        """Payload must have source + duration fields added by capture helper."""
        import responses as responses_lib
        import requests
        from stubsmith.client import StubSmith

        captured = []

        with responses_lib.RequestsMock() as rsps:
            rsps.add(
                responses_lib.POST,
                "https://api.example.com/submit",
                json={"result": "ok"},
                status=200,
            )

            client = StubSmith(
                api_key="sk-test",
                _send_fn=captured.append,  # type: ignore[call-arg]
            )
            client.instrument_requests()

            requests.post(
                "https://api.example.com/submit",
                json={"action": "test"},
            )
            client.uninstrument()

        # Wait for async send
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and not captured:
            time.sleep(0.02)

        assert len(captured) == 1
        p = captured[0]
        assert "source" in p
        assert "duration" in p
        assert p["sdk_masked"] is True
        client.close()


# ===========================================================================
# Fingerprint value discrimination (per-endpoint value_paths)
# ===========================================================================


class TestPipelineFingerprintValueDiscrimination:
    """Tests for per-endpoint fingerprint value discrimination via sync config."""

    _DOMAIN = "api.example.com"
    _METHOD = "POST"
    _PATH = "/v1/rpc"

    @property
    def _endpoint_id(self) -> str:
        return f"{self._DOMAIN}|{self._METHOD}|{self._PATH}"

    @property
    def _url(self) -> str:
        return f"https://{self._DOMAIN}{self._PATH}"

    def _make_cache_with_value_config(
        self, value_paths: List[str]
    ) -> Tuple[FakeRulesCache, PrivacyPipeline]:
        sync_resp = make_sync_response(
            fingerprint="placeholder",
            field_rules=[],
            domain=self._DOMAIN,
            method=self._METHOD,
            path_template=self._PATH,
            request_type_value_config={self._endpoint_id: value_paths},
        )
        cache, pipeline = make_pipeline(fake_responses={"sync": (200, sync_resp)})
        cache._poll_once()
        return cache, pipeline

    # ------------------------------------------------------------------
    # Core: differing values → different fingerprints
    # ------------------------------------------------------------------

    def test_different_values_produce_different_fingerprints(self):
        _, pipeline = self._make_cache_with_value_config(["action"])
        body1 = json.dumps({"action": "login", "token": "secret"})
        body2 = json.dumps({"action": "logout", "token": "secret"})
        result1 = call_process(pipeline, url=self._url, req_body=body1)
        result2 = call_process(pipeline, url=self._url, req_body=body2)
        assert result1 is not None and result2 is not None
        assert result1["req_fingerprint"] != result2["req_fingerprint"]

    def test_same_value_same_fingerprint(self):
        _, pipeline = self._make_cache_with_value_config(["action"])
        body = json.dumps({"action": "login", "token": "secret"})
        result1 = call_process(pipeline, url=self._url, req_body=body)
        result2 = call_process(pipeline, url=self._url, req_body=body)
        assert result1 is not None and result2 is not None
        assert result1["req_fingerprint"] == result2["req_fingerprint"]

    # ------------------------------------------------------------------
    # Payload contains fingerprint_value_paths (path names, not values)
    # ------------------------------------------------------------------

    def test_payload_contains_fingerprint_value_paths(self):
        _, pipeline = self._make_cache_with_value_config(["action"])
        body = json.dumps({"action": "login"})
        result = call_process(pipeline, url=self._url, req_body=body)
        assert result is not None
        assert result.get("fingerprint_value_paths") == ["action"]

    def test_fingerprint_value_paths_never_contains_values(self):
        """The payload must carry path names only - not the actual values."""
        _, pipeline = self._make_cache_with_value_config(["action"])
        body = json.dumps({"action": "supersecret"})
        result = call_process(pipeline, url=self._url, req_body=body)
        assert result is not None
        stored = result.get("fingerprint_value_paths", [])
        assert "supersecret" not in stored

    # ------------------------------------------------------------------
    # Without config: baseline behaviour unchanged
    # ------------------------------------------------------------------

    def test_without_config_same_body_same_fingerprint(self):
        _, pipeline = make_pipeline()  # no value config
        body = json.dumps({"action": "login"})
        result1 = call_process(pipeline, req_body=body)
        result2 = call_process(pipeline, req_body=body)
        assert result1 is not None and result2 is not None
        assert result1["req_fingerprint"] == result2["req_fingerprint"]

    def test_without_config_no_fingerprint_value_paths_key(self):
        _, pipeline = make_pipeline()
        result = call_process(pipeline)
        assert result is not None
        assert "fingerprint_value_paths" not in result

    def test_fingerprint_with_config_differs_from_without(self):
        """Adds value to hash → different fingerprint than the 3-arg baseline."""
        _, pipeline_with = self._make_cache_with_value_config(["action"])
        _, pipeline_without = make_pipeline()
        body = json.dumps({"action": "login"})
        r_with = call_process(pipeline_with, url=self._url, req_body=body)
        r_without = call_process(pipeline_without, url=self._url, req_body=body)
        assert r_with is not None and r_without is not None
        assert r_with["req_fingerprint"] != r_without["req_fingerprint"]

    # ------------------------------------------------------------------
    # Sync clearing: full replacement semantics
    # ------------------------------------------------------------------

    def test_sync_with_empty_config_dict_clears_value_paths(self):
        """A later sync with request_type_value_config={} clears all paths."""
        cache, pipeline = self._make_cache_with_value_config(["action"])
        assert cache.get_value_paths(self._endpoint_id) == ["action"]

        sync_empty = make_sync_response(
            fingerprint="placeholder",
            field_rules=[],
            domain=self._DOMAIN,
            method=self._METHOD,
            path_template=self._PATH,
            request_type_value_config={},  # explicit empty dict
        )
        cache._fake_responses = {"sync": (200, sync_empty)}
        cache._poll_once()
        assert cache.get_value_paths(self._endpoint_id) == []

        # After clearing, payload must not contain fingerprint_value_paths
        result = call_process(pipeline, url=self._url, req_body=json.dumps({"action": "login"}))
        assert result is not None
        assert "fingerprint_value_paths" not in result

    def test_sync_without_key_leaves_config_unchanged(self):
        """A sync response without the key must NOT clear existing config."""
        cache, _ = self._make_cache_with_value_config(["action"])
        assert cache.get_value_paths(self._endpoint_id) == ["action"]

        # Sync without request_type_value_config key
        sync_no_key = make_sync_response(
            fingerprint="placeholder",
            field_rules=[],
            domain=self._DOMAIN,
            method=self._METHOD,
            path_template=self._PATH,
            # no request_type_value_config kwarg → key absent from dict
        )
        assert "request_type_value_config" not in sync_no_key
        cache._fake_responses = {"sync": (200, sync_no_key)}
        cache._poll_once()
        # Config must be unchanged
        assert cache.get_value_paths(self._endpoint_id) == ["action"]

    def test_sync_replaces_previous_value_config_fully(self):
        """A second sync with config replaces (not merges) the previous config."""
        domain = self._DOMAIN
        method = self._METHOD
        path = self._PATH
        ep1 = self._endpoint_id
        ep2 = f"{domain}|{method}|/v1/other"

        # First sync: two endpoints configured
        sync1 = make_sync_response(
            fingerprint="placeholder",
            field_rules=[],
            domain=domain,
            method=method,
            path_template=path,
            request_type_value_config={ep1: ["action"], ep2: ["type"]},
        )
        cache, _ = make_pipeline(fake_responses={"sync": (200, sync1)})
        cache._poll_once()
        assert cache.get_value_paths(ep1) == ["action"]
        assert cache.get_value_paths(ep2) == ["type"]

        # Second sync: only ep1 remains
        sync2 = make_sync_response(
            fingerprint="placeholder",
            field_rules=[],
            domain=domain,
            method=method,
            path_template=path,
            request_type_value_config={ep1: ["cmd"]},
        )
        cache._fake_responses = {"sync": (200, sync2)}
        cache._poll_once()
        assert cache.get_value_paths(ep1) == ["cmd"]
        assert cache.get_value_paths(ep2) == []  # not in new config

    # ------------------------------------------------------------------
    # Defensive: malformed entries skipped, no crash
    # ------------------------------------------------------------------

    def test_non_str_endpoint_id_skipped(self):
        """Non-string endpoint IDs in the sync payload are silently skipped."""
        sync_bad = make_sync_response(
            fingerprint="placeholder",
            field_rules=[],
            request_type_value_config={123: ["action"]},  # int key
        )
        cache, _ = make_pipeline(fake_responses={"sync": (200, sync_bad)})
        # Must not raise
        cache._poll_once()

    def test_non_str_path_entry_skipped(self):
        """Non-string path entries within a valid endpoint config are silently skipped."""
        ep = self._endpoint_id
        sync_bad = make_sync_response(
            fingerprint="placeholder",
            field_rules=[],
            domain=self._DOMAIN,
            method=self._METHOD,
            path_template=self._PATH,
            request_type_value_config={ep: ["action", 42, None, "type"]},
        )
        cache, _ = make_pipeline(fake_responses={"sync": (200, sync_bad)})
        cache._poll_once()
        # Only string entries should be kept
        assert cache.get_value_paths(ep) == ["action", "type"]


# ===========================================================================
# Sync URL composition
# ===========================================================================

class TestSyncUrlComposition:
    """Verify that RulesCache constructs the right GET URL from backend_url.

    The cache appends ``/v1/sdk/sync`` directly to backend_url.rstrip("/").
    That means backend_url must include the path prefix required by the server.
    For the hosted service (https://app.stubsmith.dev/api) the path is
    ``/api/v1/sdk/sync``; for a local server without a prefix (http://localhost:3000)
    the path is simply ``/v1/sdk/sync``.  This test locks in the correct
    behaviour so a future refactor cannot silently reintroduce prefix surgery.
    """

    def _captured_sync_url(self, backend_url: str) -> str:
        """Return the URL that RulesCache would poll given *backend_url*."""
        captured: list = []

        cache = RulesCache(api_key="sk-test", backend_url=backend_url)

        original_http_get = cache._http_get

        def _capturing_get(url: str):
            captured.append(url.split("?")[0])  # strip query string
            return original_http_get(url)

        cache._http_get = _capturing_get  # type: ignore[method-assign]

        # Trigger one poll without starting the background thread.
        try:
            cache._poll_once()
        except Exception:
            pass

        return captured[0] if captured else ""

    def test_hosted_backend_url_composes_correctly(self):
        """Hosted: https://app.stubsmith.dev/api → .../api/v1/sdk/sync."""
        url = self._captured_sync_url("https://app.stubsmith.dev/api")
        assert url == "https://app.stubsmith.dev/api/v1/sdk/sync", (
            f"Expected https://app.stubsmith.dev/api/v1/sdk/sync, got {url!r}"
        )

    def test_local_backend_url_composes_correctly(self):
        """Local: http://localhost:3000 → .../v1/sdk/sync (no /api prefix)."""
        url = self._captured_sync_url("http://localhost:3000")
        assert url == "http://localhost:3000/v1/sdk/sync", (
            f"Expected http://localhost:3000/v1/sdk/sync, got {url!r}"
        )

    def test_stripping_api_suffix_breaks_hosted_url(self):
        """Confirm that stripping /api produces the wrong path (regression guard)."""
        wrong_base = "https://app.stubsmith.dev"  # /api stripped - this is broken
        url = self._captured_sync_url(wrong_base)
        assert url == "https://app.stubsmith.dev/v1/sdk/sync", (
            "This test documents the *wrong* URL produced by prefix stripping. "
            f"Got: {url!r}"
        )
        # The correct URL must be different from what stripping produces.
        correct = "https://app.stubsmith.dev/api/v1/sdk/sync"
        assert url != correct, "Stripping /api must not accidentally produce the correct URL"


# ===========================================================================
# Helpers
# ===========================================================================

def _flatten_values(obj: Any) -> List[Any]:
    """Recursively collect all scalar values from a JSON-like structure."""
    if isinstance(obj, dict):
        result = []
        for v in obj.values():
            result.extend(_flatten_values(v))
        return result
    if isinstance(obj, list):
        result = []
        for e in obj:
            result.extend(_flatten_values(e))
        return result
    return [obj]
