#!/usr/bin/env python3
"""Generate the shared masking and fail-closed vectors in tests/vectors/.

Usage:
    python3 tools/gen_shared_vectors.py

The inputs are declared here, one case per behaviour that a test in tests/
pins. Every ``expected`` value is produced by calling the SDK through the
operations in tests/shared_vector_ops.py; nothing is typed in by hand. The
output is deterministic (fixed inputs and salts, sorted keys), so two runs
produce identical files.

Each case name starts with the test module it comes from and ends with the test
it mirrors, so a case can be traced back to the Python test that pins the same
behaviour.
"""
from __future__ import annotations

import importlib
import json
import re
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from stubsmith.privacy.masking import HEADER_ALLOWLIST, MAX_REGEX_SCAN_CHARS  # noqa: E402
from tests.shared_vector_ops import expand, run_op, typed  # noqa: E402

fpm = importlib.import_module("stubsmith.privacy.fingerprint")

OUT = ROOT / "tests" / "vectors"

JSON = "application/json"
FORM = "application/x-www-form-urlencoded"

P = "tests/test_pipeline.py::"
M = "tests/test_privacy_modules.py::"
PH = "tests/test_placeholders.py::"
V = "tests/test_value_types.py::"

MASKING = "masking-vectors.json"
PIPELINE = "masking-pipeline-vectors.json"
VALUES = "masking-values-vectors.json"
CLOSED = "fail-closed-vectors.json"

CASES: Dict[str, List[Dict[str, Any]]] = {MASKING: [], PIPELINE: [], VALUES: [], CLOSED: []}
# (file, case name, python test ids) per case. Only `--map` reads it: it prints the list, for building a table that
# maps the Python tests to these cases.
REGISTRY: List[Dict[str, Any]] = []

_STEM = {P: "pipeline", M: "privacy_modules", PH: "placeholders", V: "value_types"}


def _derive(py: str) -> str:
    for prefix, stem in _STEM.items():
        if py.startswith(prefix):
            rest = py[len(prefix):].split("::")
            test = rest[-1]
            return f"{stem}/{test[5:] if test.startswith('test_') else test}"
    raise ValueError(py)


def add(file: str, op: str, py: List[str], inp: Dict[str, Any], name: Optional[str] = None) -> None:
    """Add one case. ``py`` lists the Python tests whose behaviour the case pins."""
    name = name or _derive(py[0])
    assert not any(c["name"] == name for c in CASES[file]), f"duplicate case name {name}"
    # Run on the data exactly as a reader of the file sees it (sorted keys, no tuples).
    plain = json.loads(json.dumps(inp, sort_keys=True))
    expected = run_op(op, expand(plain))
    CASES[file].append({"name": name, "op": op, "input": inp, "expected": expected})
    REGISTRY.append({"file": file, "name": name, "py": py})


# ---------------------------------------------------------------------------
# Long strings are written as {"$repeat": "a", "times": N} (see the descriptions)
# ---------------------------------------------------------------------------
_RUN = re.compile(r"(.)\1{1023,}", re.S)


def compress(x: Any) -> Any:
    if isinstance(x, list):
        return [compress(e) for e in x]
    if isinstance(x, dict):
        return {k: compress(v) for k, v in x.items()}
    if isinstance(x, str):
        parts: List[Any] = []
        pos = 0
        for m in _RUN.finditer(x):
            if m.start() > pos:
                parts.append(x[pos:m.start()])
            parts.append({"$repeat": m.group(1), "times": m.end() - m.start()})
            pos = m.end()
        if not parts:
            return x
        if pos < len(x):
            parts.append(x[pos:])
        return parts[0] if len(parts) == 1 else {"$concat": parts}
    return x


# ---------------------------------------------------------------------------
# Input builders
# ---------------------------------------------------------------------------
def afr(file, py, rules, body="", headers=None, query="", ct=JSON, defaults=None, salt=None, domain=None, name=None):
    add(file, "apply_field_rules", py, {
        "field_rules": rules, "body": body, "headers": headers or {}, "query": query, "content_type": ct,
        "project_defaults": defaults, "salt": salt, "email_domain": domain}, name)


def arfr(file, py, rules, body="", headers=None, ct=JSON, status=None, defaults=None, salt=None, domain=None,
    name=None):
    add(file, "apply_resp_field_rules", py, {
        "field_rules": rules, "body": body, "headers": headers or {}, "content_type": ct, "resp_status": status,
        "project_defaults": defaults, "salt": salt, "email_domain": domain}, name)


def cfr(file, py, rules, name=None):
    add(file, "compile_field_rules", py, {"field_rules": rules}, name)


def cam(file, py, field_masks=None, regex_masks=None, body="", headers=None, query="", ct=JSON, name=None):
    add(file, "compile_and_mask", py, {
        "field_masks": [] if field_masks is None else field_masks,
        "regex_masks": [] if regex_masks is None else regex_masks,
        "body": body, "headers": headers or {}, "query": query, "content_type": ct}, name)


def mall(file, py, body="", headers=None, query="", ct=JSON, name=None):
    add(file, "mask_all", py, {"body": body, "headers": headers or {}, "query": query, "content_type": ct}, name)


def keep(*paths):
    return [{"path": p, "action": "keep"} for p in paths]


# The exchange tests/test_pipeline.py::call_process sends unless a test says otherwise.
def exchange(method="POST", url="https://api.example.com/v1/orders", req_headers=None,
             req_body='{"user": {"email": "alice@example.com"}, "amount": 99}', resp_status=200,
             resp_headers=None, resp_body='{"id": 1, "status": "ok"}'):
    return {
        "method": method, "url": url, "req_headers": {"Content-Type": JSON} if req_headers is None else req_headers,
        "req_body": req_body, "resp_status": resp_status,
        "resp_headers": {"Content-Type": JSON} if resp_headers is None else resp_headers, "resp_body": resp_body}


def sync_body(fp, field_rules, domain="api.example.com", method="POST", path_template="/v1/orders", cursor="1",
              defaults="absent", value_config=None):
    body = {
        "ok": True, "cursor": cursor,
        "rules": [{"seq": 1, "request_type": {"domain": domain, "method": method, "path_template": path_template},
                   "fingerprint": fp, "field_rules": field_rules}],
        "path_templates": [],
    }
    if defaults != "absent":
        body["project_defaults"] = defaults
    if value_config is not None:
        body["request_type_value_config"] = value_config
    return body


def ok(body):
    return {"status": 200, "body": body}


def pp(file, py, request, polls=None, salt=None, name=None):
    add(file, "pipeline_process", py, {"polls": polls or [], "request": request, "salt": salt}, name)


def fp_of(body, qs="", ct=JSON):
    return fpm.fingerprint(body, qs, ct)


def known(req_body, field_rules, url_qs="", **kw):
    """A synced cache that knows the fingerprint of ``req_body``."""
    return [ok(sync_body(fp_of(req_body, url_qs), field_rules, **kw))]


# ===========================================================================
# masking-vectors.json
# ===========================================================================
def gen_masking():
    f = MASKING
    # --- compile_field_rules -------------------------------------------------
    c = P + "TestCompileFieldRules::"
    cfr(f, [c + "test_keep_body_path"], keep("body.user.email"))
    cfr(f, [c + "test_keep_query_path"], keep("query.page"))
    cfr(f, [c + "test_keep_header_path_lowercased"], keep("header.X-Request-Id"))
    cfr(f, [c + "test_mask_action_not_added"], [{"path": "body.password", "action": "mask"}])
    cfr(f, [c + "test_empty_list", c + "test_empty_list_has_keep_resp",
            P + "TestCompileFieldRulesRespHeader::test_empty_list_has_keep_resp_header"], [],
                name="pipeline/empty_list")
    cfr(f, [c + "test_none_list"], None)
    cfr(f, [c + "test_invalid_entries_skipped"], ["not-a-dict", None, {"path": "body.ok", "action": "keep"}])
    cfr(f, [c + "test_keep_resp_path"], keep("resp.id"))
    cfr(f, [c + "test_keep_resp_nested_path"], keep("resp.user.email"))
    cfr(f, [c + "test_mask_resp_action_not_added"], [{"path": "resp.secret", "action": "mask"}])
    cfr(f, [c + "test_resp_path_does_not_pollute_keep_body"], keep("resp.id"),
        name="pipeline/resp_path_does_not_pollute_keep_body")
    c = P + "TestCompileFieldRulesRespHeader::"
    cfr(f, [c + "test_keep_resp_header_path_lowercased"], keep("resp_header.X-Trace-Id"))
    cfr(f, [c + "test_resp_header_does_not_pollute_keep_header"], keep("resp_header.authorization"))
    cfr(f, [c + "test_header_does_not_pollute_keep_resp_header"], keep("header.authorization"))
    cfr(f, [c + "test_mask_resp_header_not_added"], [{"path": "resp_header.x-secret", "action": "mask"}])
    cfr(f, [c + "test_mixed_namespaces_stay_independent"],
        keep("header.authorization", "resp_header.x-request-id", "resp.id"))
    c = M + "TestStatusScopedFieldRules::"
    cfr(f, [c + "test_resp_status_keep_compiled"], keep("resp:200.order_id"))
    cfr(f, [c + "test_resp_status_mask_compiled"], [{"path": "resp:404.error", "action": "mask"}])
    cfr(f, [c + "test_resp_header_status_keep_compiled"], keep("resp_header:429.retry-after"))
    cfr(f, [c + "test_resp_header_status_mask_compiled"], [{"path": "resp_header:500.x-trace-id", "action": "mask"}])
    cfr(f, [c + "test_resp_header_status_name_lowercased"], keep("resp_header:200.X-Custom-Header"))
    cfr(f, [c + "test_boundary_status_100"], keep("resp:100.x"))
    cfr(f, [c + "test_boundary_status_599"], keep("resp:599.x"))
    cfr(f, [c + "test_nested_body_path_preserved"], keep("resp:200.items.[].id"))
    cfr(f, [c + "test_resp_status_not_mistaken_for_resp_header"], keep("resp:404.x"))
    cfr(f, [c + "test_resp_header_status_not_mistaken_for_resp_status"], keep("resp_header:429.retry-after"),
        name="privacy_modules/resp_header_status_not_mistaken_for_resp_status")

    # --- apply_field_rules: request side ---------------------------------------
    c = P + "TestApplyFieldRules::"
    afr(f, [c + "test_fail_closed_unknown_key_masked"], [], json.dumps({"secret": "sensitive", "amount": 99}))
    afr(f, [c + "test_keep_body_path_survives"], keep("body.amount"), json.dumps({"secret": "sensitive",
        "amount": 99}))
    afr(f, [c + "test_nested_path_keep"], keep("body.user.name"),
        json.dumps({"user": {"name": "alice", "email": "alice@example.com"}}))
    afr(f, [c + "test_array_element_path_keep"], keep("body.items.[].price"),
        json.dumps({"items": [{"price": 10, "secret": "x"}, {"price": 20, "secret": "y"}]}))
    afr(f, [c + "test_query_keep"], keep("query.page"), "{}", {"Content-Type": JSON}, "page=3&secret=abc")
    afr(f, [c + "test_multi_valued_query_all_masked_by_default"], [], "{}", {}, "a=1&a=2&b=3")
    afr(f, [c + "test_multi_valued_query_keep"], keep("query.a"), "{}", {}, "a=1&a=2&b=3")
    afr(f, [c + "test_header_allowlist_always_kept"], [], "{}", {"content-type": JSON, "x-secret": "tok"})
    afr(f, [c + "test_header_explicit_keep_override"], keep("header.x-request-id"), "{}",
        {"x-request-id": "req-123", "authorization": "Bearer tok"})
    afr(f, [c + "test_form_encoded_body_keep_path"], keep("body.username"), "username=alice&password=s3cr3t", ct=FORM)
    afr(f, [c + "test_empty_body_passthrough"], [], "")
    afr(f, [c + "test_keeping_a_parent_does_not_keep_its_children"], keep("body.user"),
        json.dumps({"user": {"name": "Ana", "tags": ["x"], "n": 2}}))
    afr(f, [c + "test_kept_email_and_card_number_sent_verbatim"], keep("body.note"),
        json.dumps({"note": "ana@example.com 4111 1111 1111 1111", "other": "x"}))
    afr(f, [c + "test_bool_masked_to_false"], [], json.dumps({"active": True}))
    afr(f, [c + "test_none_stays_none"], keep("body.score"), json.dumps({"score": None}))

    # --- arrays: the masking half of the key-path round trip ------------------
    body = json.dumps({"items": [1, 2, 3], "secret": "hide-me"})
    afr(f, [M + "TestExtractKeypaths::test_scalar_array_keep_round_trip"], keep("body.items.[]"), body)
    body = json.dumps({"rows": [1, {"deep": {"deeper": "SECRET"}}], "later": [None, {"late": "ALSO"}]})
    c = M + "TestArrayElementsAreAllWalked::test_every_reported_path_is_one_the_masker_can_reach"
    afr(f, [c], keep("body.rows.[].deep.deeper"), body, name="privacy_modules/every_reported_path_is_reachable/rows")
    afr(f, [c], keep("body.later.[].late"), body, name="privacy_modules/every_reported_path_is_reachable/later")

    # --- response side ---------------------------------------------------------
    c = P + "TestApplyRespFieldRulesHeaderIndependence::"
    hdr = {"x-trace-id": "trace-abc", "authorization": "Bearer tok"}
    arfr(f, [c + "test_resp_header_keep_rule_keeps_header"], keep("resp_header.x-trace-id"), "{}", hdr)
    arfr(f, [c + "test_request_header_keep_does_not_keep_response_header"], keep("header.authorization"), "{}",
         {"authorization": "Bearer resp-secret"})
    afr(f, [c + "test_resp_header_keep_does_not_affect_request_header_path"], keep("resp_header.authorization"),
        "{}", {"authorization": "Bearer req-secret"})
    afr(f, [c + "test_independence_req_keep_resp_mask"], keep("header.authorization"), "{}",
        {"authorization": "Bearer req-tok"}, name="pipeline/independence_req_keep_resp_mask/request")
    arfr(f, [c + "test_independence_req_keep_resp_mask"], keep("header.authorization"), "{}",
         {"authorization": "Bearer resp-tok"}, name="pipeline/independence_req_keep_resp_mask/response")
    afr(f, [c + "test_independence_resp_keep_req_mask"], keep("resp_header.authorization"), "{}",
        {"authorization": "Bearer req-tok"}, name="pipeline/independence_resp_keep_req_mask/request")
    arfr(f, [c + "test_independence_resp_keep_req_mask"], keep("resp_header.authorization"), "{}",
         {"authorization": "Bearer resp-tok"}, name="pipeline/independence_resp_keep_req_mask/response")
    arfr(f, [c + "test_non_allowlisted_resp_header_masked_by_default"], [], "{}", {"x-internal-token": "secret123"})
    arfr(f, [c + "test_allowlisted_resp_header_passes_without_rule"], [], "{}",
         {"content-type": JSON, "x-secret": "tok"})

    c = M + "TestStatusScopedFieldRules::"
    body = json.dumps({"order_id": "ord-1", "amount": 99, "token": "secret"})
    arfr(f, [c + "test_scoped_keep_adds_path_not_in_generic"], keep("resp.order_id", "resp:200.amount"), body,
        status=200)
    arfr(f, [c + "test_scoped_mask_overrides_generic_keep"],
         keep("resp.customer_email") + [{"path": "resp:200.customer_email", "action": "mask"}],
         json.dumps({"customer_email": "alice@example.com", "id": "ord-1"}), status=200)
    arfr(f, [c + "test_generic_rule_applies_for_different_status"], keep("resp:404.error"),
         json.dumps({"error": "something", "id": 1}), status=200)
    arfr(f, [c + "test_resp_status_none_only_generic"], keep("resp.id", "resp:404.error"),
         json.dumps({"id": "abc", "error": "not_found"}), status=None)
    arfr(f, [c + "test_resp_status_default_is_none"], keep("resp.id", "resp:200.extra"),
         json.dumps({"id": "abc", "extra": "val"}), status=None)
    generic = keep("resp.id", "resp.status", "resp_header.x-trace-id")
    body = json.dumps({"id": "ord-1", "status": "created", "token": "secret"})
    hdr = {"x-trace-id": "trace-abc", "set-cookie": "sess=x", "content-type": JSON}
    arfr(f, [c + "test_generic_only_rules_unchanged"], generic, body, hdr, status=200,
         name="privacy_modules/generic_only_rules_unchanged/with_status")
    arfr(f, [c + "test_generic_only_rules_unchanged"], generic, body, hdr, status=None,
         name="privacy_modules/generic_only_rules_unchanged/without_status")
    arfr(f, [c + "test_resp_header_scoped_keep"], keep("resp_header:429.retry-after"), "",
         {"retry-after": "60", "x-secret": "hidden", "content-type": JSON}, "", 429)
    arfr(f, [c + "test_resp_header_scoped_mask_overrides_generic_keep"],
         keep("resp_header.x-trace-id") + [{"path": "resp_header:500.x-trace-id", "action": "mask"}], "",
         {"x-trace-id": "trace-abc", "content-type": JSON}, "", 500)
    arfr(f, [c + "test_resp_header_scoped_keep_wrong_status_no_effect"], keep("resp_header:429.retry-after"), "",
         {"retry-after": "60", "content-type": JSON}, "", 200)
    arfr(f, [c + "test_credential_header_not_unmasked_by_wrong_status_scoped_keep"],
        keep("resp_header:401.set-cookie"),
         "", {"set-cookie": "session=abc; HttpOnly", "content-type": JSON}, "", 200)
    arfr(f, [c + "test_credential_header_can_be_unmasked_by_matching_status_scoped_keep"],
         keep("resp_header:401.set-cookie"), "", {"set-cookie": "session=abc; HttpOnly",
             "content-type": JSON}, "", 401)
    arfr(f, [c + "test_non_credential_header_unmasked_by_status_scoped_keep"], keep("resp_header:200.x-trace-id"), "",
         {"x-trace-id": "trace-abc", "content-type": JSON}, "", 200)

    # --- compile_and_mask: rules compiled from lists, then mask_known ---------
    c = M + "TestCompileRules::"
    cam(f, [c + "test_field_masks_lowercased"], ["Password", "  TOKEN  "])
    cam(f, [c + "test_empty_replace_becomes_masked"], regex_masks=[{"pattern": "foo", "replace": ""}])
    c = M + "TestMaskObject::"
    cam(f, [c + "test_field_mask_replaces_value"], ["password"], body=json.dumps({"password": "s3cr3t",
        "user": "alice"}))
    cam(f, [c + "test_field_mask_no_recursion_into_masked_value"], ["nested"],
        body=json.dumps({"nested": {"password": "s3cr3t", "inner": "x"}}))
    cam(f, [c + "test_field_mask_case_insensitive"], ["authorization"],
        body=json.dumps({"Authorization": "Bearer tok"}))
    cam(f, [c + "test_regex_applied_to_strings"],
        regex_masks=[{"pattern": r"Bearer\s+\S+", "replace": "<token>", "flags": ""}],
        body=json.dumps({"note": "Bearer abc123xyz"}))
    cam(f, [c + "test_regex_order_respected"],
        regex_masks=[{"pattern": "hello", "replace": "hi", "flags": ""},
                     {"pattern": "hi world", "replace": "greetings", "flags": ""}],
        body=json.dumps({"msg": "hello world"}))
    cam(f, [c + "test_case_insensitive_regex_flag"],
        regex_masks=[{"pattern": "secret_value", "replace": "<x>", "flags": "i"}],
        body=json.dumps({"val": "SECRET_VALUE"}))
    cam(f, [c + "test_numbers_unchanged_by_field_absent"], body=json.dumps({"count": 42, "rate": 3.14}))
    cam(f, [c + "test_list_recursion"], regex_masks=[{"pattern": "b", "replace": "X", "flags": ""}],
        body=json.dumps({"tags": ["a", "b", "c"]}))
    cam(f, [c + "test_non_json_body_regex_applied"],
        regex_masks=[{"pattern": r"\b\d{16}\b", "replace": "<masked-cc>", "flags": ""}],
        body="card 4111111111111111 charged", ct="text/plain")
    cam(f, [c + "test_non_json_body_no_matching_regex_unchanged"],
        regex_masks=[{"pattern": r"\d{16}", "replace": "X", "flags": ""}], body="hello world", ct="text/plain")
    c = M + "TestHeaderAllowlist::"
    hdr = {"content-type": JSON, "host": "example.com", "authorization": "Bearer tok", "x-custom": "value",
           "cookie": "session=abc"}
    cam(f, [c + "test_mask_known_header_allowlist"], body="{}", headers=hdr)
    # The names in sorted order, so that the file does not depend on set iteration order.
    allow = {name: "value" for name in sorted(HEADER_ALLOWLIST)}
    cam(f, [c + "test_all_allowlisted_names"], body="{}", headers=allow, ct="",
        name="privacy_modules/all_allowlisted_names/mask_known")
    c = M + "TestQueryMasking::"
    cam(f, [c + "test_mask_known_field_mask_in_query"], ["secret"], body="{}", query="secret=abc&safe=123")
    cam(f, [c + "test_mask_known_regex_on_unmasked_query"], regex_masks=[{"pattern": r"\d+", "replace": "0",
        "flags": ""}],
        body="{}", query="page=5&q=abc")
    cam(f, [c + "test_empty_query_string"], body="{}")
    cam(f, [M + "TestFreeTextFormBody::test_mask_known_treats_it_as_text"],
        regex_masks=[{"pattern": "PIN is \\d+", "replace": "PIN"}], body="Dear SECRET, your PIN is 1234", ct=FORM)

    # --- mask_all: header allowlist -------------------------------------------
    c = M + "TestHeaderAllowlist::"
    mall(f, [c + "test_mask_all_header_allowlist"], "{}", hdr)
    mall(f, [c + "test_all_allowlisted_names"], "{}", allow, ct="",
        name="privacy_modules/all_allowlisted_names/mask_all")

    # --- image bodies ----------------------------------------------------------
    def img(name, content_type, py):
        add(f, "binary_placeholder", py, {"content_type": content_type}, "privacy_modules/" + name)

    ii = M + "TestIsImage::"
    pm = M + "TestPlaceholderMagicBytes::"
    img("image_png", "image/png", [ii + "test_image_png", pm + "test_png_magic", pm + "test_placeholder_for_png"])
    img("image_jpeg", "image/jpeg", [ii + "test_image_jpeg", pm + "test_jpeg_magic",
        pm + "test_placeholder_for_jpeg"])
    img("image_gif", "image/gif", [ii + "test_image_gif", pm + "test_gif_magic", pm + "test_placeholder_for_gif",
                                   pm + "test_gif_starts_with_gif89a"])
    img("image_webp", "image/webp", [ii + "test_image_webp", pm + "test_unknown_image_subtype_falls_back_to_png"])
    img("image_jpg_alias", "image/jpg", [pm + "test_placeholder_for_jpg_alias"])
    img("image_avif", "image/avif", [pm + "test_unknown_image_star_falls_back_to_png"])
    img("image_png_charset", "image/png; charset=utf-8", [ii + "test_with_charset_param"])
    img("image_png_q_param", "image/png; q=0.9", [pm + "test_placeholder_for_with_charset"])
    img("image_mixed_case", "Image/PNG", [ii + "test_case_insensitive"])
    img("not_image_json", "application/json", [ii + "test_non_image"])
    img("not_image_html", "text/html", [ii + "test_non_image"])
    img("not_image_empty", "", [ii + "test_non_image"])
    img("not_image_video", "video/mp4", [ii + "test_non_image"])


# ===========================================================================
# masking-pipeline-vectors.json
# ===========================================================================
def gen_pipeline():
    f = PIPELINE
    c = P + "TestPipelineBasicOutput::"
    pp(f, [c + "test_returns_dict_with_required_keys", c + "test_sdk_masked_always_true",
           c + "test_domain_parsed_from_url", P + "TestPipelineNewPathArrays::test_all_four_arrays_are_lists",
           P + "TestPipelineImageBody::test_non_image_body_has_no_encoding_field"],
       exchange(), name="pipeline/basic_output_default")
    pp(f, [c + "test_method_uppercased"], exchange(method="get"))
    pp(f, [c + "test_status_field"], exchange(resp_status=201))
    pp(f, [c + "test_query_string_in_path_is_masked"],
        exchange(url="https://api.example.com/v1/orders?secret=abc123&page=1"))
    c = P + "TestPipelineNewPathArrays::"
    pp(f, [c + "test_key_paths_present_for_req_body"], exchange(req_body='{"user": {"email": "x"}, "amount": 99}'))
    pp(f, [c + "test_resp_key_paths_present_for_resp_body"],
       exchange(resp_body='{"id": 1, "status": "ok", "meta": {"ts": 123}}'))
    pp(f, [c + "test_resp_key_paths_empty_for_empty_resp_body"], exchange(resp_body=""))
    pp(f, [c + "test_req_header_names_lowercased"],
       exchange(req_headers={"Content-Type": JSON, "Authorization": "Bearer tok", "X-Request-Id": "req-123"}))
    pp(f, [c + "test_resp_header_names_lowercased"],
       exchange(resp_headers={"Content-Type": JSON, "X-Trace-Id": "trace-abc"}))
    pp(f, [c + "test_query_names_present"],
       exchange(url="https://api.example.com/v1/orders?page=2&sort=asc&tag=foo&tag=bar"))
    pp(f, [c + "test_query_names_empty_when_no_query"], exchange(url="https://api.example.com/v1/orders"))
    pp(f, [c + "test_resp_key_paths_values_never_sent"], exchange(resp_body='{"secret": "hunter2", "count": 42}'))
    pp(f, [M + "TestExtractKeypaths::test_values_excluded"],
        exchange(req_body=json.dumps({"secret": "super_secret_value"})))

    c = P + "TestPipelineKnownFingerprint::"
    body = '{"amount": 50, "user_id": 7}'
    pp(f, [c + "test_known_fp_not_novel"], exchange(req_body=body), known(body, keep("body.amount")))
    body = '{"amount": 50, "secret": "tok"}'
    pp(f, [c + "test_keep_field_rule_applied"], exchange(req_body=body), known(body, keep("body.amount")))
    body = '{"amount": 50, "name": "alice"}'
    pp(f, [c + "test_mask_field_rule_applied"], exchange(req_body=body), known(body, []))

    c = P + "TestPipelineRespFieldRules::"
    act = '{"action": "buy"}'
    pp(f, [c + "test_resp_kept_field_survives"],
       exchange(req_body=act, resp_body=json.dumps({"id": 42, "secret": "tok"})), known(act, keep("resp.id")))
    pp(f, [c + "test_resp_unlisted_field_masked_typed_placeholder"],
       exchange(req_body=act, resp_body=json.dumps({"id": 7, "status": "ok", "active": True})), known(act, []))
    amount = '{"amount": 99}'
    pp(f, [c + "test_resp_body_rules_independent_of_req_body_rules"],
       exchange(req_body=amount, resp_body=json.dumps({"amount": 99, "secret": "tok"})), known(amount,
           keep("body.amount")))
    act = '{"action": "query"}'
    pp(f, [c + "test_resp_kept_email_sent_verbatim"],
       exchange(req_body=act, resp_body=json.dumps({"note": "contact alice@example.com please", "id": 1})),
       known(act, keep("resp.note", "resp.id")))
    act = '{"action": "list"}'
    pp(f, [c + "test_resp_array_fail_closed"],
       exchange(req_body=act, resp_body=json.dumps({"items": [{"price": 10, "secret": "x"}]})),
       known(act, keep("resp.items.[].price")))
    act = '{"action": "get"}'
    pp(f, [c + "test_resp_nested_keep_rule"],
       exchange(req_body=act, resp_body=json.dumps({"user": {"name": "alice", "token": "secret"}})),
       known(act, keep("resp.user.name")))

    # --- project defaults ------------------------------------------------------
    c = P + "TestProjectDefaults::"
    body = json.dumps({"note": "contact alice@example.com for details", "count": 1})
    pp(f, [c + "test_synced_project_defaults_mask_kept_string_matching_regex"], exchange(req_body=body),
       known(body, keep("body.note"), defaults={
           "field_masks": [],
           "regex_masks": [{"pattern": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
                            "replace": "<masked>", "flags": ""}]}))
    body = json.dumps({"token": "super-secret", "count": 5})
    pp(f, [c + "test_synced_project_defaults_field_mask_applied_on_kept_path"], exchange(req_body=body),
       known(body, keep("body.token"), defaults={"field_masks": ["token"], "regex_masks": []}))
    body = json.dumps({"note": "reach ana@example.com please", "card": "4111111111111111", "count": 2})
    pp(f, [c + "test_absent_project_defaults_kept_values_sent_verbatim"], exchange(req_body=body),
       known(body, keep("body.note", "body.card")))
    body = json.dumps({"kept": "ana@example.com", "unkept": "bo@example.com"})
    pp(f, [c + "test_value_type_label_does_not_decide_masking"], exchange(req_body=body),
       known(body, keep("body.kept")), salt="test-salt")
    pp(f, [c + "test_get_project_defaults_returns_none_before_sync"], None)
    body = json.dumps({"x": 1})
    pp(f, [c + "test_get_project_defaults_returns_compiled_rules_after_sync"], None,
       known(body, [], defaults={"field_masks": ["secret"], "regex_masks": []}))
    body = json.dumps({"note": "contact carol@example.com please", "x": 1})
    pp(f, [c + "test_empty_project_defaults_kept_email_sent_verbatim"], exchange(req_body=body),
       known(body, keep("body.note"), defaults={"field_masks": [], "regex_masks": []}))

    c = P + "TestPipelineProjectFieldMasks::"
    password = "hunter2"
    query = f"password={password}&page=2"
    req_body = json.dumps({
        "password": password,
        "user": {"name": "Ana", "Password": password},
        "items": [{"sku": "A1", "password": password}],
        "reset": {"password": {"old": password, "new": password}},
        "history": {"password": [{"hint": password}]},
        "count": 3,
    })
    resp_body = json.dumps({"id": 9, "password": password, "pin": {"password": password}})
    rules = keep(
        "body.password", "body.user.name", "body.user.Password", "body.items.[].sku", "body.items.[].password",
        "body.reset.password.old", "body.reset.password.new", "body.count", "body.history.password.[].hint",
        "resp:200.pin.password", "resp_header:200.x-password", "query.password", "query.page",
        "header.x-password", "header.x-trace", "resp.id", "resp.password", "resp_header.x-password",
        "resp_header.x-trace")
    pp(f, [c + "test_field_masks_override_keep_in_posted_payload"],
       exchange(url=f"https://api.example.com/v1/orders?{query}",
                req_headers={"Content-Type": JSON, "X-Password": password, "X-Trace": "t-1"}, req_body=req_body,
                resp_headers={"Content-Type": JSON, "X-Password": password, "X-Trace": "t-2"}, resp_body=resp_body),
       known(req_body, rules, query, defaults={"field_masks": ["password", " X-Password "], "regex_masks": []}))
    body = f"username=ana&password={password}"
    pp(f, [c + "test_field_masks_override_keep_in_form_body"], exchange(req_headers={"Content-Type": FORM},
        req_body=body),
       [ok(sync_body(fp_of(body, "", FORM), keep("body.username", "body.password"),
                     defaults={"field_masks": ["password"], "regex_masks": []}))])

    # --- image bodies ----------------------------------------------------------
    c = P + "TestPipelineImageBody::"
    pp(f, [c + "test_req_body_image_replaced_with_base64_placeholder"],
       exchange(req_headers={"Content-Type": "image/gif"}, req_body="real-gif-pixels"))
    pp(f, [c + "test_resp_body_image_replaced_with_base64_placeholder"],
       exchange(resp_headers={"Content-Type": "image/png"}, resp_body="real-png-pixels"))
    pp(f, [c + "test_image_body_novel_flag"], exchange(req_headers={"Content-Type": "image/png"}, req_body="pixels"))

    # --- repeated query names --------------------------------------------------
    c = P + "TestPipelineMultiValuedQuery::"
    pp(f, [c + "test_multi_valued_query_all_masked_in_novel"],
       exchange(url="https://api.example.com/v1/orders?tag=foo&tag=bar&secret=xyz"))
    pp(f, [c + "test_multi_valued_query_key_names_preserved"],
        exchange(url="https://api.example.com/v1/orders?tag=foo&tag=bar"))

    # --- fingerprint value paths -----------------------------------------------
    value_config = {"api.example.com|POST|/v1/rpc": ["action"]}
    pp(f, [P + "TestPipelineFingerprintValueDiscrimination::test_fingerprint_value_paths_never_contains_values"],
       exchange(url="https://api.example.com/v1/rpc", req_body=json.dumps({"action": "supersecret"})),
       [ok(sync_body("placeholder", [], path_template="/v1/rpc", value_config=value_config))])

    # --- value types in the payload --------------------------------------------
    c = V + "TestPipelineValueTypes::"
    pp(f, [c + "test_req_value_types_in_payload"],
       exchange(url="https://api.example.com/v1/charge", req_headers={"content-type": JSON},
                req_body=json.dumps({"user_id": 42, "email": "a@b.com"}), resp_headers={"content-type": JSON},
                resp_body=json.dumps({"ok": True})))
    pp(f, [c + "test_resp_value_types_in_payload"],
       exchange(method="GET", url="https://api.example.com/v1/charge/1", req_headers={}, req_body="",
                resp_headers={"content-type": JSON},
                resp_body=json.dumps({"charge_id": "ch_3Nk9BQ2eZvKYlo2C1b2X", "amount": 999})))
    pp(f, [c + "test_value_types_omitted_when_empty"],
       exchange(url="https://api.example.com/v1/test", req_headers={"content-type": JSON},
                req_body=json.dumps({"active": True, "deleted": False}), resp_headers={"content-type": JSON},
                resp_body=""))


# ===========================================================================
# masking-values-vectors.json
# ===========================================================================
SALT = "test-salt-value-1234"


def ph(name, py, semantic_type, values, salt=SALT, domain=None):
    add(VALUES, "placeholder", py, {"semantic_type": semantic_type, "values": [typed(v) for v in values],
                                    "salt": salt, "email_domain": domain}, "placeholders/" + name)


def gen_values():
    f = VALUES
    c = PH + "TestDeterminism::"
    for n, (sem, value) in enumerate([
        ("email", "alice@example.com"), ("uuid", "any-string"), ("iso8601", "2024-01-01T00:00:00Z"),
        ("e164", "+12025550100"), ("iban", "DE44500105175407324931"), ("url", "https://example.com/path"),
        ("decimal_amount", "99.99"), ("decimal_amount", 99.99), ("decimal_amount", 100), ("integer_id", 42),
        ("opaque_token", "tok_abc123"), ("free_text", "Hello, World!")]):
        ph(f"same_output_on_repeated_calls/{sem}-{type(value).__name__}", [c + "test_same_output_on_repeated_calls"],
           sem, [value])
    ph("deterministic_across_salt_values/salt-aaaa", [c + "test_deterministic_across_salt_values"], "email",
       ["user@example.com"], salt="salt-aaaa")
    ph("deterministic_across_salt_values/salt-bbbb", [c + "test_deterministic_across_salt_values"], "email",
       ["user@example.com"], salt="salt-bbbb")

    c = PH + "TestUniqueness::"
    for sem in ("email", "uuid", "iso8601", "e164", "iban", "url", "opaque_token", "free_text"):
        ph(f"different_string_values_differ/{sem}", [c + "test_different_string_values_differ"], sem,
           ["value-one", "value-two"])
    ph("different_integer_ids_differ", [c + "test_different_integer_ids_differ"], "integer_id", [1, 2])
    ph("different_decimal_amounts_differ", [c + "test_different_decimal_amounts_differ"], "decimal_amount", [1, 2])

    c = PH + "TestReferentialIntegrity::"
    ph("same_email_at_two_paths", [c + "test_same_email_at_two_paths"], "email",
       ["alice@prod.example.com", "alice@prod.example.com"])
    ph("same_uuid_at_two_paths", [c + "test_same_uuid_at_two_paths"], "uuid",
       ["550e8400-e29b-41d4-a716-446655440000", "550e8400-e29b-41d4-a716-446655440000"])
    ph("two_different_emails_remain_distinct", [c + "test_two_different_emails_remain_distinct"], "email",
       ["alice@example.com", "bob@example.com"])

    c = PH + "TestFormatValidity::"
    ph("email_parseable", [c + "test_email_parseable", c + "test_email_uses_default_domain_when_none",
                           PH + "TestEmailDomain::test_default_domain_stub_invalid"], "email", ["user@example.com"])
    ph("email_uses_configured_domain", [c + "test_email_uses_configured_domain"], "email", ["user@example.com"],
       domain="acme.stub.invalid")
    ph("uuid_valid", [c + "test_uuid_valid"], "uuid", ["original-value"])
    ph("iso8601_parseable", [c + "test_iso8601_parseable"], "iso8601", ["2024-01-01T00:00:00Z"])
    ph("iso8601_components_in_range", [c + "test_iso8601_components_in_range"], "iso8601", ["anything"])
    ph("e164_format", [c + "test_e164_format"], "e164", ["+447700900123"])
    ph("iban_mod97", [c + "test_iban_mod97"], "iban", ["GB29NWBK60161331926819"])
    ph("iban_mod97_spread", [c + "test_iban_mod97_spread"], "iban", [f"account-{n}" for n in range(200)])
    ph("iban_nl_prefix", [c + "test_iban_nl_prefix"], "iban", ["some-account"])
    ph("url_parseable", [c + "test_url_parseable"], "url", ["https://example.com/api/v1/users"])
    ph("decimal_amount_string_input", [c + "test_decimal_amount_string_input"], "decimal_amount", ["12.99"])
    ph("decimal_amount_float_input", [c + "test_decimal_amount_float_input"], "decimal_amount", [12.99])
    ph("decimal_amount_int_input", [c + "test_decimal_amount_int_input"], "decimal_amount", [100])
    ph("integer_id_positive", [c + "test_integer_id_positive"], "integer_id", [42])
    ph("opaque_token_is_string", [c + "test_opaque_token_is_string"], "opaque_token", ["tok_abc123xyz"])
    ph("free_text_is_string", [c + "test_free_text_is_string"], "free_text", ["Hello World"])

    c = PH + "TestSaltAbsent::"
    for sem, value in [("email", "user@example.com"), ("uuid", "some-uuid"), ("iso8601", "2024-01-01"),
                       ("e164", "+1234567890"), ("iban", "GB29NWBK..."), ("url", "https://x.com"),
                       ("opaque_token", "tok_abc"), ("free_text", "anything"), ("integer_id", 123),
                       ("decimal_amount", 9.99), ("decimal_amount", 9), ("decimal_amount", "9.99"),
                       ("currency_code", "USD"), ("country_code", "US")]:
        ph(f"constant_when_salt_none/{sem}-{type(value).__name__}", [c + "test_constant_when_salt_none"], sem,
           [value], salt=None)
    ph("bool_is_always_false/no_salt", [c + "test_bool_is_always_false",
        PH + "TestLowCardinality::test_bool_returns_false_without_salt"],
       "free_text", [True], salt=None)
    ph("bool_is_always_false/salt", [c + "test_bool_is_always_false"], "email", [True])
    ph("none_stays_none/no_salt", [c + "test_none_stays_none"], "email", [None], salt=None)
    ph("none_stays_none/salt", [c + "test_none_stays_none"], "email", [None])
    ph("get_salt/absent", [c + "test_get_salt_returns_none_when_env_absent"], "email", [], salt=None)
    ph("get_salt/present", [c + "test_get_salt_returns_bytes_when_env_present"], "email", [], salt="mysecret")
    ph("get_salt/truncates_long_key", [c + "test_get_salt_truncates_long_key"], "email", [], salt="x" * 200)

    c = PH + "TestLowCardinality::"
    for sem, value in [("currency_code", "USD"), ("currency_code", "EUR"), ("country_code", "US"), ("country_code",
        "DE")]:
        ph(f"string_low_cardinality_returns_constant/{sem}-{value}",
            [c + "test_string_low_cardinality_returns_constant"],
           sem, [value])
    ph("bool_returns_false_with_salt/email", [c + "test_bool_returns_false_with_salt"], "email", [True])
    ph("bool_returns_false_with_salt/uuid", [c + "test_bool_returns_false_with_salt"], "uuid", [False])

    c = PH + "TestHintMismatch::"
    ph("integer_id_on_string_returns_digit_string", [c + "test_integer_id_on_string_returns_digit_string"],
        "integer_id", ["42"])
    ph("integer_id_on_string_differs_from_int", [c + "test_integer_id_on_string_differs_from_int"], "integer_id",
        ["7", 7])
    ph("integer_id_on_float_returns_zero", [c + "test_integer_id_on_float_returns_zero"], "integer_id", [3.14])
    ph("iso8601_on_int_returns_zero", [c + "test_iso8601_on_int_returns_zero"], "iso8601", [1234567890])
    ph("uuid_on_int_returns_zero", [c + "test_uuid_on_int_returns_zero"], "uuid", [42])
    ph("email_on_int_returns_zero", [c + "test_email_on_int_returns_zero"], "email", [100])
    ph("email_on_float_returns_zero", [c + "test_email_on_float_returns_zero"], "email", [3.14])
    ph("url_on_int_returns_zero", [c + "test_url_on_int_returns_zero"], "url", [999])
    ph("iban_on_int_returns_zero", [c + "test_iban_on_int_returns_zero"], "iban", [42])
    ph("opaque_token_on_int_returns_zero", [c + "test_opaque_token_on_int_returns_zero"], "opaque_token", [55])
    ph("decimal_amount_on_bool_returns_false", [c + "test_decimal_amount_on_bool_returns_false"], "decimal_amount",
        [True])
    ph("free_text_on_int_returns_zero", [c + "test_free_text_on_int_returns_zero"], "free_text", [42])

    c = PH + "TestEmailDomain::"
    ph("custom_domain_applied", [c + "test_custom_domain_applied"], "email", ["user@real.com"],
        domain="acme.stub.invalid")
    ph("none_domain_falls_back_to_default", [c + "test_none_domain_falls_back_to_default"], "email",
        ["user@real.com"])
    ph("different_domains_give_different_addresses/a", [c + "test_different_domains_give_different_addresses"],
        "email",
       ["user@real.com"], domain="a.stub.invalid")
    ph("different_domains_give_different_addresses/b", [c + "test_different_domains_give_different_addresses"],
        "email",
       ["user@real.com"], domain="b.stub.invalid")

    # --- placeholders through the field rules ---------------------------------
    c = PH + "TestFieldRulesIntegration::"
    typed_rule = lambda path, sem: [{"path": path, "action": "mask", "type": sem}]  # noqa: E731
    afr(f, [c + "test_email_placeholder_in_body"], typed_rule("body.email", "email"),
        json.dumps({"email": "alice@example.com"}), salt="integration-salt",
            name="placeholders/email_placeholder_in_body")
    afr(f, [c + "test_email_placeholder_uses_passed_domain"], typed_rule("body.email", "email"),
        json.dumps({"email": "alice@example.com"}), salt="integration-salt", domain="proj.stub.invalid",
        name="placeholders/email_placeholder_uses_passed_domain")
    afr(f, [c + "test_uuid_placeholder_in_body"], typed_rule("body.request_id", "uuid"),
        json.dumps({"request_id": "550e8400-e29b-41d4-a716-446655440000"}), salt="integration-salt",
        name="placeholders/uuid_placeholder_in_body")
    afr(f, [c + "test_no_salt_gives_constant"], typed_rule("body.email", "email"),
        json.dumps({"email": "alice@example.com"}), name="placeholders/no_salt_gives_constant")
    afr(f, [c + "test_integer_id_hint_on_string_stays_string"], typed_rule("body.id", "integer_id"),
        json.dumps({"id": "ch_3Nk..."}), salt="integration-salt",
            name="placeholders/integer_id_hint_on_string_stays_string")
    arfr(f, [c + "test_iso8601_placeholder_in_resp_body"], typed_rule("resp.created_at", "iso8601"),
         json.dumps({"created_at": "2023-06-01T12:00:00Z"}), salt="integration-salt",
         name="placeholders/iso8601_placeholder_in_resp_body")
    afr(f, [c + "test_determinism_across_two_calls"], typed_rule("body.user_id", "opaque_token"),
        json.dumps({"user_id": "usr_abc123"}), salt="stable-salt", name="placeholders/determinism_across_two_calls")
    afr(f, [c + "test_rule_without_type_still_uses_constant"], [{"path": "body.secret", "action": "mask"}],
        json.dumps({"secret": "super-secret-value"}), salt="any-salt",
            name="placeholders/rule_without_type_still_uses_constant")
    rules = typed_rule("resp:200.created_at", "iso8601")
    cfr(f, [c + "test_status_scoped_mask_rule_with_type"], rules,
        name="placeholders/status_scoped_mask_rule_with_type/compiled")
    arfr(f, [c + "test_status_scoped_mask_rule_with_type"], rules, json.dumps({"created_at": "2023-06-01T12:00:00Z"}),
         status=200, salt="integration-salt", name="placeholders/status_scoped_mask_rule_with_type/applied")

    # --- value types ---------------------------------------------------------
    def sc(py, src, name=None):
        add(f, "classify_scalar", [py], {"json": src}, name or _derive(py))

    c = V + "TestClassifyScalar::"
    for test, value in [
        ("test_uuid_lowercase", "550e8400-e29b-41d4-a716-446655440000"),
        ("test_uuid_uppercase", "550E8400-E29B-41D4-A716-446655440000"),
        ("test_uuid_beats_free_text", "f47ac10b-58cc-4372-a567-0e02b2c3d479"),
        ("test_iso8601_date", "2024-03-15"), ("test_iso8601_datetime_t", "2024-03-15T12:34:56Z"),
        ("test_iso8601_datetime_space", "2024-03-15 12:34:56"),
        ("test_email", "user@example.com"), ("test_email_plus", "user+tag@sub.example.org"),
        ("test_e164", "+441234567890"), ("test_e164_min_digits", "+1234567"), ("test_e164_too_short", "+12345"),
        ("test_iban", "GB29NWBK60161331926819"), ("test_iban_de", "DE89370400440532013000"),
        ("test_url_https", "https://example.com/path?q=1"), ("test_url_http", "http://api.example.com/v1/users"),
        ("test_currency_code", "EUR"), ("test_currency_code_usd", "USD"),
        ("test_country_code", "NL"), ("test_country_code_us", "US"),
        ("test_three_letters_is_currency_not_country", "GBP"),
        ("test_decimal_string", "19.99"), ("test_decimal_negative", "-5.00"),
        ("test_opaque_token_not_emitted_for_api_key", "sk_live_abc1234xyz"),
        ("test_opaque_token_not_emitted_for_mixed_alphanumeric", "a1b2c3d4e5"),
        ("test_opaque_token_not_emitted_for_stripe_id", "ch_3Nk9BQ2eZvKYlo2C1b2XNpO8"),
        ("test_free_text_with_spaces", "hello world"), ("test_free_text_short", "pending"),
        ("test_free_text_all_alpha_long", "pendingpayment"), ("test_free_text_label", "active"),
        ("test_integer_string_classifies_integer_id", "42"), ("test_integer_string_large", "1000000"),
        ("test_integer_string_zero", "0"), ("test_integer_string_negative", "-5"),
        ("test_iban_too_short_rejected", "EU20240001"), ("test_iban_batch_ref_rejected", "GB12BATCH01"),
        ("test_iban_short_code_rejected", "US24XLBLUE"), ("test_real_iban_gb_still_matches",
            "GB29NWBK60161331926819"),
        ("test_shortest_real_iban_matches", "NO9386011117947"),
        ("test_longest_real_iban_matches", "MT84MALT011000012345MTLCAST001S"),
        ("test_uuid_not_free_text", "550e8400-e29b-41d4-a716-446655440000"), ("test_email_not_free_text", "a@b.co"),
    ]:
        sc(c + test, json.dumps(value))
    sc(c + "test_integer_string_before_decimal", json.dumps("42"), "value_types/integer_string_before_decimal/int")
    sc(c + "test_integer_string_before_decimal", json.dumps("42.0"),
        "value_types/integer_string_before_decimal/decimal")
    for test, src in [("test_decimal_float", "1.99"), ("test_integer", "42"), ("test_integer_zero", "0"),
                      ("test_integer_large", "9999999"), ("test_bool_true_omitted", "true"),
                      ("test_bool_false_omitted", "false"), ("test_none_omitted", "null"),
                      ("test_dict_omitted", '{"a": 1}'), ("test_list_omitted", "[1, 2]")]:
        sc(c + test, src)

    def vt(py, body, ct):
        add(f, "extract_value_types", [py], {"body": body, "content_type": ct})

    c = V + "TestExtractValueTypes::"
    vt(c + "test_flat_json", json.dumps({"id": 42, "email": "a@b.com", "active": True}), JSON)
    vt(c + "test_nested_json", json.dumps({"user": {"id": 7, "name": "Alice"}}), JSON)
    vt(c + "test_array_of_objects", json.dumps({"items": [{"price": 9.99, "sku": "ITEM1234AB"}]}), JSON)
    vt(c + "test_scalar_array", json.dumps({"tags": ["active", "pending"]}), JSON)
    vt(c + "test_root_array", json.dumps([{"id": 1}, {"id": 2}]), JSON)
    vt(c + "test_booleans_and_nulls_omitted", json.dumps({"flag": True, "missing": None, "count": 5}), JSON)
    vt(c + "test_form_encoded", "amount=19.99&currency=EUR&note=hello+world", FORM)
    vt(c + "test_malformed_body_no_raise", "{not valid json}", JSON)
    vt(c + "test_empty_body", "", JSON)
    vt(c + "test_whitespace_only_body", "   ", JSON)
    vt(c + "test_non_json_content_type_no_raise", "hello world", "text/plain")


# ===========================================================================
# fail-closed-vectors.json
# ===========================================================================
def gen_closed():
    f = CLOSED
    # --- bodies that are not JSON ----------------------------------------------
    c = P + "TestApplyFieldRules::"
    afr(f, [c + "test_form_encoded_body_fail_closed"], [], "username=alice&password=s3cr3t", ct=FORM)
    afr(f, [c + "test_non_json_body_becomes_masked"], [], "raw text", ct="text/plain")

    # --- novel fingerprints ----------------------------------------------------
    c = P + "TestPipelineNovelFingerprint::"
    pp(f, [c + "test_novel_flag_when_fingerprint_unknown"], exchange())
    pp(f, [c + "test_body_is_fully_masked_on_novel"], exchange(req_body='{"password": "s3cr3t", "count": 5}'))
    pp(f, [P + "TestPipelineRespFieldRules::test_resp_novel_fingerprint_fully_masked"],
       exchange(resp_body=json.dumps({"id": 7, "email": "user@example.com"})))
    pp(f, [P + "TestApplyRespFieldRulesHeaderIndependence::test_novel_fingerprint_resp_headers_fully_masked"],
       exchange(resp_headers={"content-type": JSON, "x-secret": "tok"}))

    # --- project defaults that cannot be used ----------------------------------
    c = P + "TestProjectDefaults::"
    body = json.dumps({"note": "hello", "count": 3})
    pp(f, [c + "test_uncompilable_project_regex_masks_kept_strings"], exchange(req_body=body),
       known(body, keep("body.note", "body.count"), defaults={"field_masks": [],
           "regex_masks": [{"pattern": "[[["}]}))
    body = json.dumps({"amount": 50})
    pp(f, [c + "test_malformed_project_defaults_poll_still_lands_cursor_and_rules"], exchange(req_body=body),
       known(body, keep("body.amount"), cursor="99",
             defaults={"field_masks": [1, None, True], "regex_masks": [{"pattern": None}]}))
    body = json.dumps({"note": "hello", "n": 1})
    for n, defaults in enumerate([[], "rules", 5]):
        pp(f, [c + f"test_project_defaults_not_an_object_masks_kept_strings[{['project_defaults0', 'rules', '5'][n]}]"],
           exchange(req_body=body), known(body, keep("body.note", "body.n"), defaults=defaults),
           name=f"pipeline/project_defaults_not_an_object_masks_kept_strings/{['list', 'string', 'number'][n]}")
    body = json.dumps({"password": "hunter2", "note": "hello", "n": 1})
    pp(f, [c + "test_malformed_entry_keeps_the_valid_field_masks"], exchange(req_body=body),
       known(body, keep("body.password", "body.note", "body.n"),
             defaults={"field_masks": ["password"], "regex_masks": [{"pattern": 5}]}))

    # --- a sync that does not deliver rules ------------------------------------
    c = P + "TestPipelineSyncNotFound::"
    email, card, password, token = "ana@example.com", "4111111111111111", "hunter2", "tok_dummy_123"
    request = exchange(
        url=f"https://api.example.com/v1/orders?email={email}&page=2",
        req_headers={"Content-Type": JSON, "Authorization": f"Bearer {token}", "X-User": email},
        req_body=json.dumps({"user": {"email": email, "password": password}, "card": card, "amount": 99,
            "gift": True}),
        resp_headers={"Content-Type": JSON, "Set-Cookie": f"s={token}"},
        resp_body=json.dumps({"id": 7, "receipt_email": email}))
    not_found = {"status": 404, "body": None}
    pp(f, [c + "test_404_posts_fully_masked_payload"], request, [not_found])
    pp(f, [c + "test_404_does_not_mark_rules_synced"], None, [not_found])
    body = json.dumps({"id": 5})
    pp(f, [c + "test_404_after_sync_keeps_synced_rules"], exchange(req_body=body),
       known(body, keep("body.id")) + [not_found])
    c = P + "TestRulesCacheCursorAndTemplates::"
    pp(f, [c + "test_network_error_keeps_previous_cache"], None,
       [ok(sync_body("fp1", [], cursor="5")), {"status": 0, "body": None}])
    pp(f, [c + "test_wait_for_first_sync_returns_true_after_poll"], None, [ok(sync_body("abc", [], cursor="7"))])
    pp(f, [c + "test_wait_for_first_sync_not_set_on_network_error"], None, [{"status": 0, "body": None}],
       name="pipeline/wait_for_first_sync_not_set_on_network_error")
    pp(f, [c + "test_wait_for_first_sync_not_set_on_non_200"], None, [{"status": 500, "body": None}])

    # --- the regex cap and unusable rules, on every path -----------------------
    c = P + "TestRegexCapAndUnusableOnEveryPath::"
    rules = keep("body.a", "query.a", "resp.a")

    def every_path(label, value, defaults, py, with_name):
        enc = urllib.parse.quote(value)
        afr(f, [py], rules, json.dumps({"a": value}), {}, f"a={enc}", JSON, defaults,
            name=f"pipeline/{with_name}/json_body_and_query/{label}")
        afr(f, [py], rules, f"a={enc}", {}, "", FORM, defaults, name=f"pipeline/{with_name}/form_body/{label}")
        arfr(f, [py], rules, json.dumps({"a": value}), {}, JSON, 200, defaults,
            name=f"pipeline/{with_name}/resp_body/{label}")

    cap = {"field_masks": [], "regex_masks": [{"pattern": "zzz", "replace": "x"}]}
    every_path("over_cap", "a" * (MAX_REGEX_SCAN_CHARS + 1), cap, c + "test_string_over_cap_masked_on_every_path",
               "string_over_cap_masked_on_every_path")
    every_path("at_cap", "a" * MAX_REGEX_SCAN_CHARS, cap, c + "test_string_over_cap_masked_on_every_path",
               "string_over_cap_masked_on_every_path")
    every_path("hello", "hello", {"field_masks": [], "regex_masks": [{"pattern": "[[["}]},
        c + "test_unusable_rules_mask_every_path",
               "unusable_rules_mask_every_path")
    cam(f, [c + "test_unusable_rules_mask_text_plain_in_mask_known"], regex_masks=[{"pattern": "[[["}], body="hello",
        ct="text/plain")
    c = M + "TestMaskObject::"
    at_cap = "a" * MAX_REGEX_SCAN_CHARS
    cam(f, [c + "test_long_string_masked_without_running_regex"], regex_masks=[{"pattern": "zzz", "replace": "x"}],
        body=at_cap, ct="text/plain", name="privacy_modules/long_string_masked_without_running_regex/at_cap")
    cam(f, [c + "test_long_string_masked_without_running_regex"], regex_masks=[{"pattern": "zzz", "replace": "x"}],
        body=at_cap + "a", ct="text/plain", name="privacy_modules/long_string_masked_without_running_regex/over_cap")
    cam(f, [c + "test_long_string_kept_when_no_regex_active"], ["f"], body="a" * (MAX_REGEX_SCAN_CHARS + 1),
        ct="text/plain")

    # --- rules that cannot be compiled -----------------------------------------
    cam(f, [c + "test_invalid_regex_fails_closed"], regex_masks=[{"pattern": "[[[", "replace": "x"}],
        body=json.dumps({"val": "hello", "n": 1}))
    c = M + "TestCompileRules::"
    cam(f, [c + "test_invalid_regex_marks_rules_unusable"],
        regex_masks=[{"pattern": "ok", "replace": "x"}, {"pattern": "[invalid(", "replace": "x"}])
    cam(f, [c + "test_repeat_count_python_cannot_represent_marks_unusable"],
        regex_masks=[{"pattern": "a{99999999999}", "replace": "x"}])
    malformed = [
        ([], [{"pattern": 5}]), ([], [{"pattern": ""}]), ([], [{}]), ([], ["not an object"]),
        ([], [{"pattern": "a", "replace": 5}]), ([], [{"pattern": "a", "flags": 5}]), ([], {"pattern": "a"}),
        ([1, "ok"], []), ("password", []),
    ]
    ids = ["field_masks0-regex_masks0", "field_masks1-regex_masks1", "field_masks2-regex_masks2",
           "field_masks3-regex_masks3", "field_masks4-regex_masks4", "field_masks5-regex_masks5",
           "field_masks6-regex_masks6", "field_masks7-regex_masks7", "password-regex_masks8"]
    for n, (field_masks, regex_masks) in enumerate(malformed):
        cam(f, [c + f"test_malformed_entry_marks_unusable[{ids[n]}]"], field_masks, regex_masks,
            name=f"privacy_modules/malformed_entry_marks_unusable/{n}")
    cam(f, [c + "test_malformed_entry_keeps_the_rest"], [1, "Secret"], [{"pattern": 5}, {"pattern": "ok",
        "replace": "x"}])
    cam(f, [c + "test_valid_regexes_not_unusable"], regex_masks=[{"pattern": "ok", "replace": "x"}])

    # --- mask_all --------------------------------------------------------------
    mall(f, [M + "TestQueryMasking::test_mask_all_query"], "{}", {}, "a=1&b=2")
    c = M + "TestMaskAllStructure::"
    mall(f, [c + "test_json_structure_preserved"],
         json.dumps({"user": {"name": "Alice", "age": 30}, "active": True, "score": None}))
    mall(f, [c + "test_root_array_structure_preserved"], json.dumps([{"id": 1, "val": "x"}, {"id": 2, "val": "y"}]))
    mall(f, [c + "test_non_json_body_becomes_masked_string"], "not json", ct="text/plain")
    mall(f, [c + "test_form_encoded_field_names_kept"], "username=alice&password=s3cr3t", ct=FORM)
    c = M + "TestFreeTextFormBody::"
    text = "Dear SECRET, your PIN is 1234"
    for label, text_body, ident in [("free_text", text, text), ("segment_without_equals", "a=1&Dear SECRET",
        "a=1&Dear SECRET")]:
        mall(f, [c + f"test_mask_all_masks_the_whole_body[{ident}]"], text_body, ct=FORM,
             name=f"privacy_modules/mask_all_masks_the_whole_body/{label}")
    mall(f, [c + "test_mask_all_keeps_a_valid_form"], "a=1&b=", ct=FORM)
    for label, text_body in [("free_text", text), ("segment_without_equals", "a=1&Dear SECRET"),
                             ("valid_with_odd_segments", "a=1&&b=&c=x=y&"), ("empty", "")]:
        add(f, "parse_form", [c + "test_parse_form_rejects_a_segment_without_equals"], {"body": text_body},
            f"privacy_modules/parse_form_rejects_a_segment_without_equals/{label}")
    for label, text_body in [("free_text", text), ("segment_without_equals", "a=1&Dear SECRET")]:
        for op, key in (("extract_keypaths", "key_paths"), ("extract_value_types", "value_types")):
            add(f, op, [c + "test_no_key_paths_value_types_or_value_pairs"], {"body": text_body,
                "content_type": FORM},
                f"privacy_modules/no_key_paths_value_types_or_value_pairs/{op}/{label}")
    rules = keep("body.a", "body.Dear SECRET", "resp.a")
    afr(f, [c + "test_field_rules_mask_the_whole_body_even_with_a_keep"], rules, "a=1&Dear SECRET", ct=FORM,
        name="privacy_modules/field_rules_mask_the_whole_body_even_with_a_keep/request")
    arfr(f, [c + "test_field_rules_mask_the_whole_body_even_with_a_keep"], rules, text, ct=FORM, status=200,
         name="privacy_modules/field_rules_mask_the_whole_body_even_with_a_keep/response")

    # --- malformed status scopes -----------------------------------------------
    c = M + "TestStatusScopedFieldRules::"
    for test, path in [("test_malformed_non_digit_status_ignored", "resp:abc.x"),
                       ("test_malformed_one_digit_status_ignored", "resp:1.x"),
                       ("test_malformed_two_digit_status_ignored", "resp:99.x"),
                       ("test_malformed_out_of_range_600_ignored", "resp:600.x"),
                       ("test_malformed_leading_zero_ignored", "resp:0404.x"),
                       ("test_malformed_no_subpath_ignored", "resp:404"),
                       ("test_malformed_empty_subpath_ignored", "resp:404."),
                       ("test_superscript_digits_ignored_no_exception", "resp:²²².error"),
                       ("test_arabic_indic_digits_ignored_no_exception", "resp:٤٠٤.error")]:
        cfr(f, [c + test], keep(path))
    cfr(f, [c + "test_malformed_never_raises"], keep("resp:abc.x", "resp:1.x", "resp:99.x", "resp:600.x",
        "resp:0404.x",
                                                    "resp:404", "resp:404."))
    arfr(f, [c + "test_conflict_mask_wins_body"],
         keep("resp:200.name") + [{"path": "resp:200.name", "action": "mask"}], json.dumps({"name": "Alice",
             "id": 1}),
         status=200)
    arfr(f, [c + "test_conflict_mask_wins_header"],
         keep("resp_header:200.x-custom") + [{"path": "resp_header:200.x-custom", "action": "mask"}], "",
         {"x-custom": "val", "content-type": JSON}, "", 200)


# ===========================================================================
# Descriptions
# ===========================================================================
OPS_DOC = {
    "compile_field_rules": (
        "input {field_rules}; expected the compiled sets as sorted lists: keep_body, keep_query, keep_header, "
            "keep_resp, "
        "keep_resp_header, keep_resp_status, mask_resp_status, keep_resp_header_status, mask_resp_header_status (the "
            "last "
        "four as [status, path] pairs sorted by status then path), and the objects body_mask_types, query_mask_types, "
        "resp_mask_types."),
    "apply_field_rules": (
        "input {field_rules, body, headers, query, content_type, project_defaults, salt, email_domain}; compile the "
            "field "
        "rules, then mask a request. project_defaults is null or {field_masks, regex_masks}, compiled as the project's "
        "extra rules. salt is the STUBSMITH_MASK_SALT string (null means unset). email_domain null means the default. "
        "expected {body, headers, query}, compared as exact text."),
    "apply_resp_field_rules": (
        "same input as apply_field_rules without query, plus resp_status (an integer or null); expected {body, "
            "headers}."),
    "compile_and_mask": (
        "input {field_masks, regex_masks, body, headers, query, content_type}; compile the two lists as the project's "
        "mask rules (any JSON, including malformed values), then mask_known. expected {rules: {unusable, field_masks "
        "(sorted), regex_replacements (the replacement text of each usable regex, in order)}, body, headers, query}."),
    "mask_all": "input {body, headers, query, content_type}; expected {body, headers, query}.",
    "parse_form": "input {body}; expected {result}: null for a body that is not key=value pairs, else the parsed "
        "{name: [values]}.",
    "binary_placeholder": (
        "input {content_type}; expected {is_image, subtype, data_base64}: the last two are null unless the type is "
            "an image, "
        "otherwise the placeholder's canonical subtype and its bytes in base64."),
    "pipeline_process": (
        "input {polls, request, salt}; salt is the STUBSMITH_MASK_SALT string or null; build an empty rules cache "
            "and feed it each poll in order, as the answer of the sync "
        "endpoint ({status, body}: status 0 is a network error, body null when there is none), then process request "
        "({method, url, req_headers, req_body, resp_status, resp_headers, resp_body}) unless it is null. expected "
        "{payload, cache}: payload is the whole payload without sdk_version (each SDK checks its own), or null; "
            "cache is "
        "{cursor, first_sync_done, project_defaults}, where project_defaults is null or {field_masks (sorted), "
            "regex_count, "
        "unusable}."),
    "placeholder": (
        "input {semantic_type, values, salt, email_domain}; values are typed scalars {type: str|int|float|bool|none, "
            "value or text}, with text the Python repr of a float and the decimal digits of an int; the key is the "
                "salt string as UTF-8 "
        "truncated to 64 bytes (null or empty means no key). Each value is generated twice and the two results must "
            "be equal. "
        "expected {salt_key_hex, outputs} with typed outputs."),
    "classify_scalar": "input {json}: JSON source text of one value, parsed as Python json.loads does; expected "
        "{label} (null for no label).",
    "extract_keypaths": "input {body, content_type}; expected {key_paths}, the list of key paths in order.",
    "extract_value_types": "input {body, content_type}; expected {value_types}.",
}

COMMON = (
    "Shared vectors: the Python SDK is the source of truth and any other SDK runs the same file and must reproduce "
    "every expected value exactly. Each case is {name, op, input, expected}; op names one of the operations below. "
    "JSON bodies are source text, masked bodies are Python json.dumps text, and form and query output is "
    "urlencode(doseq=True) text; compare them as strings. A string of many equal characters is written "
    "{\"$repeat\": \"a\", \"times\": 65537}, and a string made of such parts {\"$concat\": [...]}; expand them "
        "before use."
)

NOT_VECTORISED = {
    MASKING: [
        ("tests/test_privacy_modules.py::TestCompileRules::test_i_flag_prepends_prefix",
         "reads the Python pattern string for (?i); the behaviour is in case_insensitive_regex_flag"),
        ("tests/test_placeholders.py::TestFormatValidity::test_iban_mod97_boundary_check98",
         "calls the private generator with crafted bytes"),
        ("tests/test_value_types.py::TestClassifyScalar::test_never_raises_on_bytes",
         "a bytes value is not JSON"),
        ("tests/test_classifier_spec.py::TestGeneratedFromSpec and TestSpecExamples (7 tests)",
         "driven by the shared classifier spec file, not by these vectors"),
        ("tests/test_capture.py: the requests and httpx capture tests, the userinfo and free-text form tests, the "
         "prepared-request test, the streaming and stream-guard tests, and the debug-logging and refusal-warning tests",
         "need a real HTTP exchange through the instrumented client, or log capture"),
        ("tests/test_pipeline.py::TestClientPipelineIntegration::test_pipeline_payload_enqueued_with_source_and_duration",
         "needs a real HTTP exchange and the client queue"),
    ],
    CLOSED: [
        ("tests/test_pipeline.py::TestProjectDefaults::test_project_defaults_that_fail_to_compile_mask_kept_strings",
         "patches compile_rules to raise"),
        ("tests/test_pipeline.py::TestPipelineFailClosed (3 tests) and "
            "tests/test_value_types.py::TestPipelineValueTypes::test_catastrophic_failure_returns_none",
         "patch the masker or the URL parser to raise"),
        ("tests/test_pipeline.py::TestPipelineSyncNotFound::test_404_logs_one_warning_naming_404_and_backend_url and "
            "the three other 404 warning tests",
         "assert on log records"),
        ("tests/test_pipeline.py::TestRulesCacheCursorAndTemplates::test_wait_for_first_sync_times_out_when_backend_unreachable",
         "asserts on a timeout"),
        ("tests/test_pipeline.py::TestClientPipelineIntegration::test_privacy_init_failure_drops_capture_not_raw",
         "patches the cache constructor and sends through a real client"),
        ("tests/test_privacy_modules.py::TestCompileRules::test_invalid_regex_warns_once", "asserts on log records"),
        ("tests/test_privacy_modules.py::TestFreeTextFormBody::test_no_key_paths_value_types_or_value_pairs "
         "(the _extract_value_pairs assertion only; the key path and value type assertions are cases)",
         "calls a private helper that has no operation"),
        ("tests/test_first_sync_hold.py (8 tests)", "need threads, timing and a capture queue"),
        ("tests/test_capture.py::test_multipart_upload_records_type_but_no_fabricated_body and test_disabled_*",
         "need a real HTTP exchange or the client options"),
        ("tests/test_replay.py::TestInstallInteraction (2 tests) and "
            "tests/test_cli.py::TestSummaryWarnings::test_degraded_stubs_surfaced",
         "need the replay engine or the command line"),
    ],
}

DESCRIPTIONS = {
    MASKING: ["compile_field_rules", "apply_field_rules", "apply_resp_field_rules", "compile_and_mask", "mask_all",
              "binary_placeholder"],
    PIPELINE: ["pipeline_process"],
    VALUES: ["placeholder", "apply_field_rules", "apply_resp_field_rules", "compile_field_rules", "classify_scalar",
             "extract_value_types"],
    CLOSED: ["apply_field_rules", "apply_resp_field_rules", "compile_field_rules", "compile_and_mask", "mask_all",
             "parse_form", "extract_keypaths", "extract_value_types", "pipeline_process"],
}

PURPOSE = {
    MASKING: "Masking behaviour of the field rules, the project mask rules, the header allowlist and image bodies. ",
    PIPELINE: "Masking behaviour of the whole pipeline, for known and unknown fingerprints. ",
    VALUES: "Format-preserving placeholders, their use through field rules, and the observed value types. ",
    CLOSED: "Fail-closed behaviour: whatever cannot be understood or used is masked, never sent. ",
}


def description(file: str) -> str:
    ops = "\n".join(f"- {op}: {OPS_DOC[op]}" for op in DESCRIPTIONS[file])
    text = PURPOSE[file] + COMMON + "\nOperations used in this file:\n" + ops
    if file in NOT_VECTORISED:
        lines = "\n".join(f"- {test}: {why}" for test, why in NOT_VECTORISED[file])
        text += "\nNot vectorised (each stays a test in its own repository):\n" + lines
    return text


SOURCES = {
    MASKING: "stubsmith.privacy.field_rules, masking, binary (via tests/shared_vector_ops.py)",
    PIPELINE: "stubsmith.privacy.pipeline.PrivacyPipeline.process, rules_cache (via tests/shared_vector_ops.py)",
    VALUES: "stubsmith.privacy.placeholders, field_rules, fingerprint (via tests/shared_vector_ops.py)",
    CLOSED: "stubsmith.privacy.field_rules, masking, pipeline (via tests/shared_vector_ops.py)",
}


def build() -> Dict[str, str]:
    """Run the generator and return the text of every file, without writing anything."""
    for cases in CASES.values():
        cases.clear()
    REGISTRY.clear()
    gen_masking()
    gen_pipeline()
    gen_values()
    gen_closed()
    out = {}
    for file, cases in CASES.items():
        # The stored form must expand back to exactly what the SDK was run on.
        stored = [
            {"name": c["name"], "op": c["op"], "input": compress(c["input"]), "expected": compress(c["expected"])}
            for c in cases
        ]
        for c, st in zip(cases, stored):
            assert expand(st["input"]) == c["input"] and expand(st["expected"]) == c["expected"], c["name"]
        doc = {"description": description(file), "source": SOURCES[file], "cases": stored}
        out[file] = json.dumps(doc, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    return out


def main() -> None:
    files = build()
    if "--map" in sys.argv:
        print(json.dumps(REGISTRY, indent=1))
        return
    for file, text in files.items():
        (OUT / file).write_text(text, encoding="utf-8")
        print(f"{file}: {len(CASES[file])}")


if __name__ == "__main__":
    main()
