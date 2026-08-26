"""
Tests for the observed value type classifier (classify_scalar, extract_value_types)
and for the pipeline's inclusion of req_value_types / resp_value_types in the
outbound payload.

All tests are offline (no network, no DB).
"""

from __future__ import annotations

import json
from typing import Any, Optional

import pytest

from stubsmith.privacy.fingerprint import classify_scalar, extract_value_types


# ===========================================================================
# classify_scalar - every branch
# ===========================================================================

class TestClassifyScalar:

    # ── UUID ──────────────────────────────────────────────────────────────

    def test_uuid_lowercase(self):
        assert classify_scalar("550e8400-e29b-41d4-a716-446655440000") == "uuid"

    def test_uuid_uppercase(self):
        assert classify_scalar("550E8400-E29B-41D4-A716-446655440000") == "uuid"

    def test_uuid_beats_free_text(self):
        # A UUID must never fall through to opaque_token or free_text.
        result = classify_scalar("f47ac10b-58cc-4372-a567-0e02b2c3d479")
        assert result == "uuid", f"expected uuid, got {result!r}"

    # ── ISO 8601 ──────────────────────────────────────────────────────────

    def test_iso8601_date(self):
        assert classify_scalar("2024-03-15") == "iso8601"

    def test_iso8601_datetime_t(self):
        assert classify_scalar("2024-03-15T12:34:56Z") == "iso8601"

    def test_iso8601_datetime_space(self):
        assert classify_scalar("2024-03-15 12:34:56") == "iso8601"

    # ── Email ─────────────────────────────────────────────────────────────

    def test_email(self):
        assert classify_scalar("user@example.com") == "email"

    def test_email_plus(self):
        assert classify_scalar("user+tag@sub.example.org") == "email"

    # ── E.164 ─────────────────────────────────────────────────────────────

    def test_e164(self):
        assert classify_scalar("+441234567890") == "e164"

    def test_e164_min_digits(self):
        assert classify_scalar("+1234567") == "e164"   # 7 digits after +

    def test_e164_too_short(self):
        # 5 digits after +  → does not match e164 → falls through
        result = classify_scalar("+12345")
        assert result != "e164"

    # ── IBAN ──────────────────────────────────────────────────────────────

    def test_iban(self):
        assert classify_scalar("GB29NWBK60161331926819") == "iban"

    def test_iban_de(self):
        assert classify_scalar("DE89370400440532013000") == "iban"

    # ── URL ───────────────────────────────────────────────────────────────

    def test_url_https(self):
        assert classify_scalar("https://example.com/path?q=1") == "url"

    def test_url_http(self):
        assert classify_scalar("http://api.example.com/v1/users") == "url"

    # ── Currency / country codes ──────────────────────────────────────────

    def test_currency_code(self):
        assert classify_scalar("EUR") == "currency_code"

    def test_currency_code_usd(self):
        assert classify_scalar("USD") == "currency_code"

    def test_country_code(self):
        assert classify_scalar("NL") == "country_code"

    def test_country_code_us(self):
        assert classify_scalar("US") == "country_code"

    # 3-letter codes are currency, 2-letter codes are country.
    def test_three_letters_is_currency_not_country(self):
        assert classify_scalar("GBP") == "currency_code"

    # ── Decimal amount ────────────────────────────────────────────────────

    def test_decimal_float(self):
        assert classify_scalar(1.99) == "decimal_amount"

    def test_decimal_string(self):
        assert classify_scalar("19.99") == "decimal_amount"

    def test_decimal_negative(self):
        assert classify_scalar("-5.00") == "decimal_amount"

    # ── Integer ID ────────────────────────────────────────────────────────

    def test_integer(self):
        assert classify_scalar(42) == "integer_id"

    def test_integer_zero(self):
        assert classify_scalar(0) == "integer_id"

    def test_integer_large(self):
        assert classify_scalar(9999999) == "integer_id"

    # ── opaque_token is NOT emitted by the classifier ────────────────────

    def test_opaque_token_not_emitted_for_api_key(self):
        # Character composition is not a recognizable format; falls to free_text.
        result = classify_scalar("sk_live_abc1234xyz")
        assert result == "free_text"

    def test_opaque_token_not_emitted_for_mixed_alphanumeric(self):
        # Pinning test: mixed-alphanumeric must classify free_text, not opaque_token.
        result = classify_scalar("a1b2c3d4e5")
        assert result == "free_text"

    def test_opaque_token_not_emitted_for_stripe_id(self):
        # Stripe-style IDs are format-free from the classifier's perspective.
        result = classify_scalar("ch_3Nk9BQ2eZvKYlo2C1b2XNpO8")
        assert result == "free_text"

    # ── Free text ─────────────────────────────────────────────────────────

    def test_free_text_with_spaces(self):
        assert classify_scalar("hello world") == "free_text"

    def test_free_text_short(self):
        # len < 8 → free_text
        assert classify_scalar("pending") == "free_text"

    def test_free_text_all_alpha_long(self):
        # No digits → free_text
        assert classify_scalar("pendingpayment") == "free_text"

    def test_free_text_label(self):
        assert classify_scalar("active") == "free_text"

    # ── Integer string ────────────────────────────────────────────────────

    def test_integer_string_classifies_integer_id(self):
        # A bare-integer string should carry numeric character info to the server.
        assert classify_scalar("42") == "integer_id"

    def test_integer_string_large(self):
        assert classify_scalar("1000000") == "integer_id"

    def test_integer_string_zero(self):
        assert classify_scalar("0") == "integer_id"

    def test_integer_string_negative(self):
        assert classify_scalar("-5") == "integer_id"

    def test_integer_string_before_decimal(self):
        # "42" must match integer_id (no dot); "42.0" must match decimal_amount.
        assert classify_scalar("42") == "integer_id"
        assert classify_scalar("42.0") == "decimal_amount"

    # ── IBAN false-positive rejection ──────────────────────────────────────

    def test_iban_too_short_rejected(self):
        # 10 chars - below real IBAN minimum (15, Norway).
        result = classify_scalar("EU20240001")
        assert result != "iban", f"short string must not match iban, got {result!r}"

    def test_iban_batch_ref_rejected(self):
        # 11 chars - still below minimum.
        assert classify_scalar("GB12BATCH01") != "iban"

    def test_iban_short_code_rejected(self):
        # 10 chars.
        assert classify_scalar("US24XLBLUE") != "iban"

    def test_real_iban_gb_still_matches(self):
        # 22 chars - valid GB IBAN.
        assert classify_scalar("GB29NWBK60161331926819") == "iban"

    def test_shortest_real_iban_matches(self):
        # 15 chars - Norway, the shortest real IBAN, and the exact lower
        # boundary of the {11,30} trailing group.  Pins the minimum so a
        # future tightening cannot silently exclude a valid country.
        assert classify_scalar("NO9386011117947") == "iban"

    def test_longest_real_iban_matches(self):
        # 31 chars - Malta, the longest real IBAN, well inside the upper bound.
        assert classify_scalar("MT84MALT011000012345MTLCAST001S") == "iban"

    # ── Booleans and None are omitted ────────────────────────────────────

    def test_bool_true_omitted(self):
        assert classify_scalar(True) is None

    def test_bool_false_omitted(self):
        assert classify_scalar(False) is None

    def test_none_omitted(self):
        assert classify_scalar(None) is None

    # ── Non-scalar containers are omitted ────────────────────────────────

    def test_dict_omitted(self):
        assert classify_scalar({"a": 1}) is None

    def test_list_omitted(self):
        assert classify_scalar([1, 2]) is None

    # ── Never raises on unexpected input ─────────────────────────────────

    def test_never_raises_on_bytes(self):
        # bytes is not a supported type - should return None, not raise
        result = classify_scalar(b"not a string")
        assert result is None

    # ── Ordering: uuid before opaque_token / free_text ───────────────────

    def test_uuid_not_free_text(self):
        # UUID must be caught by the uuid check, not fall through to free_text.
        assert classify_scalar("550e8400-e29b-41d4-a716-446655440000") == "uuid"

    def test_email_not_free_text(self):
        assert classify_scalar("a@b.co") == "email"


# ===========================================================================
# extract_value_types - arrays, nested objects, malformed bodies
# ===========================================================================

class TestExtractValueTypes:

    def test_flat_json(self):
        body = json.dumps({"id": 42, "email": "a@b.com", "active": True})
        result = extract_value_types(body, "application/json")
        assert result["id"] == "integer_id"
        assert result["email"] == "email"
        assert "active" not in result   # bool omitted

    def test_nested_json(self):
        body = json.dumps({"user": {"id": 7, "name": "Alice"}})
        result = extract_value_types(body, "application/json")
        assert result["user.id"] == "integer_id"
        assert result["user.name"] == "free_text"

    def test_array_of_objects(self):
        body = json.dumps({"items": [{"price": 9.99, "sku": "ITEM1234AB"}]})
        result = extract_value_types(body, "application/json")
        assert result["items.[].price"] == "decimal_amount"
        # opaque_token not emitted by classifier; character composition is not a format
        assert result["items.[].sku"] == "free_text"

    def test_scalar_array(self):
        body = json.dumps({"tags": ["active", "pending"]})
        result = extract_value_types(body, "application/json")
        # Only first element walked; it's a short all-alpha string → free_text
        assert result["tags.[]"] == "free_text"

    def test_root_array(self):
        body = json.dumps([{"id": 1}, {"id": 2}])
        result = extract_value_types(body, "application/json")
        assert result["[].id"] == "integer_id"

    def test_booleans_and_nulls_omitted(self):
        body = json.dumps({"flag": True, "missing": None, "count": 5})
        result = extract_value_types(body, "application/json")
        assert "flag" not in result
        assert "missing" not in result
        assert result["count"] == "integer_id"

    def test_form_encoded(self):
        body = "amount=19.99&currency=EUR&note=hello+world"
        result = extract_value_types(body, "application/x-www-form-urlencoded")
        assert result["amount"] == "decimal_amount"
        assert result["currency"] == "currency_code"
        assert result["note"] == "free_text"

    def test_malformed_body_no_raise(self):
        result = extract_value_types("{not valid json}", "application/json")
        assert result == {}

    def test_empty_body(self):
        assert extract_value_types("", "application/json") == {}

    def test_whitespace_only_body(self):
        assert extract_value_types("   ", "application/json") == {}

    def test_non_json_content_type_no_raise(self):
        # text/plain - not parseable as JSON or form, returns {}
        result = extract_value_types("hello world", "text/plain")
        assert result == {}


# ===========================================================================
# Pipeline integration: payload includes req/resp_value_types when non-empty
# ===========================================================================

class TestPipelineValueTypes:
    """Light integration test: PrivacyPipeline emits value type maps."""

    def _make_pipeline(self):
        """Return a minimal PrivacyPipeline with a stub RulesCache."""
        from unittest import mock
        from stubsmith.privacy.pipeline import PrivacyPipeline
        from stubsmith.privacy.rules_cache import RulesCache

        cache = mock.create_autospec(RulesCache, instance=True)
        cache.get_curated_templates.return_value = []
        cache.get_value_paths.return_value = None
        cache.lookup.return_value = None          # unknown fingerprint → mask_all
        cache.get_cursor.return_value = 0
        cache.get_project_defaults.return_value = None
        cache.get_email_placeholder_domain.return_value = "stub.invalid"
        return PrivacyPipeline(cache)

    def test_req_value_types_in_payload(self):
        pipeline = self._make_pipeline()
        req_body = json.dumps({"user_id": 42, "email": "a@b.com"})
        payload = pipeline.process(
            "POST", "https://api.example.com/v1/charge",
            {"content-type": "application/json"}, req_body,
            200, {"content-type": "application/json"}, json.dumps({"ok": True}),
        )
        assert payload is not None
        vt = payload.get("req_value_types", {})
        assert vt.get("user_id") == "integer_id"
        assert vt.get("email") == "email"

    def test_resp_value_types_in_payload(self):
        pipeline = self._make_pipeline()
        resp_body = json.dumps({"charge_id": "ch_3Nk9BQ2eZvKYlo2C1b2X", "amount": 999})
        payload = pipeline.process(
            "GET", "https://api.example.com/v1/charge/1",
            {}, "",
            200, {"content-type": "application/json"}, resp_body,
        )
        assert payload is not None
        vt = payload.get("resp_value_types", {})
        # charge_id is a mixed-alphanumeric string; no recognized format → free_text
        assert vt.get("charge_id") == "free_text"
        assert vt.get("amount") == "integer_id"

    def test_value_types_omitted_when_empty(self):
        pipeline = self._make_pipeline()
        # Boolean-only body - no types emitted
        req_body = json.dumps({"active": True, "deleted": False})
        payload = pipeline.process(
            "POST", "https://api.example.com/v1/test",
            {"content-type": "application/json"}, req_body,
            200, {"content-type": "application/json"}, "",
        )
        assert payload is not None
        assert "req_value_types" not in payload
        assert "resp_value_types" not in payload

    def test_catastrophic_failure_returns_none(self):
        """Pipeline must return None on catastrophic failure, never raise."""
        from unittest import mock
        from stubsmith.privacy.pipeline import PrivacyPipeline
        from stubsmith.privacy.rules_cache import RulesCache

        cache = mock.create_autospec(RulesCache, instance=True)
        cache.get_curated_templates.side_effect = RuntimeError("boom")
        pipeline = PrivacyPipeline(cache)
        result = pipeline.process("GET", "https://example.com/", {}, "", 200, {}, "")
        assert result is None
