"""
Tests for stubsmith.privacy.placeholders and its integration with field_rules.

All tests are offline.  No network, no real STUBSMITH_MASK_SALT env var is
assumed in the test process - each test that needs a salt passes one explicitly.
"""

from __future__ import annotations

import json
import os
import uuid as _uuid_module
from datetime import datetime, timezone
from typing import Any
from unittest import mock

import pytest

from stubsmith.privacy.placeholders import (
    DEFAULT_EMAIL_DOMAIN,
    SEMANTIC_TYPE_VOCAB,
    _constant_for,
    _gen_decimal_amount,
    _gen_e164,
    _gen_email,
    _gen_free_text,
    _gen_iban,
    _gen_integer_id,
    _gen_iso8601,
    _gen_opaque_token,
    _gen_url,
    _gen_uuid,
    generate,
    get_salt,
)
from stubsmith.privacy.field_rules import (
    apply_field_rules,
    apply_resp_field_rules,
    compile_field_rules,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SALT = b"test-salt-value-1234"   # arbitrary fixed salt for determinism tests


def _hash_bytes(value: Any, salt: bytes = _SALT) -> bytes:
    """Reproduce the 16-byte BLAKE2b digest used by generate()."""
    import hashlib
    return hashlib.blake2b(
        str(value).encode("utf-8"), key=salt, digest_size=16
    ).digest()


def _iban_valid(iban: str) -> bool:
    """Validate IBAN mod-97 checksum.  Returns True for a valid IBAN."""
    # Move first four chars to end, convert letters to digits, check mod 97 == 1.
    rearranged = iban[4:] + iban[:4]
    numeric = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    return int(numeric) % 97 == 1


# ---------------------------------------------------------------------------
# 1. Determinism
# ---------------------------------------------------------------------------

class TestDeterminism:
    """Same (value, salt, type) always produces the same output."""

    @pytest.mark.parametrize("sem_type,value", [
        ("email",         "alice@example.com"),
        ("uuid",          "any-string"),
        ("iso8601",       "2024-01-01T00:00:00Z"),
        ("e164",          "+12025550100"),
        ("iban",          "DE44500105175407324931"),
        ("url",           "https://example.com/path"),
        ("decimal_amount", "99.99"),
        ("decimal_amount", 99.99),
        ("decimal_amount", 100),
        ("integer_id",    42),
        ("opaque_token",  "tok_abc123"),
        ("free_text",     "Hello, World!"),
    ])
    def test_same_output_on_repeated_calls(self, sem_type, value):
        first  = generate(sem_type, value, _SALT)
        second = generate(sem_type, value, _SALT)
        assert first == second, f"Non-deterministic output for {sem_type!r} + {value!r}"

    def test_deterministic_across_salt_values(self):
        salt_a = b"salt-aaaa"
        salt_b = b"salt-bbbb"
        out_a = generate("email", "user@example.com", salt_a)
        out_b = generate("email", "user@example.com", salt_b)
        # Different salts must differ
        assert out_a != out_b


# ---------------------------------------------------------------------------
# 2. Uniqueness
# ---------------------------------------------------------------------------

class TestUniqueness:
    """Different inputs (with the same salt) produce different outputs."""

    @pytest.mark.parametrize("sem_type", [
        "email", "uuid", "iso8601", "e164", "iban", "url", "opaque_token", "free_text",
    ])
    def test_different_string_values_differ(self, sem_type):
        out1 = generate(sem_type, "value-one", _SALT)
        out2 = generate(sem_type, "value-two", _SALT)
        assert out1 != out2, f"Collision for {sem_type!r} with distinct inputs"

    def test_different_integer_ids_differ(self):
        assert generate("integer_id", 1, _SALT) != generate("integer_id", 2, _SALT)

    def test_different_decimal_amounts_differ(self):
        assert generate("decimal_amount", 1, _SALT) != generate("decimal_amount", 2, _SALT)


# ---------------------------------------------------------------------------
# 3. Referential integrity
# ---------------------------------------------------------------------------

class TestReferentialIntegrity:
    """The same production value at two different field paths yields the same fake value.

    generate() does not take a path argument - only (type, value, salt) - so
    two paths holding the same original value automatically produce the same
    placeholder, preserving cross-field relationships after masking.
    """

    def test_same_email_at_two_paths(self):
        prod_email = "alice@prod.example.com"
        ph_path_a = generate("email", prod_email, _SALT)
        ph_path_b = generate("email", prod_email, _SALT)
        assert ph_path_a == ph_path_b

    def test_same_uuid_at_two_paths(self):
        prod_id = "550e8400-e29b-41d4-a716-446655440000"
        assert generate("uuid", prod_id, _SALT) == generate("uuid", prod_id, _SALT)

    def test_two_different_emails_remain_distinct(self):
        ph1 = generate("email", "alice@example.com", _SALT)
        ph2 = generate("email", "bob@example.com", _SALT)
        assert ph1 != ph2


# ---------------------------------------------------------------------------
# 4. Format validity per type
# ---------------------------------------------------------------------------

class TestFormatValidity:
    def test_email_parseable(self):
        out = generate("email", "user@example.com", _SALT)
        assert isinstance(out, str)
        assert "@" in out
        local, domain = out.split("@", 1)
        assert local and domain

    def test_email_uses_default_domain_when_none(self):
        out = generate("email", "user@example.com", _SALT)
        assert out.endswith(f"@{DEFAULT_EMAIL_DOMAIN}")

    def test_email_uses_configured_domain(self):
        out = generate("email", "user@example.com", _SALT, email_domain="acme.stub.invalid")
        assert out.endswith("@acme.stub.invalid")

    def test_uuid_valid(self):
        out = generate("uuid", "original-value", _SALT)
        parsed = _uuid_module.UUID(out)   # raises ValueError if malformed
        assert str(parsed) == out
        assert parsed.version == 4
        assert (parsed.int >> 62) & 0x3 == 0x2   # RFC 4122 variant

    def test_iso8601_parseable(self):
        out = generate("iso8601", "2024-01-01T00:00:00Z", _SALT)
        assert isinstance(out, str)
        # datetime.fromisoformat handles "+00:00" on Python 3.7+; no workaround needed.
        dt = datetime.fromisoformat(out)
        assert dt is not None

    def test_iso8601_components_in_range(self):
        out = generate("iso8601", "anything", _SALT)
        # Must be of the form YYYY-MM-DDTHH:MM:SS+00:00
        date_part, rest = out.split("T")
        time_part = rest[:-6]   # strip "+00:00"
        assert out.endswith("+00:00")
        year, month, day = (int(x) for x in date_part.split("-"))
        hour, minute, second = (int(x) for x in time_part.split(":"))
        assert 2000 <= year <= 2023
        assert 1 <= month <= 12
        assert 1 <= day <= 28
        assert 0 <= hour <= 23
        assert 0 <= minute <= 59
        assert 0 <= second <= 59

    def test_e164_format(self):
        out = generate("e164", "+447700900123", _SALT)
        assert isinstance(out, str)
        assert out.startswith("+")
        assert out[1:].isdigit()
        assert len(out) >= 7   # minimum E.164 length

    def test_iban_mod97(self):
        out = generate("iban", "GB29NWBK60161331926819", _SALT)
        assert isinstance(out, str)
        assert _iban_valid(out), f"IBAN mod-97 check failed for {out!r}"

    def test_iban_mod97_boundary_check98(self):
        # BBAN=ABCD0000000072 is a known input where check=98 (mod97_result=0),
        # the boundary the old clamp silently mis-handled by emitting NL97…
        # instead of the correct NL98…, producing an invalid IBAN.
        # Drive _gen_iban directly with bytes crafted to produce that BBAN:
        #   b[0]%26==0 (→'A'), b[1]%26==1 (→'B'), b[2]%26==2 (→'C'),
        #   b[3]%26==3 (→'D'), b[4..11]%10==0, b[12]%10==7, b[13]%10==2.
        from stubsmith.privacy.placeholders import _gen_iban
        crafted = bytes([0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 7, 2, 0, 0])
        iban = _gen_iban(crafted)
        assert iban.startswith("NL98"), (
            f"Expected NL98… for BBAN=ABCD0000000072 but got {iban!r} - "
            "check=98 is valid per spec; clamp bug may have been reintroduced"
        )
        assert _iban_valid(iban), f"IBAN mod-97 check failed for {iban!r}"

    def test_iban_mod97_spread(self):
        # Validate mod-97 correctness across 200 distinct inputs.  A single
        # spot-check cannot detect a ~1% boundary failure (one in every 97
        # inputs hits check=98 when the old clamp was present).
        for i in range(200):
            value = f"account-{i}"
            out = generate("iban", value, _SALT)
            assert _iban_valid(out), (
                f"IBAN mod-97 check failed for input {value!r}: {out!r}"
            )

    def test_iban_nl_prefix(self):
        out = generate("iban", "some-account", _SALT)
        assert out.startswith("NL")

    def test_url_parseable(self):
        import urllib.parse
        out = generate("url", "https://example.com/api/v1/users", _SALT)
        assert isinstance(out, str)
        parsed = urllib.parse.urlparse(out)
        assert parsed.scheme == "https"
        assert parsed.netloc

    def test_decimal_amount_string_input(self):
        out = generate("decimal_amount", "12.99", _SALT)
        assert isinstance(out, str)
        float(out)   # must be parseable as a number

    def test_decimal_amount_float_input(self):
        out = generate("decimal_amount", 12.99, _SALT)
        assert isinstance(out, float)
        assert out > 0

    def test_decimal_amount_int_input(self):
        out = generate("decimal_amount", 100, _SALT)
        assert isinstance(out, int)
        assert out > 0

    def test_integer_id_positive(self):
        out = generate("integer_id", 42, _SALT)
        assert isinstance(out, int)
        assert not isinstance(out, bool)
        assert out > 0

    def test_opaque_token_is_string(self):
        out = generate("opaque_token", "tok_abc123xyz", _SALT)
        assert isinstance(out, str)
        assert len(out) > 0

    def test_free_text_is_string(self):
        out = generate("free_text", "Hello World", _SALT)
        assert isinstance(out, str)
        assert len(out) > 0


# ---------------------------------------------------------------------------
# 5. Salt absent means constant behavior (compatibility guarantee)
# ---------------------------------------------------------------------------

class TestSaltAbsent:
    """With salt=None the output is byte-identical to the pre-placeholder constants."""

    @pytest.mark.parametrize("sem_type,value,expected", [
        ("email",          "user@example.com", "<masked>"),
        ("uuid",           "some-uuid",        "<masked>"),
        ("iso8601",        "2024-01-01",        "<masked>"),
        ("e164",           "+1234567890",       "<masked>"),
        ("iban",           "GB29NWBK...",       "<masked>"),
        ("url",            "https://x.com",     "<masked>"),
        ("opaque_token",   "tok_abc",           "<masked>"),
        ("free_text",      "anything",          "<masked>"),
        ("integer_id",     123,                 0),
        ("decimal_amount", 9.99,                0),
        ("decimal_amount", 9,                   0),
        ("decimal_amount", "9.99",              "<masked>"),
        ("currency_code",  "USD",               "<masked>"),
        ("country_code",   "US",                "<masked>"),
    ])
    def test_constant_when_salt_none(self, sem_type, value, expected):
        out = generate(sem_type, value, None)
        assert out == expected, (
            f"Expected constant {expected!r} for {sem_type!r}/{type(value).__name__} "
            f"when salt is None, got {out!r}"
        )

    def test_bool_is_always_false(self):
        assert generate("free_text", True, None) is False
        assert generate("email",     True, _SALT) is False

    def test_none_stays_none(self):
        assert generate("email", None, None) is None
        assert generate("email", None, _SALT) is None

    def test_get_salt_returns_none_when_env_absent(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            # Ensure the env var is absent
            os.environ.pop("STUBSMITH_MASK_SALT", None)
            assert get_salt() is None

    def test_get_salt_returns_bytes_when_env_present(self):
        with mock.patch.dict(os.environ, {"STUBSMITH_MASK_SALT": "mysecret"}):
            s = get_salt()
            assert s == b"mysecret"

    def test_get_salt_truncates_long_key(self):
        long_val = "x" * 200
        with mock.patch.dict(os.environ, {"STUBSMITH_MASK_SALT": long_val}):
            s = get_salt()
            assert len(s) == 64


# ---------------------------------------------------------------------------
# 6. Low-cardinality refusal
# ---------------------------------------------------------------------------

class TestLowCardinality:
    @pytest.mark.parametrize("sem_type,value,expected", [
        ("currency_code", "USD", "<masked>"),
        ("currency_code", "EUR", "<masked>"),
        ("country_code",  "US",  "<masked>"),
        ("country_code",  "DE",  "<masked>"),
    ])
    def test_string_low_cardinality_returns_constant(self, sem_type, value, expected):
        out = generate(sem_type, value, _SALT)
        assert out == expected

    def test_bool_returns_false_with_salt(self):
        assert generate("email", True,  _SALT) is False
        assert generate("uuid",  False, _SALT) is False

    def test_bool_returns_false_without_salt(self):
        assert generate("free_text", True, None) is False


# ---------------------------------------------------------------------------
# 7. Hint-mismatch fallbacks
# ---------------------------------------------------------------------------

class TestHintMismatch:
    """A wrong type hint must not change the JSON type of the output."""

    def test_integer_id_on_string_returns_digit_string(self):
        # integer_id on a string input returns a digit string (preserves JSON type).
        out = generate("integer_id", "42", _SALT)
        assert isinstance(out, str), f"expected str, got {type(out).__name__}"
        assert out.lstrip("-").isdigit(), f"expected digit string, got {out!r}"

    def test_integer_id_on_string_differs_from_int(self):
        # Same value but different input types produce different JSON types in output.
        out_str = generate("integer_id", "7", _SALT)
        out_int = generate("integer_id", 7, _SALT)
        assert isinstance(out_str, str)
        assert isinstance(out_int, int)

    def test_integer_id_on_float_returns_zero(self):
        out = generate("integer_id", 3.14, _SALT)
        assert isinstance(out, (int, float))
        assert out == 0

    def test_iso8601_on_int_returns_zero(self):
        out = generate("iso8601", 1234567890, _SALT)
        assert out == 0

    def test_uuid_on_int_returns_zero(self):
        out = generate("uuid", 42, _SALT)
        assert out == 0

    def test_email_on_int_returns_zero(self):
        out = generate("email", 100, _SALT)
        assert out == 0

    def test_email_on_float_returns_zero(self):
        out = generate("email", 3.14, _SALT)
        assert out == 0

    def test_url_on_int_returns_zero(self):
        out = generate("url", 999, _SALT)
        assert out == 0

    def test_iban_on_int_returns_zero(self):
        out = generate("iban", 42, _SALT)
        assert out == 0

    def test_opaque_token_on_int_returns_zero(self):
        out = generate("opaque_token", 55, _SALT)
        assert out == 0

    def test_decimal_amount_on_bool_returns_false(self):
        # Booleans are caught before the hint validation.
        out = generate("decimal_amount", True, _SALT)
        assert out is False

    def test_free_text_on_int_returns_zero(self):
        # free_text is a string-type generator; int input → mismatch → constant 0.
        out = generate("free_text", 42, _SALT)
        assert out == 0


# ---------------------------------------------------------------------------
# 8. Email domain routing
# ---------------------------------------------------------------------------

class TestEmailDomain:
    def test_default_domain_stub_invalid(self):
        out = generate("email", "user@real.com", _SALT)
        assert out.endswith(f"@{DEFAULT_EMAIL_DOMAIN}")
        assert DEFAULT_EMAIL_DOMAIN == "stub.invalid"

    def test_custom_domain_applied(self):
        out = generate("email", "user@real.com", _SALT, email_domain="acme.stub.invalid")
        assert out.endswith("@acme.stub.invalid")

    def test_none_domain_falls_back_to_default(self):
        out = generate("email", "user@real.com", _SALT, email_domain=None)
        assert out.endswith(f"@{DEFAULT_EMAIL_DOMAIN}")

    def test_different_domains_give_different_addresses(self):
        domain_a = generate("email", "user@real.com", _SALT, email_domain="a.stub.invalid")
        domain_b = generate("email", "user@real.com", _SALT, email_domain="b.stub.invalid")
        assert domain_a != domain_b


# ---------------------------------------------------------------------------
# 9. Integration with field_rules - wire-through tests
# ---------------------------------------------------------------------------

class TestFieldRulesIntegration:
    """Verify that format-preserving generation flows through apply_field_rules."""

    def _make_rules(self, path: str, sem_type: str):
        return compile_field_rules([{"path": path, "action": "mask", "type": sem_type}])

    def test_email_placeholder_in_body(self):
        body = json.dumps({"email": "alice@example.com"})
        rules = self._make_rules("body.email", "email")
        with mock.patch.dict(os.environ, {"STUBSMITH_MASK_SALT": "integration-salt"}):
            out_body, _, _ = apply_field_rules(
                body, {}, "", "application/json", rules
            )
        parsed = json.loads(out_body)
        email_val = parsed["email"]
        assert isinstance(email_val, str)
        assert "@" in email_val
        # Must be at the default domain (no email_domain passed)
        assert email_val.endswith(f"@{DEFAULT_EMAIL_DOMAIN}")

    def test_email_placeholder_uses_passed_domain(self):
        body = json.dumps({"email": "alice@example.com"})
        rules = self._make_rules("body.email", "email")
        with mock.patch.dict(os.environ, {"STUBSMITH_MASK_SALT": "integration-salt"}):
            out_body, _, _ = apply_field_rules(
                body, {}, "", "application/json", rules,
                email_domain="proj.stub.invalid",
            )
        parsed = json.loads(out_body)
        assert parsed["email"].endswith("@proj.stub.invalid")

    def test_uuid_placeholder_in_body(self):
        body = json.dumps({"request_id": "550e8400-e29b-41d4-a716-446655440000"})
        rules = self._make_rules("body.request_id", "uuid")
        with mock.patch.dict(os.environ, {"STUBSMITH_MASK_SALT": "integration-salt"}):
            out_body, _, _ = apply_field_rules(
                body, {}, "", "application/json", rules
            )
        parsed = json.loads(out_body)
        uid = _uuid_module.UUID(parsed["request_id"])   # must not raise
        assert uid.version == 4

    def test_no_salt_gives_constant(self):
        body = json.dumps({"email": "alice@example.com"})
        rules = self._make_rules("body.email", "email")
        env = {k: v for k, v in os.environ.items() if k != "STUBSMITH_MASK_SALT"}
        with mock.patch.dict(os.environ, env, clear=True):
            out_body, _, _ = apply_field_rules(
                body, {}, "", "application/json", rules
            )
        assert json.loads(out_body)["email"] == "<masked>"

    def test_integer_id_hint_on_string_stays_string(self):
        body = json.dumps({"id": "ch_3Nk..."})
        rules = self._make_rules("body.id", "integer_id")
        with mock.patch.dict(os.environ, {"STUBSMITH_MASK_SALT": "integration-salt"}):
            out_body, _, _ = apply_field_rules(
                body, {}, "", "application/json", rules
            )
        parsed = json.loads(out_body)
        # Must stay a string (digit string), not become an integer.
        assert isinstance(parsed["id"], str)
        assert parsed["id"].lstrip("-").isdigit(), f"expected digit string, got {parsed['id']!r}"

    def test_iso8601_placeholder_in_resp_body(self):
        resp_body = json.dumps({"created_at": "2023-06-01T12:00:00Z"})
        field_rules = [{"path": "resp.created_at", "action": "mask", "type": "iso8601"}]
        rules = compile_field_rules(field_rules)
        with mock.patch.dict(os.environ, {"STUBSMITH_MASK_SALT": "integration-salt"}):
            out_body, _ = apply_resp_field_rules(
                resp_body, {}, "application/json", rules
            )
        parsed = json.loads(out_body)
        val = parsed["created_at"]
        assert isinstance(val, str)
        # Must be parseable as ISO 8601 directly (no workaround for Z suffix).
        datetime.fromisoformat(val)

    def test_determinism_across_two_calls(self):
        body = json.dumps({"user_id": "usr_abc123"})
        rules = self._make_rules("body.user_id", "opaque_token")
        with mock.patch.dict(os.environ, {"STUBSMITH_MASK_SALT": "stable-salt"}):
            out1, _, _ = apply_field_rules(body, {}, "", "application/json", rules)
            out2, _, _ = apply_field_rules(body, {}, "", "application/json", rules)
        assert json.loads(out1)["user_id"] == json.loads(out2)["user_id"]

    def test_rule_without_type_still_uses_constant(self):
        """A mask rule that carries no type hint must still use the constant placeholder."""
        body = json.dumps({"secret": "super-secret-value"})
        rules = compile_field_rules([{"path": "body.secret", "action": "mask"}])
        with mock.patch.dict(os.environ, {"STUBSMITH_MASK_SALT": "any-salt"}):
            out_body, _, _ = apply_field_rules(
                body, {}, "", "application/json", rules
            )
        assert json.loads(out_body)["secret"] == "<masked>"

    def test_status_scoped_mask_rule_with_type(self):
        """Status-scoped resp:NNN.path rules with a type must honour the hint."""
        resp_body = json.dumps({"created_at": "2023-06-01T12:00:00Z"})
        field_rules_list = [
            {"path": "resp:200.created_at", "action": "mask", "type": "iso8601"},
        ]
        rules = compile_field_rules(field_rules_list)
        # Verify that resp_mask_types was populated for the status-scoped rule.
        assert "created_at" in rules.resp_mask_types
        assert rules.resp_mask_types["created_at"] == "iso8601"

        with mock.patch.dict(os.environ, {"STUBSMITH_MASK_SALT": "integration-salt"}):
            out_body, _ = apply_resp_field_rules(
                resp_body, {}, "application/json", rules, resp_status=200
            )
        parsed = json.loads(out_body)
        val = parsed["created_at"]
        assert isinstance(val, str)
        # Must be parseable as ISO 8601 directly - format-preserving, not "<masked>".
        dt = datetime.fromisoformat(val)
        assert dt is not None
