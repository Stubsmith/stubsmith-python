"""
Tests for the stubsmith.privacy pure modules.

Covers: fingerprint, templating, masking, binary.
All tests are offline (no network).
"""

from __future__ import annotations

import json
import urllib.parse
from typing import Any, Dict

import pytest

from stubsmith.privacy.fingerprint import (
    _canonical_scalar,
    extract_keypaths,
    fingerprint,
    resp_fingerprint,
)
from stubsmith.privacy.templating import (
    CuratedTemplate,
    _heuristic_template,
    load_curated_templates,
    template_path,
)
from stubsmith.privacy.masking import (
    HEADER_ALLOWLIST,
    CompiledRules,
    compile_rules,
    mask_all,
    mask_known,
)
from stubsmith.privacy.binary import (
    GIF_1X1,
    JPEG_1X1,
    PNG_1X1,
    is_image,
    placeholder_for,
)


# ===========================================================================
# fingerprint.py
# ===========================================================================


class TestExtractKeypaths:
    def test_flat_dict(self):
        body = json.dumps({"a": 1, "b": "hello"})
        kp = extract_keypaths(body)
        assert set(kp) == {"a", "b"}

    def test_nested_dict(self):
        body = json.dumps({"user": {"email": "x", "name": "y"}})
        kp = extract_keypaths(body)
        assert set(kp) == {"user", "user.email", "user.name"}

    def test_array_segment(self):
        body = json.dumps({"items": [{"price": 1, "qty": 2}]})
        kp = extract_keypaths(body)
        assert "items" in kp
        assert "items.[].price" in kp
        assert "items.[].qty" in kp

    def test_array_at_root(self):
        body = json.dumps([{"id": 1, "val": "x"}])
        kp = extract_keypaths(body)
        assert "[].id" in kp
        assert "[].val" in kp

    def test_empty_body_returns_empty(self):
        assert extract_keypaths("") == []
        assert extract_keypaths("   ") == []

    def test_non_json_returns_empty(self):
        assert extract_keypaths("not json at all") == []

    def test_empty_array_at_root_returns_empty(self):
        assert extract_keypaths("[]") == []

    def test_unicode_keys(self):
        body = json.dumps({"ñame": "José", "数字": 42})
        kp = extract_keypaths(body)
        assert "ñame" in kp
        assert "数字" in kp

    def test_form_encoded(self):
        body = "email=x%40x.com&name=Joe&name=Mary"
        kp = extract_keypaths(body, "application/x-www-form-urlencoded")
        assert set(kp) == {"email", "name"}

    def test_form_encoded_with_charset(self):
        body = "a=1&b=2"
        kp = extract_keypaths(body, "application/x-www-form-urlencoded; charset=utf-8")
        assert set(kp) == {"a", "b"}

    def test_values_excluded(self):
        body = json.dumps({"secret": "super_secret_value"})
        kp = extract_keypaths(body)
        assert "secret" in kp
        assert "super_secret_value" not in kp

    def test_scalar_array_emits_bracket_leaf(self):
        """Scalar arrays must emit the [] segment as a leaf path.

        Before the fix, {"items":[1,2,3]} produced only ["items"].
        After the fix it must also produce "items.[]" so that a reviewer
        keep rule on body.items.[] actually matches _walk_and_mask at
        masking time.
        """
        body = json.dumps({"items": [1, 2, 3]})
        kp = extract_keypaths(body)
        assert "items" in kp, f"parent key missing: {kp}"
        assert "items.[]" in kp, f"scalar-array leaf missing: {kp}"

    def test_scalar_array_at_root_emits_bracket_leaf(self):
        """Root-level scalar array must emit [] as the leaf."""
        body = json.dumps([1, 2, 3])
        kp = extract_keypaths(body)
        assert "[]" in kp, f"root scalar-array leaf missing: {kp}"

    def test_scalar_array_keep_round_trip(self):
        """A keep rule on items.[] must actually preserve values through masking.

        Verifies the full round-trip: extract_keypaths emits items.[]
        → compile_field_rules sees it in the keep set
        → apply_field_rules keeps the scalar elements.
        """
        from stubsmith.privacy.field_rules import apply_field_rules, compile_field_rules

        body = json.dumps({"items": [1, 2, 3], "secret": "hide-me"})
        rules = compile_field_rules([{"path": "body.items.[]", "action": "keep"}])
        # key_paths now includes "items.[]" so the keep rule is discoverable
        kp = extract_keypaths(body)
        assert "items.[]" in kp, f"items.[] not in key_paths: {kp}"
        masked_body, _, _ = apply_field_rules(body, {}, "", "application/json", rules)
        parsed = json.loads(masked_body)
        assert parsed["items"] == [1, 2, 3], f"items not kept: {parsed['items']}"
        assert parsed["secret"] == "<masked>", f"secret not masked: {parsed['secret']}"


class TestArrayElementsAreAllWalked:
    """Every element of an array contributes paths, not just the first.

    Sampling element 0 lost the shape of any array whose first entry is a
    scalar or null. The value was still masked, because the masker walks every
    element, but the path never reached the review queue, so an operator could
    not see the field and could never write a keep rule for it. It was masked
    forever with no way to discover why.
    """

    def test_object_after_a_scalar_is_reported(self):
        kp = extract_keypaths(json.dumps({"mixed": [1, {"deep": {"deeper": "x"}}]}))
        assert "mixed.[].deep.deeper" in kp

    def test_object_after_a_null_is_reported(self):
        kp = extract_keypaths(json.dumps({"rows": [None, {"late": "x"}]}))
        assert "rows.[].late" in kp

    def test_paths_are_unioned_across_differing_elements(self):
        kp = extract_keypaths(json.dumps({"rows": [{"a": 1}, {"b": 2}, {"c": 3}]}))
        for path in ("rows.[].a", "rows.[].b", "rows.[].c"):
            assert path in kp, f"{path} missing from {kp}"

    def test_repeated_shapes_are_not_duplicated(self):
        kp = extract_keypaths(json.dumps({"rows": [{"a": 1}, {"a": 2}, {"a": 3}]}))
        assert kp.count("rows.[].a") == 1

    def test_scalar_array_still_emits_the_bracket_leaf(self):
        kp = extract_keypaths(json.dumps({"tags": ["a", "b"]}))
        assert "tags.[]" in kp

    def test_fingerprint_no_longer_depends_on_element_order(self):
        """Sampling the first element made one logical endpoint fingerprint as
        two, depending on which element happened to come first."""
        a = json.dumps({"rows": [1, {"x": 1}]})
        b = json.dumps({"rows": [{"x": 1}, 1]})
        assert sorted(extract_keypaths(a)) == sorted(extract_keypaths(b))

    def test_every_reported_path_is_one_the_masker_can_reach(self):
        """The report and the masker must agree: a path shown to a reviewer
        that no keep rule can match is a rule that silently does nothing."""
        from stubsmith.privacy.field_rules import apply_field_rules, compile_field_rules

        body = json.dumps({
            "rows": [1, {"deep": {"deeper": "SECRET"}}],
            "later": [None, {"late": "ALSO"}],
        })
        # Each path is checked against its own value: asserting that *either*
        # token survived would let a rule on one path pass on the strength of
        # the other.
        for path, token, other in (
            ("rows.[].deep.deeper", "SECRET", "ALSO"),
            ("later.[].late", "ALSO", "SECRET"),
        ):
            assert path in extract_keypaths(body)
            out, _, _ = apply_field_rules(
                body, {}, "", "application/json",
                compile_field_rules([{"path": "body." + path, "action": "keep"}]),
            )
            assert token in out, f"keep rule on {path} did nothing"
            assert other not in out, f"masking leaked {other} while keeping {path}"


class TestFingerprint:
    def test_stability_same_values_same_fp(self):
        body1 = json.dumps({"user": "alice", "age": 30})
        body2 = json.dumps({"user": "bob", "age": 25})
        assert fingerprint(body1, "", "application/json") == fingerprint(
            body2, "", "application/json"
        )

    def test_new_key_new_fp(self):
        body1 = json.dumps({"user": "alice"})
        body2 = json.dumps({"user": "alice", "extra": "field"})
        assert fingerprint(body1, "", "application/json") != fingerprint(
            body2, "", "application/json"
        )

    def test_content_type_affects_fp(self):
        body = json.dumps({"a": 1})
        fp1 = fingerprint(body, "", "application/json")
        fp2 = fingerprint(body, "", "text/plain")
        assert fp1 != fp2

    def test_query_names_affect_fp(self):
        body = "{}"
        fp1 = fingerprint(body, "q=hello", "application/json")
        fp2 = fingerprint(body, "q=hello&page=1", "application/json")
        assert fp1 != fp2

    def test_multi_valued_query_dedupe(self):
        """?a=1&a=2 and ?a=3 have the same query name set → same fp."""
        body = "{}"
        ct = "application/json"
        fp1 = fingerprint(body, "a=1&a=2", ct)
        fp2 = fingerprint(body, "a=3", ct)
        assert fp1 == fp2

    def test_query_value_ignored_same_name_set(self):
        body = "{}"
        ct = "application/json"
        fp1 = fingerprint(body, "key=foo", ct)
        fp2 = fingerprint(body, "key=bar", ct)
        assert fp1 == fp2

    def test_returns_16_chars(self):
        fp = fingerprint("{}", "", "application/json")
        assert len(fp) == 16
        assert all(c in "0123456789abcdef" for c in fp)

    def test_form_encoded_body(self):
        body1 = "name=alice&email=a%40b.com"
        body2 = "name=bob&email=c%40d.com"
        ct = "application/x-www-form-urlencoded"
        assert fingerprint(body1, "", ct) == fingerprint(body2, "", ct)

    def test_form_encoded_new_field_new_fp(self):
        body1 = "name=alice"
        body2 = "name=alice&age=30"
        ct = "application/x-www-form-urlencoded"
        assert fingerprint(body1, "", ct) != fingerprint(body2, "", ct)

    def test_unicode_body_does_not_raise(self):
        body = json.dumps({"名前": "テスト"})
        fp = fingerprint(body, "", "application/json")
        assert len(fp) == 16

    def test_array_at_root(self):
        body = json.dumps([{"id": 1}])
        fp = fingerprint(body, "", "application/json")
        assert len(fp) == 16

    def test_empty_body_stable(self):
        fp1 = fingerprint("", "", "")
        fp2 = fingerprint("", "", "")
        assert fp1 == fp2


class TestFingerprintValueDiscrimination:
    """Tests for the optional value_paths parameter of fingerprint()."""

    def _fp3(self, body: str, qs: str = "", ct: str = "application/json") -> str:
        """3-argument baseline call (no value_paths)."""
        return fingerprint(body, qs, ct)

    # ------------------------------------------------------------------
    # Invariant: empty / None config → byte-identical to 3-arg call
    # ------------------------------------------------------------------

    def test_none_value_paths_identical_to_no_arg(self):
        body = json.dumps({"action": "login"})
        assert fingerprint(body, "", "application/json", value_paths=None) == self._fp3(body)

    def test_empty_value_paths_identical_to_no_arg(self):
        body = json.dumps({"action": "login"})
        assert fingerprint(body, "", "application/json", value_paths=[]) == self._fp3(body)

    # ------------------------------------------------------------------
    # Core discrimination behaviour
    # ------------------------------------------------------------------

    def test_differing_value_different_hashes(self):
        ct = "application/json"
        body1 = json.dumps({"action": "login"})
        body2 = json.dumps({"action": "logout"})
        vp = ["action"]
        assert fingerprint(body1, "", ct, value_paths=vp) != fingerprint(body2, "", ct, value_paths=vp)

    def test_same_value_stable_hash(self):
        body = json.dumps({"action": "login", "token": "xyz"})
        vp = ["action"]
        ct = "application/json"
        assert fingerprint(body, "", ct, value_paths=vp) == fingerprint(body, "", ct, value_paths=vp)

    # ------------------------------------------------------------------
    # Absent / non-scalar at path → identical to no-config
    # ------------------------------------------------------------------

    def test_absent_path_identical_to_no_config(self):
        body = json.dumps({"action": "login"})
        ct = "application/json"
        assert fingerprint(body, "", ct, value_paths=["missing_key"]) == self._fp3(body, ct=ct)

    def test_dict_at_path_identical_to_no_config(self):
        body = json.dumps({"meta": {"inner": "x"}, "action": "login"})
        ct = "application/json"
        assert fingerprint(body, "", ct, value_paths=["meta"]) == self._fp3(body, ct=ct)

    def test_list_at_path_identical_to_no_config(self):
        body = json.dumps({"tags": ["a", "b"], "action": "login"})
        ct = "application/json"
        assert fingerprint(body, "", ct, value_paths=["tags"]) == self._fp3(body, ct=ct)

    # ------------------------------------------------------------------
    # Canonical value encoding
    # ------------------------------------------------------------------

    def test_bool_true_canonical(self):
        assert _canonical_scalar(True) == "true"

    def test_bool_false_canonical(self):
        assert _canonical_scalar(False) == "false"

    def test_bool_before_int_check(self):
        """True must produce 'true', not '1' (bool checked before int)."""
        assert _canonical_scalar(True) == "true"
        assert _canonical_scalar(True) != "1"

    def test_none_canonical(self):
        assert _canonical_scalar(None) == "null"

    def test_int_canonical(self):
        assert _canonical_scalar(42) == "42"

    def test_float_canonical(self):
        assert _canonical_scalar(1.5) == "1.5"

    def test_str_canonical_raw(self):
        assert _canonical_scalar("hello") == "hello"

    def test_dict_canonical_returns_none(self):
        assert _canonical_scalar({"k": "v"}) is None

    def test_list_canonical_returns_none(self):
        assert _canonical_scalar([1, 2]) is None

    def test_bool_discrimination(self):
        """Two bodies differing only in a bool value → different fingerprints."""
        ct = "application/json"
        vp = ["active"]
        body_true = json.dumps({"active": True})
        body_false = json.dumps({"active": False})
        assert fingerprint(body_true, "", ct, value_paths=vp) != fingerprint(body_false, "", ct, value_paths=vp)

    def test_null_value_discrimination(self):
        """Body with None vs. absent path → different outcomes (null vs. absent)."""
        ct = "application/json"
        vp = ["v"]
        body_null = json.dumps({"v": None})
        body_absent = json.dumps({"other": 1})
        # null → included; absent → not included → different from null
        assert fingerprint(body_null, "", ct, value_paths=vp) != fingerprint(body_absent, "", ct, value_paths=vp)

    # ------------------------------------------------------------------
    # Form-encoded body
    # ------------------------------------------------------------------

    def test_form_encoded_top_level_key_works(self):
        ct = "application/x-www-form-urlencoded"
        body1 = "action=login&user=alice"
        body2 = "action=logout&user=alice"
        assert fingerprint(body1, "", ct, value_paths=["action"]) != fingerprint(body2, "", ct, value_paths=["action"])

    def test_form_encoded_absent_key_identical_to_no_config(self):
        ct = "application/x-www-form-urlencoded"
        body = "action=login"
        assert fingerprint(body, "", ct, value_paths=["missing"]) == self._fp3(body, ct=ct)

    # ------------------------------------------------------------------
    # Robustness: unparseable body never raises, equals no-config
    # ------------------------------------------------------------------

    def test_unparseable_body_does_not_raise(self):
        body = "this is not json {{ broken"
        ct = "application/json"
        # must not raise
        result = fingerprint(body, "", ct, value_paths=["action"])
        assert isinstance(result, str) and len(result) == 16

    def test_unparseable_body_equals_no_config(self):
        body = "this is not json {{ broken"
        ct = "application/json"
        assert fingerprint(body, "", ct, value_paths=["action"]) == self._fp3(body, ct=ct)


class TestRespFingerprint:
    def test_varies_by_status(self):
        body = json.dumps({"ok": True})
        rfp200 = resp_fingerprint(200, body, "", "application/json")
        rfp404 = resp_fingerprint(404, body, "", "application/json")
        assert rfp200 != rfp404

    def test_same_status_same_body_stable(self):
        body = json.dumps({"x": 1})
        assert resp_fingerprint(200, body, "", "application/json") == resp_fingerprint(
            200, body, "", "application/json"
        )

    def test_status_prefix(self):
        rfp = resp_fingerprint(201, "{}", "", "application/json")
        assert rfp.startswith("201")


# ===========================================================================
# templating.py
# ===========================================================================


class TestHeuristicTemplate:
    def test_numeric_segment(self):
        assert _heuristic_template("/users/123") == "/users/{id}"

    def test_uuid_segment(self):
        assert (
            _heuristic_template("/users/550e8400-e29b-41d4-a716-446655440000")
            == "/users/{id}"
        )

    def test_hex16_segment(self):
        assert _heuristic_template("/tokens/deadbeefcafebabe") == "/tokens/{id}"

    def test_short_hex_not_replaced(self):
        # Fewer than 16 hex chars and not all-digits → literal
        assert _heuristic_template("/tokens/deadbeef") == "/tokens/deadbeef"

    def test_literal_segments_kept(self):
        assert _heuristic_template("/api/users") == "/api/users"

    def test_mixed_path(self):
        result = _heuristic_template("/orders/42/items/abc123")
        assert result == "/orders/{id}/items/abc123"

    def test_leading_slash_preserved(self):
        result = _heuristic_template("/v1/99")
        assert result.startswith("/")

    def test_uuid_case_insensitive(self):
        path = "/obj/550E8400-E29B-41D4-A716-446655440000"
        assert _heuristic_template(path) == "/obj/{id}"


class TestLoadCuratedTemplates:
    def test_sorted_by_literal_count_desc(self):
        templates = [
            "/users/{id}",          # 1 literal
            "/users/{id}/orders",   # 2 literals
            "/{id}",                # 0 literals
        ]
        curated = load_curated_templates(templates)
        counts = [c.literal_count for c in curated]
        assert counts == sorted(counts, reverse=True)

    def test_tiebreak_lexicographic(self):
        templates = [
            "/b/{id}",
            "/a/{id}",
        ]
        curated = load_curated_templates(templates)
        assert curated[0].template == "/a/{id}"
        assert curated[1].template == "/b/{id}"

    def test_literal_count_precomputed(self):
        curated = load_curated_templates(["/users/{id}/orders"])
        assert curated[0].literal_count == 2

    def test_all_literal(self):
        curated = load_curated_templates(["/api/health"])
        assert curated[0].literal_count == 2

    def test_named_wildcard_not_counted_as_literal(self):
        # {userId} and {p1} are wildcards - should not count as literals
        curated = load_curated_templates(["/users/{userId}/orders/{p1}"])
        assert curated[0].literal_count == 2

    def test_named_wildcard_sorted_correctly(self):
        templates = [
            "/v1/{p1}",             # 1 literal
            "/v1/{p1}/profile",     # 2 literals
        ]
        curated = load_curated_templates(templates)
        assert curated[0].template == "/v1/{p1}/profile"
        assert curated[1].template == "/v1/{p1}"


class TestTemplatePath:
    def test_curated_wins_over_heuristic(self):
        # Heuristic would keep "v1" as literal but curated says {id}
        curated = load_curated_templates(["/api/{id}/detail"])
        result = template_path("/api/v1/detail", curated)
        assert result == "/api/{id}/detail"

    def test_more_literals_wins(self):
        templates = [
            "/users/{id}",           # 1 literal
            "/users/{id}/settings",  # 2 literals
        ]
        curated = load_curated_templates(templates)
        result = template_path("/users/42/settings", curated)
        assert result == "/users/{id}/settings"

    def test_segment_count_mismatch_skipped(self):
        curated = load_curated_templates(["/users/{id}/orders"])
        # Path has 2 segments, template has 3 - must not match
        result = template_path("/users/42", curated)
        assert result == "/users/{id}"  # falls back to heuristic

    def test_fallback_to_heuristic(self):
        curated = load_curated_templates(["/products/{id}"])
        result = template_path("/orders/99/items", curated)
        assert result == "/orders/{id}/items"

    def test_empty_curated_list(self):
        result = template_path("/v2/widgets/abc123def456789a", [])
        assert result == "/v2/widgets/{id}"

    def test_exact_literal_match(self):
        curated = load_curated_templates(["/health"])
        result = template_path("/health", curated)
        assert result == "/health"

    def test_named_wildcard_p1_matches_concrete_segment(self):
        curated = load_curated_templates(["/v1/{p1}/profile"])
        result = template_path("/v1/abc123/profile", curated)
        assert result == "/v1/{p1}/profile"

    def test_named_wildcard_userId_matches_numeric_segment(self):
        curated = load_curated_templates(["/users/{userId}/orders"])
        result = template_path("/users/42/orders", curated)
        assert result == "/users/{userId}/orders"

    def test_named_wildcard_more_specific_wins_over_id(self):
        # {userId} and {id} are both wildcards; path-specific name wins via
        # literal_count tie-break (both 2 literals) → lexicographic order
        templates = ["/users/{id}/orders", "/users/{userId}/orders"]
        curated = load_curated_templates(templates)
        result = template_path("/users/42/orders", curated)
        # First lexicographically among equal-literal-count templates
        assert result == "/users/{id}/orders"

    def test_named_wildcard_does_not_match_literal_segment_name(self):
        # A template segment {p1} must NOT be used as a literal match
        # against the concrete segment "p1" - it is still a wildcard.
        curated = load_curated_templates(["/api/{p1}/data"])
        result = template_path("/api/p1/data", curated)
        assert result == "/api/{p1}/data"


# ===========================================================================
# masking.py
# ===========================================================================


def _rules(field_masks=None, regex_masks=None) -> CompiledRules:
    return compile_rules(field_masks or [], regex_masks or [])


class TestCompileRules:
    def test_field_masks_lowercased(self):
        rules = _rules(field_masks=["Password", "  TOKEN  "])
        assert "password" in rules.field_masks
        assert "token" in rules.field_masks

    def test_invalid_regex_skipped(self):
        rules = _rules(regex_masks=[{"pattern": "[invalid(", "replace": "x"}])
        assert len(rules.regex_masks) == 0

    def test_empty_replace_becomes_masked(self):
        rules = _rules(regex_masks=[{"pattern": "foo", "replace": ""}])
        assert rules.regex_masks[0][1] == "<masked>"

    def test_i_flag_prepends_prefix(self):
        rules = _rules(regex_masks=[{"pattern": "secret", "flags": "i", "replace": "X"}])
        pattern_str = rules.regex_masks[0][0].pattern
        assert "(?i)" in pattern_str


class TestMaskObject:
    """Tests for Go-parity semantics via mask_known on JSON bodies."""

    def test_field_mask_replaces_value(self):
        body = json.dumps({"password": "s3cr3t", "user": "alice"})
        rules = _rules(field_masks=["password"])
        masked, _, _ = mask_known(body, {}, "", "application/json", rules)
        obj = json.loads(masked)
        assert obj["password"] == "<masked>"
        assert obj["user"] == "alice"

    def test_field_mask_no_recursion_into_masked_value(self):
        """When a field is masked the whole value is '<masked>', not recursed."""
        body = json.dumps({"nested": {"password": "s3cr3t", "inner": "x"}})
        rules = _rules(field_masks=["nested"])
        masked, _, _ = mask_known(body, {}, "", "application/json", rules)
        obj = json.loads(masked)
        assert obj["nested"] == "<masked>"

    def test_field_mask_case_insensitive(self):
        body = json.dumps({"Authorization": "Bearer tok"})
        rules = _rules(field_masks=["authorization"])
        masked, _, _ = mask_known(body, {}, "", "application/json", rules)
        obj = json.loads(masked)
        assert obj["Authorization"] == "<masked>"

    def test_regex_applied_to_strings(self):
        body = json.dumps({"note": "Bearer abc123xyz"})
        rules = _rules(
            regex_masks=[
                {"pattern": r"Bearer\s+\S+", "replace": "<token>", "flags": ""}
            ]
        )
        masked, _, _ = mask_known(body, {}, "", "application/json", rules)
        obj = json.loads(masked)
        assert obj["note"] == "<token>"

    def test_regex_order_respected(self):
        body = json.dumps({"msg": "hello world"})
        rules = _rules(
            regex_masks=[
                {"pattern": "hello", "replace": "hi", "flags": ""},
                {"pattern": "hi world", "replace": "greetings", "flags": ""},
            ]
        )
        masked, _, _ = mask_known(body, {}, "", "application/json", rules)
        obj = json.loads(masked)
        assert obj["msg"] == "greetings"

    def test_case_insensitive_regex_flag(self):
        body = json.dumps({"val": "SECRET_VALUE"})
        rules = _rules(
            regex_masks=[{"pattern": "secret_value", "replace": "<x>", "flags": "i"}]
        )
        masked, _, _ = mask_known(body, {}, "", "application/json", rules)
        obj = json.loads(masked)
        assert obj["val"] == "<x>"

    def test_numbers_unchanged_by_field_absent(self):
        body = json.dumps({"count": 42, "rate": 3.14})
        rules = _rules()
        masked, _, _ = mask_known(body, {}, "", "application/json", rules)
        obj = json.loads(masked)
        assert obj["count"] == 42
        assert obj["rate"] == pytest.approx(3.14)

    def test_list_recursion(self):
        body = json.dumps({"tags": ["a", "b", "c"]})
        rules = _rules(regex_masks=[{"pattern": "b", "replace": "X", "flags": ""}])
        masked, _, _ = mask_known(body, {}, "", "application/json", rules)
        obj = json.loads(masked)
        assert obj["tags"] == ["a", "X", "c"]

    def test_non_json_body_regex_applied(self):
        """Non-JSON bodies must still have regex masks applied (Go string branch)."""
        body = "card 4111111111111111 charged"
        rules = _rules(
            regex_masks=[{"pattern": r"\b\d{16}\b", "replace": "<masked-cc>", "flags": ""}]
        )
        masked, _, _ = mask_known(body, {}, "", "text/plain", rules)
        assert "<masked-cc>" in masked
        assert "4111111111111111" not in masked

    def test_non_json_body_no_matching_regex_unchanged(self):
        """Non-JSON body with no matching regex must be returned as-is."""
        body = "hello world"
        rules = _rules(regex_masks=[{"pattern": r"\d{16}", "replace": "X", "flags": ""}])
        masked, _, _ = mask_known(body, {}, "", "text/plain", rules)
        assert masked == "hello world"

    def test_invalid_regex_silently_skipped(self):
        body = json.dumps({"val": "hello"})
        rules = compile_rules([], [{"pattern": "[[[", "replace": "x"}])
        # No exception; body returned unchanged
        masked, _, _ = mask_known(body, {}, "", "application/json", rules)
        obj = json.loads(masked)
        assert obj["val"] == "hello"


class TestHeaderAllowlist:
    def _check_headers(self, masked_headers: dict):
        # Allowlisted headers keep their values
        assert masked_headers.get("content-type") == "application/json"
        assert masked_headers.get("host") == "example.com"
        # Non-allowlisted must be masked
        assert masked_headers.get("authorization") == "<masked>"
        assert masked_headers.get("x-custom") == "<masked>"
        assert masked_headers.get("cookie") == "<masked>"

    def test_mask_known_header_allowlist(self):
        headers = {
            "content-type": "application/json",
            "host": "example.com",
            "authorization": "Bearer tok",
            "x-custom": "value",
            "cookie": "session=abc",
        }
        rules = _rules()
        _, masked, _ = mask_known("{}", headers, "", "application/json", rules)
        self._check_headers(masked)

    def test_mask_all_header_allowlist(self):
        headers = {
            "content-type": "application/json",
            "host": "example.com",
            "authorization": "Bearer tok",
            "x-custom": "value",
            "cookie": "session=abc",
        }
        _, masked, _ = mask_all("{}", headers, "", "application/json")
        self._check_headers(masked)

    def test_all_allowlisted_names(self):
        """Every name in HEADER_ALLOWLIST must survive unmasked."""
        headers = {name: "value" for name in HEADER_ALLOWLIST}
        rules = _rules()
        _, masked_known, _ = mask_known("{}", headers, "", "", rules)
        _, masked_all, _ = mask_all("{}", headers, "", "")
        for name in HEADER_ALLOWLIST:
            assert masked_known[name] == "value", f"mask_known dropped {name}"
            assert masked_all[name] == "value", f"mask_all dropped {name}"


class TestQueryMasking:
    def test_mask_known_field_mask_in_query(self):
        rules = _rules(field_masks=["secret"])
        _, _, q = mask_known(
            "{}", {}, "secret=abc&safe=123", "application/json", rules
        )
        parsed = urllib.parse.parse_qs(q)
        assert parsed["secret"] == ["<masked>"]
        assert parsed["safe"] == ["123"]

    def test_mask_known_regex_on_unmasked_query(self):
        rules = _rules(
            regex_masks=[{"pattern": r"\d+", "replace": "0", "flags": ""}]
        )
        _, _, q = mask_known(
            "{}", {}, "page=5&q=abc", "application/json", rules
        )
        parsed = urllib.parse.parse_qs(q)
        assert parsed["page"] == ["0"]
        assert parsed["q"] == ["abc"]

    def test_mask_all_query(self):
        _, _, q = mask_all("{}", {}, "a=1&b=2", "application/json")
        parsed = urllib.parse.parse_qs(q)
        assert parsed["a"] == ["<masked>"]
        assert parsed["b"] == ["<masked>"]

    def test_empty_query_string(self):
        rules = _rules()
        _, _, q = mask_known("{}", {}, "", "application/json", rules)
        assert q == ""


class TestMaskAllStructure:
    def test_json_structure_preserved(self):
        body = json.dumps({
            "user": {"name": "Alice", "age": 30},
            "active": True,
            "score": None,
        })
        masked, _, _ = mask_all(body, {}, "", "application/json")
        obj = json.loads(masked)
        assert isinstance(obj["user"], dict)
        assert obj["user"]["name"] == "<masked>"
        assert obj["user"]["age"] == 0
        assert obj["active"] is False
        assert obj["score"] is None

    def test_root_array_structure_preserved(self):
        body = json.dumps([{"id": 1, "val": "x"}, {"id": 2, "val": "y"}])
        masked, _, _ = mask_all(body, {}, "", "application/json")
        arr = json.loads(masked)
        assert isinstance(arr, list)
        assert len(arr) == 2
        assert arr[0]["id"] == 0
        assert arr[0]["val"] == "<masked>"

    def test_non_json_body_becomes_masked_string(self):
        masked, _, _ = mask_all("not json", {}, "", "text/plain")
        assert masked == "<masked>"

    def test_form_encoded_field_names_kept(self):
        body = "username=alice&password=s3cr3t"
        masked, _, _ = mask_all(
            body, {}, "", "application/x-www-form-urlencoded"
        )
        parsed = urllib.parse.parse_qs(masked)
        assert "username" in parsed
        assert "password" in parsed
        assert parsed["username"] == ["<masked>"]
        assert parsed["password"] == ["<masked>"]


# ===========================================================================
# binary.py
# ===========================================================================


class TestIsImage:
    def test_image_png(self):
        assert is_image("image/png") is True

    def test_image_jpeg(self):
        assert is_image("image/jpeg") is True

    def test_image_gif(self):
        assert is_image("image/gif") is True

    def test_image_webp(self):
        assert is_image("image/webp") is True

    def test_with_charset_param(self):
        assert is_image("image/png; charset=utf-8") is True

    def test_case_insensitive(self):
        assert is_image("Image/PNG") is True

    def test_non_image(self):
        assert is_image("application/json") is False
        assert is_image("text/html") is False
        assert is_image("") is False
        assert is_image("video/mp4") is False


class TestPlaceholderMagicBytes:
    def test_png_magic(self):
        assert PNG_1X1[:4] == b"\x89PNG"

    def test_gif_magic(self):
        assert GIF_1X1[:4] == b"GIF8"

    def test_jpeg_magic(self):
        assert JPEG_1X1[:2] == b"\xff\xd8"

    def test_placeholder_for_png(self):
        data, subtype = placeholder_for("image/png")
        assert data == PNG_1X1
        assert subtype == "png"

    def test_placeholder_for_gif(self):
        data, subtype = placeholder_for("image/gif")
        assert data == GIF_1X1
        assert subtype == "gif"

    def test_placeholder_for_jpeg(self):
        data, subtype = placeholder_for("image/jpeg")
        assert data == JPEG_1X1
        assert subtype == "jpeg"

    def test_placeholder_for_jpg_alias(self):
        data, subtype = placeholder_for("image/jpg")
        assert data == JPEG_1X1
        assert subtype == "jpeg"

    def test_unknown_image_subtype_falls_back_to_png(self):
        data, subtype = placeholder_for("image/webp")
        assert data == PNG_1X1
        assert subtype == "png"

    def test_unknown_image_star_falls_back_to_png(self):
        data, subtype = placeholder_for("image/avif")
        assert data == PNG_1X1
        assert subtype == "png"

    def test_placeholder_for_with_charset(self):
        data, subtype = placeholder_for("image/png; q=0.9")
        assert data == PNG_1X1
        assert subtype == "png"

    def test_gif_starts_with_gif89a(self):
        assert GIF_1X1[:6] == b"GIF89a"


# ===========================================================================
# field_rules.py - status-scoped rules
# ===========================================================================


class TestStatusScopedFieldRules:
    """Tests for per-status resp: and resp_header: rule grammar."""

    # ------------------------------------------------------------------
    # Imports (localised to avoid circular-import risk in top-level scope)
    # ------------------------------------------------------------------

    def _cf(self):
        from stubsmith.privacy.field_rules import compile_field_rules
        return compile_field_rules

    def _arf(self):
        from stubsmith.privacy.field_rules import apply_resp_field_rules
        return apply_resp_field_rules

    # ------------------------------------------------------------------
    # Compilation - valid status-scoped paths
    # ------------------------------------------------------------------

    def test_resp_status_keep_compiled(self):
        rules = self._cf()([{"path": "resp:200.order_id", "action": "keep"}])
        assert (200, "order_id") in rules.keep_resp_status

    def test_resp_status_mask_compiled(self):
        rules = self._cf()([{"path": "resp:404.error", "action": "mask"}])
        assert (404, "error") in rules.mask_resp_status

    def test_resp_header_status_keep_compiled(self):
        rules = self._cf()([{"path": "resp_header:429.retry-after", "action": "keep"}])
        assert (429, "retry-after") in rules.keep_resp_header_status

    def test_resp_header_status_mask_compiled(self):
        rules = self._cf()([{"path": "resp_header:500.x-trace-id", "action": "mask"}])
        assert (500, "x-trace-id") in rules.mask_resp_header_status

    def test_resp_header_status_name_lowercased(self):
        rules = self._cf()([{"path": "resp_header:200.X-Custom-Header", "action": "keep"}])
        assert (200, "x-custom-header") in rules.keep_resp_header_status

    def test_boundary_status_100(self):
        rules = self._cf()([{"path": "resp:100.x", "action": "keep"}])
        assert (100, "x") in rules.keep_resp_status

    def test_boundary_status_599(self):
        rules = self._cf()([{"path": "resp:599.x", "action": "keep"}])
        assert (599, "x") in rules.keep_resp_status

    def test_nested_body_path_preserved(self):
        rules = self._cf()([{"path": "resp:200.items.[].id", "action": "keep"}])
        assert (200, "items.[].id") in rules.keep_resp_status

    def test_resp_status_not_mistaken_for_resp_header(self):
        """resp:404.x must not land in keep_resp_header_status."""
        rules = self._cf()([{"path": "resp:404.x", "action": "keep"}])
        assert (404, "x") in rules.keep_resp_status
        assert len(rules.keep_resp_header_status) == 0

    def test_resp_header_status_not_mistaken_for_resp_status(self):
        """resp_header:429.retry-after must not land in keep_resp_status."""
        rules = self._cf()([{"path": "resp_header:429.retry-after", "action": "keep"}])
        assert (429, "retry-after") in rules.keep_resp_header_status
        assert len(rules.keep_resp_status) == 0

    # ------------------------------------------------------------------
    # Compilation - malformed status values are silently ignored
    # ------------------------------------------------------------------

    def test_malformed_non_digit_status_ignored(self):
        rules = self._cf()([{"path": "resp:abc.x", "action": "keep"}])
        assert len(rules.keep_resp_status) == 0

    def test_malformed_one_digit_status_ignored(self):
        rules = self._cf()([{"path": "resp:1.x", "action": "keep"}])
        assert len(rules.keep_resp_status) == 0

    def test_malformed_two_digit_status_ignored(self):
        rules = self._cf()([{"path": "resp:99.x", "action": "keep"}])
        assert len(rules.keep_resp_status) == 0

    def test_malformed_out_of_range_600_ignored(self):
        rules = self._cf()([{"path": "resp:600.x", "action": "keep"}])
        assert len(rules.keep_resp_status) == 0

    def test_malformed_leading_zero_ignored(self):
        """resp:0404.x - four digits, not three."""
        rules = self._cf()([{"path": "resp:0404.x", "action": "keep"}])
        assert len(rules.keep_resp_status) == 0

    def test_malformed_no_subpath_ignored(self):
        """resp:404 with no dot → no subpath."""
        rules = self._cf()([{"path": "resp:404", "action": "keep"}])
        assert len(rules.keep_resp_status) == 0

    def test_malformed_empty_subpath_ignored(self):
        """resp:404. with empty subpath after the dot."""
        rules = self._cf()([{"path": "resp:404.", "action": "keep"}])
        assert len(rules.keep_resp_status) == 0

    def test_malformed_never_raises(self):
        rules = self._cf()([
            {"path": "resp:abc.x", "action": "keep"},
            {"path": "resp:1.x", "action": "keep"},
            {"path": "resp:99.x", "action": "keep"},
            {"path": "resp:600.x", "action": "keep"},
            {"path": "resp:0404.x", "action": "keep"},
            {"path": "resp:404", "action": "keep"},
            {"path": "resp:404.", "action": "keep"},
        ])
        assert len(rules.keep_resp_status) == 0

    # ------------------------------------------------------------------
    # Precedence branch 1 - status-scoped keep adds a path
    # ------------------------------------------------------------------

    def test_scoped_keep_adds_path_not_in_generic(self):
        """resp:200.amount keep - amount is not in generic resp. set."""
        rules = self._cf()([
            {"path": "resp.order_id", "action": "keep"},
            {"path": "resp:200.amount", "action": "keep"},
        ])
        body = json.dumps({"order_id": "ord-1", "amount": 99, "token": "secret"})
        masked_body, _ = self._arf()(body, {}, "application/json", rules, resp_status=200)
        obj = json.loads(masked_body)
        assert obj["order_id"] == "ord-1"
        assert obj["amount"] == 99
        assert obj["token"] == "<masked>"

    # ------------------------------------------------------------------
    # Precedence branch 1 - status-scoped mask overrides generic keep
    # ------------------------------------------------------------------

    def test_scoped_mask_overrides_generic_keep(self):
        """resp:200.customer_email mask overrides generic resp.customer_email keep."""
        rules = self._cf()([
            {"path": "resp.customer_email", "action": "keep"},
            {"path": "resp:200.customer_email", "action": "mask"},
        ])
        body = json.dumps({"customer_email": "alice@example.com", "id": "ord-1"})
        masked_body, _ = self._arf()(body, {}, "application/json", rules, resp_status=200)
        obj = json.loads(masked_body)
        assert obj["customer_email"] == "<masked>"

    # ------------------------------------------------------------------
    # Precedence branch 2 - generic rule applies when no scoped rule matches
    # ------------------------------------------------------------------

    def test_generic_rule_applies_for_different_status(self):
        """resp:404.error keep - at status 200 the generic set applies (error masked)."""
        rules = self._cf()([
            {"path": "resp:404.error", "action": "keep"},
        ])
        body = json.dumps({"error": "something", "id": 1})
        masked_body, _ = self._arf()(body, {}, "application/json", rules, resp_status=200)
        obj = json.loads(masked_body)
        assert obj["error"] == "<masked>"
        assert obj["id"] == 0

    # ------------------------------------------------------------------
    # resp_status=None - only generic rules, backward-compat
    # ------------------------------------------------------------------

    def test_resp_status_none_only_generic(self):
        """When resp_status=None, status-scoped rules are invisible."""
        rules = self._cf()([
            {"path": "resp.id", "action": "keep"},
            {"path": "resp:404.error", "action": "keep"},
        ])
        body = json.dumps({"id": "abc", "error": "not_found"})
        masked_body, _ = self._arf()(body, {}, "application/json", rules, resp_status=None)
        obj = json.loads(masked_body)
        assert obj["id"] == "abc"
        assert obj["error"] == "<masked>"

    def test_resp_status_default_is_none(self):
        """apply_resp_field_rules with no resp_status kwarg behaves like None."""
        rules = self._cf()([
            {"path": "resp.id", "action": "keep"},
            {"path": "resp:200.extra", "action": "keep"},
        ])
        body = json.dumps({"id": "abc", "extra": "val"})
        masked_body, _ = self._arf()(body, {}, "application/json", rules)
        obj = json.loads(masked_body)
        assert obj["id"] == "abc"
        assert obj["extra"] == "<masked>"

    # ------------------------------------------------------------------
    # Regression guard - generic-only rule set behaves exactly as before
    # ------------------------------------------------------------------

    def test_generic_only_rules_unchanged(self):
        """A rule set with only generic resp. rules must produce the same output
        as the pre-status-scoped implementation would have.  This is the path
        taken by every currently deployed SDK that has not been upgraded, and
        it must not silently regress."""
        rules = self._cf()([
            {"path": "resp.id", "action": "keep"},
            {"path": "resp.status", "action": "keep"},
            {"path": "resp_header.x-trace-id", "action": "keep"},
        ])
        body = json.dumps({"id": "ord-1", "status": "created", "token": "secret"})
        headers = {"x-trace-id": "trace-abc", "set-cookie": "sess=x", "content-type": "application/json"}
        # With status
        mb_with, mh_with = self._arf()(body, headers, "application/json", rules, resp_status=200)
        # Without status (None)
        mb_none, mh_none = self._arf()(body, headers, "application/json", rules, resp_status=None)
        # Results must be identical: no status-scoped rules means status is irrelevant
        assert json.loads(mb_with) == json.loads(mb_none)
        assert mh_with == mh_none
        # Verify the content
        obj = json.loads(mb_with)
        assert obj["id"] == "ord-1"
        assert obj["status"] == "created"
        assert obj["token"] == "<masked>"

    # ------------------------------------------------------------------
    # Response header status-scoped rules
    # ------------------------------------------------------------------

    def test_resp_header_scoped_keep(self):
        rules = self._cf()([{"path": "resp_header:429.retry-after", "action": "keep"}])
        headers = {"retry-after": "60", "x-secret": "hidden", "content-type": "application/json"}
        _, mh = self._arf()("", headers, "", rules, resp_status=429)
        assert mh["retry-after"] == "60"
        assert mh["x-secret"] == "<masked>"
        assert mh["content-type"] == "application/json"

    def test_resp_header_scoped_mask_overrides_generic_keep(self):
        rules = self._cf()([
            {"path": "resp_header.x-trace-id", "action": "keep"},
            {"path": "resp_header:500.x-trace-id", "action": "mask"},
        ])
        headers = {"x-trace-id": "trace-abc", "content-type": "application/json"}
        _, mh = self._arf()("", headers, "", rules, resp_status=500)
        assert mh["x-trace-id"] == "<masked>"

    def test_resp_header_scoped_keep_wrong_status_no_effect(self):
        rules = self._cf()([{"path": "resp_header:429.retry-after", "action": "keep"}])
        headers = {"retry-after": "60", "content-type": "application/json"}
        _, mh = self._arf()("", headers, "", rules, resp_status=200)
        assert mh["retry-after"] == "<masked>"

    # ------------------------------------------------------------------
    # Credential-header scoping - wrong-status keep does not unmask
    # ------------------------------------------------------------------

    def test_credential_header_not_unmasked_by_wrong_status_scoped_keep(self):
        """A resp_header:401.set-cookie keep does NOT unmask set-cookie at status 200.

        The module's guarantee for response-header keep rules is that any header
        can be unmasked by an explicit keep rule - generic (resp_header.) or
        status-scoped (resp_header:N.) - but only when the rule's status matches
        the actual response status.  At a non-matching status the header is masked.
        This test verifies that a status-scoped keep for 401 has no effect at 200,
        so a credential header scoped to the wrong status stays masked.
        """
        rules = self._cf()([{"path": "resp_header:401.set-cookie", "action": "keep"}])
        headers = {"set-cookie": "session=abc; HttpOnly", "content-type": "application/json"}
        _, mh = self._arf()("", headers, "", rules, resp_status=200)
        assert mh["set-cookie"] == "<masked>"

    def test_credential_header_can_be_unmasked_by_matching_status_scoped_keep(self):
        """A resp_header:401.set-cookie keep DOES unmask set-cookie at status 401.

        This mirrors the behavior of generic resp_header.set-cookie keep rules
        (which also unmask the header).  The module applies no additional
        credential-header blocklist; operator-written rules are trusted as written.
        """
        rules = self._cf()([{"path": "resp_header:401.set-cookie", "action": "keep"}])
        headers = {"set-cookie": "session=abc; HttpOnly", "content-type": "application/json"}
        _, mh = self._arf()("", headers, "", rules, resp_status=401)
        assert mh["set-cookie"] == "session=abc; HttpOnly"

    def test_non_credential_header_unmasked_by_status_scoped_keep(self):
        """A non-credential header CAN be unmasked by a matching status-scoped keep."""
        rules = self._cf()([{"path": "resp_header:200.x-trace-id", "action": "keep"}])
        headers = {"x-trace-id": "trace-abc", "content-type": "application/json"}
        _, mh = self._arf()("", headers, "", rules, resp_status=200)
        assert mh["x-trace-id"] == "trace-abc"

    # ------------------------------------------------------------------
    # Unicode digit robustness - _parse_status_suffix must never raise
    # ------------------------------------------------------------------

    def test_superscript_digits_ignored_no_exception(self):
        """resp:²²².error - '²' passes isdigit() but is not ASCII; must be ignored."""
        rules = self._cf()([{"path": "resp:²²².error", "action": "keep"}])
        assert len(rules.keep_resp_status) == 0

    def test_arabic_indic_digits_ignored_no_exception(self):
        """resp:٤٠٤.error - Arabic-Indic digits pass isdigit() but not isascii()."""
        rules = self._cf()([{"path": "resp:٤٠٤.error", "action": "keep"}])
        assert len(rules.keep_resp_status) == 0

    # ------------------------------------------------------------------
    # Conflict resolution - mask wins when same (status, path) in both sets
    # ------------------------------------------------------------------

    def test_conflict_mask_wins_body(self):
        """When resp:200.name appears as both keep and mask, mask wins (fail-closed)."""
        rules = self._cf()([
            {"path": "resp:200.name", "action": "keep"},
            {"path": "resp:200.name", "action": "mask"},
        ])
        body = json.dumps({"name": "Alice", "id": 1})
        masked_body, _ = self._arf()(body, {}, "application/json", rules, resp_status=200)
        obj = json.loads(masked_body)
        assert obj["name"] == "<masked>"

    def test_conflict_mask_wins_header(self):
        """When resp_header:200.x-custom appears as both keep and mask, mask wins."""
        rules = self._cf()([
            {"path": "resp_header:200.x-custom", "action": "keep"},
            {"path": "resp_header:200.x-custom", "action": "mask"},
        ])
        headers = {"x-custom": "val", "content-type": "application/json"}
        _, mh = self._arf()("", headers, "", rules, resp_status=200)
        assert mh["x-custom"] == "<masked>"
