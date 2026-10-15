"""The value-type labels and path ID rules come from the shared classifier spec.

tools/classifiers/classifiers.json is a copy of the spec; generate.py turns it
into stubsmith/privacy/_classifiers.py.  These tests run the spec's own examples
against the generated code and the SDK functions that use it, check that the
generated file matches the spec next to it, and cover the project's "Group IDs
in paths automatically" setting in capture and replay.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import pathlib
import subprocess
import sys

import pytest
import requests

from stubsmith.privacy import _classifiers
from stubsmith.replay import StubNotFound, replay

_fingerprint = importlib.import_module("stubsmith.privacy.fingerprint")
_templating = importlib.import_module("stubsmith.privacy.templating")
_placeholders = importlib.import_module("stubsmith.privacy.placeholders")

ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC_PATH = ROOT / "tools" / "classifiers" / "classifiers.json"
SPEC = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
RULES = SPEC["value_classifier"]["string_rules"]


def _first_label(value):
    """The label the spec says a string gets: the first rule that matches."""
    import re
    for rule in RULES:
        flags = re.IGNORECASE if "i" in rule.get("flags", "") else 0
        if re.match(rule["regex"], value, flags):
            return rule["label"]
    return SPEC["value_classifier"]["string_fallback"]


class TestGeneratedFromSpec:
    def test_generated_file_matches_the_spec(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "classifiers" / "generate.py"), "--target", "python", "--root", str(ROOT), "--check"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, result.stderr

    def test_version_and_digest_are_the_spec_s(self):
        assert _classifiers.SPEC_VERSION == SPEC["version"]
        assert _classifiers.SPEC_SHA256 == hashlib.sha256(SPEC_PATH.read_bytes()).hexdigest()

    def test_vocabulary(self):
        labels = tuple(entry["label"] for entry in SPEC["labels"])
        assert _classifiers.VOCAB == labels
        assert _fingerprint._VOCAB == frozenset(labels)
        assert _placeholders.SEMANTIC_TYPE_VOCAB == frozenset(labels)


class TestSpecExamples:
    @pytest.mark.parametrize("rule", RULES, ids=[r["label"] for r in RULES])
    def test_string_rule_examples(self, rule):
        for value in rule["match"]:
            assert _classifiers.classify_string(value) == _first_label(value)
            assert _fingerprint.classify_scalar(value) == _first_label(value)
        # The generated rule itself does not match its no_match examples.
        generated = dict(_classifiers.STRING_RULES)[rule["label"]]
        for value in rule["no_match"]:
            assert not generated.match(value), value

    def test_each_match_example_gets_its_rule_s_label_unless_an_earlier_rule_wins(self):
        for index, rule in enumerate(RULES):
            for value in rule["match"]:
                earlier = [r["label"] for r in RULES[:index]]
                got = _fingerprint.classify_scalar(value)
                assert got == rule["label"] or got in earlier, (value, got)

    def test_fallback_examples(self):
        for value in SPEC["value_classifier"]["fallback_examples"]:
            assert _fingerprint.classify_scalar(value) == SPEC["value_classifier"]["string_fallback"]

    def test_json_numbers(self):
        assert _fingerprint.classify_scalar(42) == SPEC["value_classifier"]["json_integer"]
        assert _fingerprint.classify_scalar(4.2) == SPEC["value_classifier"]["json_float"]
        assert _fingerprint.classify_scalar(True) is None
        assert _fingerprint.classify_scalar(None) is None

    def test_path_id_examples(self):
        for seg in SPEC["path_id"]["match"]:
            assert _templating._is_id_segment(seg), seg
        for seg in SPEC["path_id"]["no_match"]:
            assert not _templating._is_id_segment(seg), seg


class TestGroupIdsSetting:
    def test_template_path_on_and_off(self):
        curated = _templating.load_curated_templates(["/shops/{shop}/orders"])
        assert _templating.template_path("/orders/123", curated) == "/orders/{id}"
        assert _templating.template_path("/orders/123", curated, group_ids=False) == "/orders/123"
        # curated templates still group paths when the heuristic is off
        assert _templating.template_path("/shops/x1/orders", curated, group_ids=False) == "/shops/{shop}/orders"


class TestCaptureGroupIds:
    """The setting arrives in the rules sync and decides path_template."""

    def _process(self, sync_extra):
        from tests.test_pipeline import call_process, make_pipeline, make_sync_response
        sync = make_sync_response(fingerprint="unused", field_rules=[])
        sync.update(sync_extra)
        cache, pipeline = make_pipeline(fake_responses={"sync": (200, sync)})
        cache._poll_once()
        return cache, call_process(pipeline, url="https://api.example.com/v1/orders/123")

    def test_on_by_default_and_when_the_sync_says_so(self):
        for extra in ({}, {"project_settings": {"group_ids_in_paths": True}}):
            cache, payload = self._process(extra)
            assert cache.get_group_ids_in_paths() is True
            assert payload["path_template"] == "/v1/orders/{id}"

    def test_off_sends_the_path_as_written(self):
        cache, payload = self._process({"project_settings": {"group_ids_in_paths": False}})
        assert cache.get_group_ids_in_paths() is False
        assert payload["path_template"] == "/v1/orders/123"

    def test_a_later_sync_without_the_setting_keeps_it(self):
        from tests.test_pipeline import call_process, make_pipeline, make_sync_response
        off = make_sync_response(fingerprint="unused", field_rules=[], cursor="1")
        off["project_settings"] = {"group_ids_in_paths": False}
        cache, pipeline = make_pipeline(fake_responses={"sync": (200, off)})
        cache._poll_once()
        cache._fake_responses["sync"] = (200, make_sync_response(fingerprint="unused", field_rules=[], cursor="2"))
        cache._poll_once()
        assert cache.get_group_ids_in_paths() is False
        assert call_process(pipeline, url="https://api.example.com/v1/orders/123")["path_template"] == "/v1/orders/123"

    @pytest.mark.parametrize("bad", [{"project_settings": {"group_ids_in_paths": "false"}}, {"project_settings": []}, {"project_settings": None}])
    def test_a_malformed_setting_leaves_it_as_it_was(self, bad):
        cache, payload = self._process(bad)
        assert cache.get_group_ids_in_paths() is True

    def test_payload_names_the_classifier_spec_version(self):
        _, payload = self._process({})
        assert payload["classifier_spec_version"] == SPEC["version"]


class TestReplayGroupIds:
    _BASE = "https://api.example.com"

    def _bundle(self, settings):
        bundle = {
            "ok": True, "version": 1, "cursor": "0", "generated_at": "2024-01-01T00:00:00Z",
            "endpoints": [{
                "domain": "api.example.com", "method": "GET", "path_template": "/api/users/7",
                "is_dynamic": False, "fingerprint_value_paths": [], "stubs": [],
            }],
        }
        if settings is not None:
            bundle["project_settings"] = settings
        return bundle

    @pytest.mark.parametrize("settings, expected", [
        (None, "/api/orders/{id}"),
        ({"group_ids_in_paths": True}, "/api/orders/{id}"),
        ({"group_ids_in_paths": False}, "/api/orders/42"),
        ({"group_ids_in_paths": "no"}, "/api/orders/{id}"),
    ])
    def test_replay_templates_paths_like_capture(self, settings, expected):
        with pytest.raises(StubNotFound) as exc_info:
            with replay(bundle=self._bundle(settings)):
                requests.get(f"{self._BASE}/api/orders/42")
        assert exc_info.value.path_template == expected
