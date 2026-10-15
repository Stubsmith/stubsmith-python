"""Tests for generate.py: the spec checks, the regex translation and --check.

    python3 -m unittest discover -s <the directory of this file> -p 'test_*.py'

Standard library only.
"""
import contextlib
import copy
import hashlib
import io
import tempfile
import unittest
from pathlib import Path

import generate
from generate import SpecError, check_spec, js_regex, load_spec


def quiet(fn, *args, **kwargs):
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return fn(*args, **kwargs)


class SpecChecks(unittest.TestCase):
    def setUp(self):
        self.spec, self.sha = load_spec()

    def refused(self, change, message):
        spec = copy.deepcopy(self.spec)
        change(spec)
        with self.assertRaisesRegex(SpecError, message):
            check_spec(spec)

    def test_the_spec_passes(self):
        check_spec(self.spec)
        self.assertEqual(self.sha, hashlib.sha256(generate.SPEC_PATH.read_bytes()).hexdigest())

    def test_duplicate_label(self):
        self.refused(lambda s: s["labels"].append(dict(s["labels"][0])), "unique")

    def test_label_without_display_name(self):
        self.refused(lambda s: s["labels"][0].pop("display"), "display name")

    def test_current_version_not_accepted(self):
        self.refused(lambda s: s.update(version=s["version"] + 1), "accepted_versions")

    def test_rule_with_unknown_label(self):
        self.refused(lambda s: s["value_classifier"]["string_rules"][0].update(label="nope"), "unknown label")

    def test_unknown_flags(self):
        self.refused(lambda s: s["value_classifier"]["string_rules"][0].update(flags="m"), "flags")

    def test_match_example_that_does_not_match(self):
        self.refused(lambda s: s["value_classifier"]["string_rules"][0]["match"].append("not a match"), "does not match")

    def test_no_match_example_that_matches(self):
        rule = self.spec["value_classifier"]["string_rules"][0]
        self.refused(lambda s: s["value_classifier"]["string_rules"][0]["no_match"].append(rule["match"][0]), "should not")

    def test_fallback_example_that_matches_a_rule(self):
        rule = self.spec["value_classifier"]["string_rules"][0]
        self.refused(lambda s: s["value_classifier"]["fallback_examples"].append(rule["match"][0]), "matches a rule")

    def test_path_id_example_that_is_no_id(self):
        self.refused(lambda s: s["path_id"]["match"].append("orders"), "is not an ID")

    def test_path_id_rule_kinds(self):
        self.refused(lambda s: s["path_id"]["rules"].append({"name": "x", "kind": "glob"}), "unknown kind")
        self.refused(lambda s: s["path_id"]["rules"].append({"name": "x", "kind": "isdigit", "regex": "^a"}), "takes no regex")
        self.refused(lambda s: s["path_id"]["rules"].append({"name": "Bad", "kind": "isdigit"}), "identifiers")

    def test_unsupported_regex_syntax_in_a_rule(self):
        self.refused(lambda s: s["value_classifier"]["string_rules"][0].update(regex="^\\w+$"), "not supported")

    def test_i_flag_with_a_literal_or_class_matching_i(self):
        for regex in ("^[a-z]+$", "^id$", "^[^0-9]$", "^[\u0130]$", "^[\\-\u0131]$"):
            with self.subTest(regex=regex):
                self.refused(lambda s: s["value_classifier"]["string_rules"][0].update(regex=regex, flags="i"), "fold")
        # The uuid rule uses i with [0-9a-f], which cannot match the i family,
        # and test_the_spec_passes checks it is accepted.
        self.assertEqual(self.spec["value_classifier"]["string_rules"][0]["flags"], "i")

    def test_a_regex_python_cannot_compile(self):
        self.refused(lambda s: s["value_classifier"]["string_rules"][0].update(regex="^(a$"), "missing \\)")

    def test_label_that_is_no_identifier(self):
        self.refused(lambda s: s["labels"][0].update(label="a-b"), "identifier")

    def test_boolean_version(self):
        self.refused(lambda s: s.update(version=True, accepted_versions=[True]), "positive integer")

    def test_negative_min_length(self):
        def change(s):
            next(r for r in s["path_id"]["rules"] if r["kind"] == "regex")["min_length"] = -1
        self.refused(change, "non-negative")


class JsRegex(unittest.TestCase):
    def test_translation_follows_python_re(self):
        # re.match anchors at the start; RegExp.test would search.
        self.assertEqual(js_regex("abc"), "^(?:abc)")
        self.assertEqual(js_regex("^a|b"), "^(?:^a|b)")
        self.assertEqual(js_regex("^a$"), "^(?:^a(?=\\n?$))")
        self.assertEqual(js_regex("a.b"), "^(?:a[^\\n]b)")
        self.assertEqual(js_regex("\\d{2}"), "^(?:\\p{Nd}{2})")
        self.assertEqual(js_regex("[.$\\-]"), "^(?:[.$\\-])")
        self.assertEqual(js_regex("(?:a|b)\\.\\/"), "^(?:(?:a|b)\\.\\/)")
        self.assertEqual(js_regex("a??b*?c{2,}?"), "^(?:a??b*?c{2,}?)")

    def test_refused_syntax(self):
        for source in (
            "\\w", "\\s", "\\b", "(?=a)", "(?i)a", "(?P<n>a)", "a\\", "[a", "[[a]",
            # Python reads these as literals or possessives; JS with the u flag rejects them.
            "[]a]", "[^]a]", "a{", "a}", "b]", "a{,3}", "a*+", "a++", "a?+", "a??+",
            # Not a regex in either engine.
            "x{2,1}", "*a", "a**", "a{2}{3}",
        ):
            with self.subTest(source=source), self.assertRaises(SpecError):
                js_regex(source)

    def test_refusals_name_the_problem(self):
        for source, message in (
            ("[]a]", "first in a character class"),
            ("[^]a]", "first in a character class"),
            ("a*+", "possessive"),
            ("a{2}{3}", "stacked"),
            ("a{,3}", "\\{n\\}"),
            ("*a", "nothing to repeat"),
            ("a{1001}", "over 1000"),
            ("a{2,1001}", "over 1000"),
        ):
            with self.subTest(source=source), self.assertRaisesRegex(SpecError, message):
                js_regex(source)


class GeneratedPython(unittest.TestCase):
    """The generated Python module behaves as the spec's examples say."""

    @classmethod
    def setUpClass(cls):
        spec, sha = load_spec()
        cls.spec = spec
        cls.sha = sha
        cls.module = {}
        exec(compile(generate.gen_python(spec, sha), "_classifiers.py", "exec"), cls.module)

    def test_header_and_constants(self):
        source = generate.gen_python(self.spec, self.sha)
        self.assertIn(f"spec version {self.spec['version']}, sha256 {self.sha}", source.splitlines()[0])
        self.assertEqual(self.module["SPEC_VERSION"], self.spec["version"])
        self.assertEqual(self.module["SPEC_SHA256"], self.sha)
        self.assertEqual(self.module["VOCAB"], tuple(e["label"] for e in self.spec["labels"]))

    def test_value_classifier_examples(self):
        classify = self.module["classify_string"]
        vc = self.spec["value_classifier"]
        for i, rule in enumerate(vc["string_rules"]):
            earlier = vc["string_rules"][:i]
            for value in rule["match"]:
                # An earlier rule may claim the value first; the spec check
                # guarantees this rule matches it, so the label is one of these.
                labels = {r["label"] for r in earlier} | {rule["label"]}
                with self.subTest(label=rule["label"], value=value):
                    self.assertIn(classify(value), labels)
        for value in vc["fallback_examples"]:
            with self.subTest(value=value):
                self.assertEqual(classify(value), vc["string_fallback"])

    def test_path_id_examples(self):
        is_id = self.module["is_id_segment"]
        for value in self.spec["path_id"]["match"]:
            with self.subTest(value=value):
                self.assertTrue(is_id(value))
        for value in self.spec["path_id"]["no_match"]:
            with self.subTest(value=value):
                self.assertFalse(is_id(value))


class Check(unittest.TestCase):
    def test_check_fails_on_a_missing_or_edited_file_and_passes_after_writing(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root, "stubsmith/privacy/_classifiers.py")
            self.assertEqual(quiet(generate.main, ["--target", "python", "--root", root, "--check"]), 1)
            self.assertFalse(target.exists())
            self.assertEqual(quiet(generate.main, ["--target", "python", "--root", root]), 0)
            self.assertEqual(quiet(generate.main, ["--target", "python", "--root", root, "--check"]), 0)
            target.write_text(target.read_text(encoding="utf-8") + "# edited\n", encoding="utf-8")
            self.assertEqual(quiet(generate.main, ["--target", "python", "--root", root, "--check"]), 1)


if __name__ == "__main__":
    unittest.main()
