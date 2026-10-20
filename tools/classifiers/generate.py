#!/usr/bin/env python3
"""Generate the value-type classifier and path ID code from classifiers.json.

One spec, many copies: each SDK gets a generated file, so a label or rule
changes in one place. Every generated file records the spec's version and
SHA-256.

    python3 tools/classifiers/generate.py --target python          # write
    python3 tools/classifiers/generate.py --target python --check  # CI: fail on drift

Targets and the files they write (relative to --root, default the current
directory):

    python     stubsmith/privacy/_classifiers.py
    node       src/privacy/classifiers.generated.ts

Before writing anything the spec is checked: labels are unique and have a
display name, every rule names a known label, flags are known, regexes use only
the syntax the JavaScript translation reproduces exactly, and every example in
the spec behaves as stated under Python's re (the reference engine). Standard
library only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC_PATH = HERE / "classifiers.json"


class SpecError(Exception):
    pass


def load_spec():
    raw = SPEC_PATH.read_bytes()
    return json.loads(raw.decode("utf-8")), hashlib.sha256(raw).hexdigest()


def py_flags(flags):
    return re.IGNORECASE if flags == "i" else 0


def check_flags(where, flags):
    if flags not in (None, "", "i"):
        raise SpecError(f"{where}: flags must be \"\" or \"i\"")


IDENTIFIER = re.compile(r"[a-z][a-z0-9_]*")


def is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


# Under case-insensitive matching Python folds i, I, U+0130 and U+0131 together;
# JavaScript's iu does not.
I_FAMILY = "iI\u0130\u0131"


def check_case_fold(where, source):
    """Refuse an "i" rule where a literal or a class could match the i family."""
    i = 0
    while i < len(source):
        c = source[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            end = i + 1
            while source[end] != "]":
                end += 2 if source[end] == "\\" else 1
            cls = re.compile(source[i:end + 1])
            if any(cls.fullmatch(ch) for ch in I_FAMILY):
                raise SpecError(f"{where}: with flags \"i\", a class must not match i or I (Python and JavaScript fold them differently)")
            i = end + 1
            continue
        if c in I_FAMILY:
            raise SpecError(f"{where}: with flags \"i\", a literal i or I is not allowed (Python and JavaScript fold it differently)")
        i += 1


def compile_rule(where, rule):
    """Compile a rule's regex for Python, after checking the JS translation accepts it."""
    js_regex(rule["regex"])  # refuses syntax the JS translation cannot reproduce
    if rule.get("flags") == "i":
        check_case_fold(where, rule["regex"])
    try:
        return re.compile(rule["regex"], py_flags(rule.get("flags")))
    except re.error as exc:
        raise SpecError(f"{where}: {exc}") from None


def check_spec(spec):
    labels = [entry.get("label") for entry in spec["labels"]]
    if len(set(labels)) != len(labels):
        raise SpecError("labels must be unique")
    for entry in spec["labels"]:
        if not isinstance(entry.get("label"), str) or not isinstance(entry.get("display"), str):
            raise SpecError("every label needs a label and a display name")
        if not IDENTIFIER.fullmatch(entry["label"]):
            raise SpecError(f"label {entry['label']!r} must be a lowercase identifier")
    if not is_int(spec.get("version")) or spec["version"] < 1:
        raise SpecError("version must be a positive integer")
    accepted = spec.get("accepted_versions", [])
    if spec["version"] not in accepted or any(not is_int(v) for v in accepted):
        raise SpecError("accepted_versions must list the current version")
    vc = spec["value_classifier"]
    for key in ("json_integer", "json_float", "string_fallback"):
        if vc[key] not in labels:
            raise SpecError(f"value_classifier.{key} names an unknown label")
    for rule in vc["string_rules"]:
        if rule["label"] not in labels:
            raise SpecError(f"string rule for unknown label {rule['label']!r}")
        check_flags(f"string rule {rule['label']}", rule.get("flags"))
        rx = compile_rule(f"string rule {rule['label']}", rule)
        for value in rule["match"]:
            if not rx.match(value):
                raise SpecError(f"{rule['label']}: example {value!r} does not match")
        for value in rule["no_match"]:
            if rx.match(value):
                raise SpecError(f"{rule['label']}: example {value!r} matches but should not")
    for value in vc["fallback_examples"]:
        if any(compile_rule("", r).match(value) for r in vc["string_rules"]):
            raise SpecError(f"fallback example {value!r} matches a rule")
    pid = spec["path_id"]
    names = [rule.get("name") for rule in pid["rules"]]
    if len(set(names)) != len(names) or not all(isinstance(n, str) and IDENTIFIER.fullmatch(n) for n in names):
        raise SpecError("path_id rule names must be unique lowercase identifiers")
    for rule in pid["rules"]:
        if rule["kind"] == "isdigit":
            if set(rule) - {"name", "kind"}:
                raise SpecError(f"path_id rule {rule['name']}: isdigit takes no regex, flags or min_length")
        elif rule["kind"] == "regex":
            check_flags(f"path_id rule {rule['name']}", rule.get("flags"))
            compile_rule(f"path_id rule {rule['name']}", rule)
            if not is_int(rule.get("min_length", 0)) or rule.get("min_length", 0) < 0:
                raise SpecError(f"path_id rule {rule['name']}: min_length must be a non-negative integer")
        else:
            raise SpecError(f"path_id rule {rule['name']}: unknown kind {rule['kind']!r}")
    for value in pid["match"]:
        if not py_is_id_segment(pid, value):
            raise SpecError(f"path_id: example {value!r} is not an ID")
    for value in pid["no_match"]:
        if py_is_id_segment(pid, value):
            raise SpecError(f"path_id: example {value!r} is an ID but should not be")


def py_is_id_segment(pid, seg):
    for rule in pid["rules"]:
        if rule["kind"] == "isdigit":
            if seg.isdigit():
                return True
        elif rule["kind"] == "regex":
            if len(seg) >= rule.get("min_length", 0) and compile_rule("", rule).match(seg):
                return True
        else:
            raise SpecError(f"unknown path_id rule kind {rule['kind']!r}")
    return False


# ---------------------------------------------------------------------------
# Python regex to JavaScript. The JS side must behave like Python's re.match:
# anchored at the start, `$` also matching before one trailing newline, `.`
# excluding only a newline, and \d any Unicode decimal digit. Only syntax this
# translation reproduces exactly is accepted; anything else is refused, so the
# generated JS can never fail to compile or mean something else.
# ---------------------------------------------------------------------------

JS_SYNTAX = set("^$\\.*+?()[]{}|/")
QUANTIFIER = re.compile(r"\{(\d+)(,(\d*))?\}")


def js_regex(source):
    out = []
    i = 0
    in_class = False
    # Whether the last token can take a quantifier, whether it is one, and
    # whether that quantifier is already lazy.
    can_repeat = False
    repeated = False
    lazy = False
    while i < len(source):
        c = source[i]
        if c == "\\":
            if i + 1 >= len(source):
                raise SpecError("a regex ends with a lone backslash")
            nxt = source[i + 1]
            if nxt == "d":
                out.append("\\p{Nd}")
            elif nxt in JS_SYNTAX or (in_class and nxt == "-"):
                out.append("\\" + nxt)
            else:
                raise SpecError(f"the escape \\{nxt} is not supported in classifiers.json")
            i += 2
            can_repeat, repeated = not in_class, False
            continue
        if in_class:
            if c == "[":
                raise SpecError("a [ inside a character class must be escaped")
            if c == "]":
                in_class = False
                can_repeat, repeated = True, False
            out.append(c)
            i += 1
            continue
        if c in "*+?{":
            if c == "{":
                m = QUANTIFIER.match(source, i)
                if not m:
                    raise SpecError("a { must start a {n}, {n,} or {n,m} repeat; escape a literal one")
                if m.group(3) and int(m.group(3)) < int(m.group(1)):
                    raise SpecError(f"the repeat {m.group(0)} is out of order")
                if max(int(m.group(1)), int(m.group(3) or 0)) > 1000:
                    raise SpecError(f"the repeat {m.group(0)} is over 1000, the most RE2 allows")
                token = m.group(0)
            else:
                token = c
            if c == "?" and repeated and not lazy:
                out.append("?")
                i += 1
                lazy = True
                continue
            if repeated:
                raise SpecError("possessive and stacked repeats are not supported in classifiers.json")
            if not can_repeat:
                raise SpecError(f"{token} has nothing to repeat")
            out.append(token)
            i += len(token)
            can_repeat, repeated, lazy = False, True, False
            continue
        if c in "}]":
            raise SpecError(f"a literal {c} must be escaped")
        if c == "[":
            in_class = True
            out.append(c)
            i += 1
            if source.startswith("^", i):
                out.append("^")
                i += 1
            if source.startswith("]", i):
                raise SpecError("a ] first in a character class must be escaped")
            continue
        if c == "(" and source.startswith("(?", i):
            if not source.startswith("(?:", i):
                raise SpecError("only (...) and (?:...) groups are supported in classifiers.json")
            out.append("(?:")
            i += 3
            can_repeat, repeated = False, False
            continue
        if c == "$":
            out.append("(?=\\n?$)")
        elif c == ".":
            out.append("[^\\n]")
        else:
            out.append(c)
        i += 1
        can_repeat, repeated = c not in "(|^$", False
    if in_class:
        raise SpecError("a character class is not closed")
    # re.match only tries the start of the string; RegExp.test tries every position.
    return "^(?:" + "".join(out) + ")"


def js_flags(flags):
    return "u" + ("i" if "i" in (flags or "") else "")


def header(comment, spec, sha, tool="generate.py"):
    return (
        f"{comment} Generated by {tool} from classifiers.json "
        f"(spec version {spec['version']}, sha256 {sha}). Do not edit; change the spec and regenerate.\n"
    )


def js_string(s):
    return json.dumps(s, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------

def gen_python(spec, sha):
    vc = spec["value_classifier"]
    pid = spec["path_id"]
    lines = [
        header("#", spec, sha).rstrip("\n"),
        '"""Value-type labels and path ID rules, generated from classifiers.json."""',
        "",
        "import re",
        "",
        f"SPEC_VERSION = {spec['version']}",
        f"SPEC_SHA256 = {sha!r}",
        "",
        "# Value-type labels, in display order.",
        "VOCAB = (",
        *[f"    {e['label']!r}," for e in spec["labels"]],
        ")",
        "",
        f"JSON_INTEGER = {vc['json_integer']!r}",
        f"JSON_FLOAT = {vc['json_float']!r}",
        f"STRING_FALLBACK = {vc['string_fallback']!r}",
        "",
        "# String rules in check order: the first that matches gives the label.",
        "STRING_RULES = (",
    ]
    for rule in vc["string_rules"]:
        flags = ", re.IGNORECASE" if "i" in rule.get("flags", "") else ""
        lines.append(f"    ({rule['label']!r}, re.compile({rule['regex']!r}{flags})),")
    lines += [
        ")",
        "",
        "",
        "def classify_string(s):",
        '    """Return the label for a string value."""',
        "    for label, rx in STRING_RULES:",
        "        if rx.match(s):",
        "            return label",
        "    return STRING_FALLBACK",
        "",
        "",
    ]
    regexes = []
    checks = []
    for rule in pid["rules"]:
        if rule["kind"] == "isdigit":
            checks.append("    if seg.isdigit():\n        return True")
        else:
            name = "_PATH_ID_" + rule["name"].upper()
            flags = ", re.IGNORECASE" if "i" in rule.get("flags", "") else ""
            regexes.append(f"{name} = re.compile({rule['regex']!r}{flags})")
            cond = f"{name}.match(seg)"
            if rule.get("min_length"):
                cond = f"len(seg) >= {rule['min_length']} and {cond}"
            checks.append(f"    if {cond}:\n        return True")
    lines += regexes + [
        "",
        "",
        "def is_id_segment(seg):",
        '    """Return True when a path segment looks like a dynamic ID."""',
        *checks,
        "    return False",
        "",
    ]
    return "\n".join(lines)


def gen_node(spec, sha):
    vc = spec["value_classifier"]
    pid = spec["path_id"]
    lines = [
        header("//", spec, sha),
        'import { pyIsDigit } from "../internal/pystr.js";',
        "",
        f"export const SPEC_VERSION = {spec['version']};",
        f"export const SPEC_SHA256 = {js_string(sha)};",
        "",
        "/** Value-type labels, in display order. */",
        "export const VOCAB: ReadonlySet<string> = new Set([",
        *[f"  {js_string(e['label'])}," for e in spec["labels"]],
        "]);",
        "",
        f"export const JSON_INTEGER = {js_string(vc['json_integer'])};",
        f"export const JSON_FLOAT = {js_string(vc['json_float'])};",
        f"export const STRING_FALLBACK = {js_string(vc['string_fallback'])};",
        "",
        "/** String rules in check order; Python re semantics ($ before a trailing newline, Unicode \\d). */",
        "export const STRING_RULES: ReadonlyArray<readonly [string, RegExp]> = [",
    ]
    for rule in vc["string_rules"]:
        lines.append(f"  [{js_string(rule['label'])}, new RegExp({js_string(js_regex(rule['regex']))}, {js_string(js_flags(rule.get('flags')))})],")
    lines += [
        "];",
        "",
        "/** The label for a string value. */",
        "export function classifyString(s: string): string {",
        "  for (const [label, rx] of STRING_RULES) if (rx.test(s)) return label;",
        "  return STRING_FALLBACK;",
        "}",
        "",
    ]
    checks = []
    for rule in pid["rules"]:
        if rule["kind"] == "isdigit":
            checks.append("  if (pyIsDigit(seg)) return true;")
        else:
            name = "PATH_ID_" + rule["name"].upper()
            lines.append(f"const {name} = new RegExp({js_string(js_regex(rule['regex']))}, {js_string(js_flags(rule.get('flags')))});")
            cond = f"{name}.test(seg)"
            if rule.get("min_length"):
                # min_length counts code points, as Python's len does.
                cond = f"[...seg].length >= {rule['min_length']} && {cond}"
            checks.append(f"  if ({cond}) return true;")
    lines += [
        "",
        "/** True when a path segment looks like a dynamic ID. */",
        "export function isIdSegment(seg: string): boolean {",
        *checks,
        "  return false;",
        "}",
        "",
    ]
    return "\n".join(lines)


TARGETS = {
    "python": [("stubsmith/privacy/_classifiers.py", gen_python)],
    "node": [("src/privacy/classifiers.generated.ts", gen_node)],
}


def main(argv=None, targets=None):
    targets = targets or TARGETS
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", required=True, choices=sorted(targets))
    parser.add_argument("--root", default=".", help="repository root the target paths are relative to")
    parser.add_argument("--check", action="store_true", help="fail if a generated file differs, write nothing")
    args = parser.parse_args(argv)

    spec, sha = load_spec()
    try:
        check_spec(spec)
    except SpecError as exc:
        print(f"classifiers.json: {exc}", file=sys.stderr)
        return 1

    root = Path(args.root)
    stale = []
    for rel, gen in targets[args.target]:
        path = root / rel
        content = gen(spec, sha)
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if current == content:
            continue
        if args.check:
            stale.append(rel)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            print(f"wrote {rel}")
    if stale:
        for rel in stale:
            print(f"{rel} is out of date with classifiers.json; run the generator with --target {args.target}", file=sys.stderr)
        return 1
    if args.check:
        print(f"generated files match classifiers.json (version {spec['version']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
