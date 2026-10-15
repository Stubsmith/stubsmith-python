# Value-type labels and path ID rules

`classifiers.json` is the single definition of:

- the value-type labels an SDK reports for observed values (`email`, `uuid`, ...), with their display names;
- how an SDK picks a label for a value (`value_classifier`);
- which path segments an SDK treats as IDs and turns into `{id}` (`path_id`), when the project lets it group IDs automatically.

`generate.py` turns it into code. Every generated file starts with a header naming the spec version and its SHA-256, and must not be edited by hand.

| Target | Generated file |
| --- | --- |
| `python` | `stubsmith/privacy/_classifiers.py` |
| `node` | `src/privacy/classifiers.generated.ts` |

## Changing a label or a rule

1. Edit `classifiers.json`. Bump `version` for any change to labels or rules, and add the new version to `accepted_versions`; keep older versions there for as long as SDKs that send them are in use.
2. Copy the same `classifiers.json` and `generate.py` into each SDK (`tools/classifiers/`) and run `python3 tools/classifiers/generate.py --target <target>` from its root.
3. CI runs the generator with `--check`, which fails when a generated file does not match the spec next to it.

`python3 -m unittest discover -s <this directory> -p 'test_*.py'` tests the generator itself.

Before writing anything, `generate.py` checks the spec itself: labels are unique lowercase identifiers, every rule names a known label, the current version is accepted, every regex compiles, and every `match`/`no_match` example behaves as stated under Python's `re`, the reference engine. The SDKs' own test suites run the same examples against their generated code.

Regexes are Python `re` syntax and are applied the way `re.match` applies them: anchored at the start, with `$` also matching before one trailing newline and `\d` matching any Unicode decimal digit. The JavaScript output reproduces that. Only a small subset is allowed: literals, `.`, `^`, `$`, `|`, `(...)` and `(?:...)` groups, character classes, the escapes `\d` and escaped punctuation, and the repeats `* + ? {n} {n,} {n,m}`, lazy or not. No lookarounds, backreferences, possessive repeats, `\w`, `\s` or `\b`. With the `i` flag, a literal or class that could match `i` or `I` is refused too, because Python folds `İ` and `ı` into them and JavaScript does not. `generate.py` refuses the rest, so every regex is also valid RE2 and behaves the same in Python and JavaScript on ASCII; which non-ASCII characters `\d` covers follows each runtime's Unicode version.
