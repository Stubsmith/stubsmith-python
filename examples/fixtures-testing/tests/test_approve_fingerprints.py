"""
Hermetic tests for approve_fingerprints.py - no network.

The script's job is to reproduce, by API, the rule set README.md documents.
Two things can silently break it: the table drifting away from the README, and
the (method, path_template, fingerprint) key degrading to fingerprint alone -
which looks fine until two endpoints share a hash. Both are covered here.
"""
from __future__ import annotations

import io
import json
import pathlib
import re
import urllib.error
import urllib.request

import pytest

import approve_fingerprints as af

_README = pathlib.Path(__file__).parent.parent / "README.md"


@pytest.fixture(autouse=True)
def _default_project(monkeypatch):
    """Scope every main() test to a project.

    The script refuses to run unscoped, which is its own test below -- those
    tests clear this variable explicitly.
    """
    monkeypatch.setenv("STUBSMITH_PROJECT_ID", "proj-default")


# ---------------------------------------------------------------------------
# Fake HTTP
# ---------------------------------------------------------------------------

class _FakeResponse(io.BytesIO):
    """Minimal urlopen() stand-in: a context manager whose read() returns bytes."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _fake_urlopen(queue, recorder, fail_on=None):
    """Return a urlopen replacement serving *queue* and recording approvals."""

    def _opener(req, *a, **kw):
        url = req.full_url
        if "/v1/review/queue" in url:
            return _FakeResponse(json.dumps({"ok": True, "queue": queue}).encode())
        m = re.search(r"/v1/review/([^/]+)/decision$", url)
        if m:
            fp_id = m.group(1)
            if fail_on and fp_id in fail_on:
                raise urllib.error.HTTPError(
                    url, 400, "Bad Request", {}, io.BytesIO(b'{"error":"nope"}')
                )
            recorder.append((fp_id, json.loads(req.data.decode())))
            return _FakeResponse(b'{"ok":true}')
        raise AssertionError(f"unexpected URL: {url}")

    return _opener


def _row(method, path_template, fingerprint, fp_id="fp-1", value_paths=None):
    return {
        "id": fp_id,
        "method": method,
        "path_template": path_template,
        "fingerprint": fingerprint,
        "fingerprint_value_paths": value_paths or [],
    }


# ---------------------------------------------------------------------------
# Rule lookup
# ---------------------------------------------------------------------------

def test_colliding_fingerprint_resolves_by_endpoint():
    """fc552c95a0bb0d3e belongs to two endpoints with different rules.

    Keying on the fingerprint alone would return one endpoint's rules for the
    other, keeping resp.id on an orders response and resp.order_id on a users
    response - both would then be masked and fail a test with no clue why.
    """
    users = af.rules_for(_row("GET", "/api/users/{id}", "fc552c95a0bb0d3e"))
    orders = af.rules_for(_row("GET", "/api/orders/{id}", "fc552c95a0bb0d3e"))

    users_paths = {r["path"] for r in users}
    orders_paths = {r["path"] for r in orders}

    assert users_paths != orders_paths
    assert "resp.plan" in users_paths
    assert "resp.plan" not in orders_paths
    assert "resp.total_cents" in orders_paths
    assert "resp.total_cents" not in users_paths


def test_charges_fingerprints_get_different_rules():
    """Same endpoint, two request shapes, two rule sets."""
    ok = af.rules_for(_row("POST", "/api/payments/charges", "79148562d5fb5ae8"))
    declined = af.rules_for(_row("POST", "/api/payments/charges", "4a17ca4d93dddd7d"))

    assert "resp.card.last4" in {r["path"] for r in ok}
    assert "resp.card.last4" not in {r["path"] for r in declined}
    assert "resp.code" in {r["path"] for r in declined}


def test_unknown_row_returns_none():
    assert af.rules_for(_row("GET", "/api/unheard-of", "0000000000000000")) is None


def test_method_is_matched_case_insensitively():
    assert af.rules_for(_row("get", "/api/users/{id}", "fc552c95a0bb0d3e")) is not None


def test_every_rule_is_a_keep():
    for rules in (af.rules_for(_row(m, p, f)) for m, p, f in af.KEEP_RULES):
        assert all(r["action"] == "keep" for r in rules)


# ---------------------------------------------------------------------------
# Value-path keeps
# ---------------------------------------------------------------------------

def test_value_paths_are_namespaced_and_appended():
    """The backend requires a keep rule at "body." + path for each value path."""
    rules = af.build_field_rules(["resp.id"], ["status", "card.brand"])
    paths = [r["path"] for r in rules]
    assert paths == ["resp.id", "body.status", "body.card.brand"]


def test_value_path_already_kept_is_not_duplicated():
    rules = af.build_field_rules(["body.status"], ["status"])
    assert [r["path"] for r in rules] == ["body.status"]


def test_non_string_value_paths_are_ignored():
    rules = af.build_field_rules(["resp.id"], [None, 7, "status"])
    assert [r["path"] for r in rules] == ["resp.id", "body.status"]


def test_rules_for_includes_value_path_keeps():
    row = _row(
        "POST", "/api/payments/charges", "79148562d5fb5ae8", value_paths=["currency"]
    )
    assert "body.currency" in {r["path"] for r in af.rules_for(row)}


# ---------------------------------------------------------------------------
# README parity
# ---------------------------------------------------------------------------

def _readme_rules():
    text = _README.read_text()
    pattern = re.compile(
        r"\*\*(GET|POST|PUT|PATCH|DELETE)\s+(\S+).*?fingerprint\s+`([0-9a-f]{16})`\*\*"
        r"\s*```json\s*(\[.*?\])\s*```",
        re.DOTALL,
    )
    out = {}
    for method, path, fp, body in pattern.findall(text):
        out[(method, path, fp)] = [r["path"] for r in json.loads(body)]
    return out


def test_readme_documents_the_same_rules_as_the_script():
    """The README is the user-facing instruction; drift makes it a lie.

    A reader who follows Step 3 by hand must land on the same bundle the script
    produces, or the committed assertions pass for one path and fail for the
    other.
    """
    documented = _readme_rules()
    assert documented, "no rule blocks parsed from README.md - parser is broken"
    assert documented == {k: list(v) for k, v in af.KEEP_RULES.items()}


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------

def test_main_approves_every_queued_fingerprint(monkeypatch, capsys):
    queue = [
        _row("GET", "/api/users/{id}", "fc552c95a0bb0d3e", fp_id="a"),
        _row("POST", "/api/users", "90dc0baeeee2ad16", fp_id="b"),
    ]
    sent = []
    monkeypatch.setenv("STUBSMITH_API_KEY", "org-key")
    monkeypatch.setenv("STUBSMITH_API_URL", "https://example.invalid/api")
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen(queue, sent))

    assert af.main([]) == 0
    assert [fp_id for fp_id, _ in sent] == ["a", "b"]
    assert all(p["decision"] == "approve" for _, p in sent)
    assert {r["path"] for r in sent[0][1]["field_rules"]} == {
        "resp.id",
        "resp.plan",
        "resp.active",
    }


def test_undocumented_fingerprint_aborts_before_approving_anything(monkeypatch, capsys):
    """A queue holding fingerprints this example does not document means the
    wrong project. The recognised ones must not be approved anyway: these keep
    rules are written for the shop service, and another project's operator never
    chose to keep those fields. Reporting after approving would be too late."""
    queue = [
        _row("GET", "/api/unheard-of", "0000000000000000", fp_id="z"),
        _row("POST", "/api/users", "90dc0baeeee2ad16", fp_id="b"),
    ]
    sent = []
    monkeypatch.setenv("STUBSMITH_ORG_API_KEY", "org-key")
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen(queue, sent))

    assert af.main([]) == 2
    assert sent == [], "must approve nothing when the project looks wrong"
    err = capsys.readouterr().err
    assert "/api/unheard-of" in err
    assert "--ignore-unknown" in err


def test_ignore_unknown_approves_the_documented_ones(monkeypatch, capsys):
    queue = [
        _row("GET", "/api/unheard-of", "0000000000000000", fp_id="z"),
        _row("POST", "/api/users", "90dc0baeeee2ad16", fp_id="b"),
    ]
    sent = []
    monkeypatch.setenv("STUBSMITH_ORG_API_KEY", "org-key")
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen(queue, sent))

    assert af.main(["--ignore-unknown"]) == 1
    assert [fp_id for fp_id, _ in sent] == ["b"]
    assert "/api/unheard-of" in capsys.readouterr().err


def test_dry_run_also_aborts_on_unknown(monkeypatch, capsys):
    """--dry-run is how you check a project before committing to it, so it must
    report the same verdict rather than printing a reassuring plan."""
    queue = [_row("GET", "/api/unheard-of", "0000000000000000", fp_id="z")]
    sent = []
    monkeypatch.setenv("STUBSMITH_ORG_API_KEY", "org-key")
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen(queue, sent))

    assert af.main(["--dry-run"]) == 2
    assert sent == []


def test_summary_names_the_project_it_approved_in(monkeypatch, capsys):
    queue = [_row("POST", "/api/users", "90dc0baeeee2ad16", fp_id="b")]
    sent = []
    monkeypatch.setenv("STUBSMITH_ORG_API_KEY", "org-key")
    monkeypatch.setenv("STUBSMITH_PROJECT_ID", "shop-proj-uuid")
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen(queue, sent))

    assert af.main([]) == 0
    assert "shop-proj-uuid" in capsys.readouterr().out


def test_main_reports_approval_failures(monkeypatch, capsys):
    queue = [_row("POST", "/api/users", "90dc0baeeee2ad16", fp_id="b")]
    sent = []
    monkeypatch.setenv("STUBSMITH_API_KEY", "org-key")
    monkeypatch.setattr(
        urllib.request, "urlopen", _fake_urlopen(queue, sent, fail_on={"b"})
    )

    assert af.main([]) == 1
    assert "HTTP 400" in capsys.readouterr().err


def test_dry_run_sends_nothing(monkeypatch, capsys):
    queue = [_row("GET", "/api/users/{id}", "fc552c95a0bb0d3e", fp_id="a")]
    sent = []
    monkeypatch.setenv("STUBSMITH_API_KEY", "org-key")
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen(queue, sent))

    assert af.main(["--dry-run"]) == 0
    assert sent == []
    assert "would approve" in capsys.readouterr().out


def test_empty_queue_is_success(monkeypatch, capsys):
    monkeypatch.setenv("STUBSMITH_API_KEY", "org-key")
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen([], []))

    assert af.main([]) == 0
    assert "Nothing to approve" in capsys.readouterr().out


def test_missing_api_key_exits_two(monkeypatch, capsys):
    monkeypatch.delenv("STUBSMITH_ORG_API_KEY", raising=False)
    monkeypatch.delenv("STUBSMITH_API_KEY", raising=False)
    assert af.main([]) == 2
    assert "STUBSMITH_ORG_API_KEY" in capsys.readouterr().err


def test_project_id_is_passed_as_query_param(monkeypatch):
    seen = {}

    def _opener(req, *a, **kw):
        seen["url"] = req.full_url
        return _FakeResponse(json.dumps({"queue": []}).encode())

    monkeypatch.setenv("STUBSMITH_API_KEY", "org-key")
    monkeypatch.setattr(urllib.request, "urlopen", _opener)
    af.main(["--project-id", "abc-123"])
    assert "projectId=abc-123" in seen["url"]


def test_default_api_url_is_the_hosted_service(monkeypatch):
    """Guards the localhost-default regression in this script too."""
    seen = {}

    def _opener(req, *a, **kw):
        seen["url"] = req.full_url
        return _FakeResponse(json.dumps({"queue": []}).encode())

    monkeypatch.delenv("STUBSMITH_API_URL", raising=False)
    monkeypatch.delenv("STUBSMITH_BACKEND_URL", raising=False)
    monkeypatch.setenv("STUBSMITH_API_KEY", "org-key")
    monkeypatch.setattr(urllib.request, "urlopen", _opener)
    af.main([])
    assert seen["url"].startswith("https://app.stubsmith.dev/api/")


# ---------------------------------------------------------------------------
# Key selection
#
# generate_traffic.py needs the project key in STUBSMITH_API_KEY and this script
# needs an org key. They run in sequence, so a shared variable would have to be
# swapped between steps.
# ---------------------------------------------------------------------------

def test_org_key_wins_over_project_key(monkeypatch):
    seen = {}

    def _opener(req, *a, **kw):
        seen["auth"] = req.headers.get("Authorization")
        return _FakeResponse(json.dumps({"queue": []}).encode())

    monkeypatch.setenv("STUBSMITH_API_KEY", "project-key")
    monkeypatch.setenv("STUBSMITH_ORG_API_KEY", "org-key")
    monkeypatch.setattr(urllib.request, "urlopen", _opener)
    af.main([])
    assert seen["auth"] == "Bearer org-key"


def test_falls_back_to_api_key_when_org_key_absent(monkeypatch):
    seen = {}

    def _opener(req, *a, **kw):
        seen["auth"] = req.headers.get("Authorization")
        return _FakeResponse(json.dumps({"queue": []}).encode())

    monkeypatch.delenv("STUBSMITH_ORG_API_KEY", raising=False)
    monkeypatch.setenv("STUBSMITH_API_KEY", "only-key")
    monkeypatch.setattr(urllib.request, "urlopen", _opener)
    af.main([])
    assert seen["auth"] == "Bearer only-key"


def test_blank_key_is_treated_as_missing(monkeypatch, capsys):
    monkeypatch.setenv("STUBSMITH_ORG_API_KEY", "   ")
    monkeypatch.delenv("STUBSMITH_API_KEY", raising=False)
    assert af.main([]) == 2
    assert "STUBSMITH_ORG_API_KEY" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Auth failure diagnostics
# ---------------------------------------------------------------------------

def _http_error_opener(code):
    def _opener(req, *a, **kw):
        raise urllib.error.HTTPError(
            req.full_url, code, "denied", {}, io.BytesIO(b'{"error":"invalid token"}')
        )

    return _opener


def test_401_names_the_variable_the_key_came_from(monkeypatch, capsys):
    """A bare 401 does not say the *kind* of key was wrong.

    The fallback to STUBSMITH_API_KEY is the trap: that variable holds the
    project key the traffic script needs, and this endpoint rejects it.
    """
    monkeypatch.delenv("STUBSMITH_ORG_API_KEY", raising=False)
    monkeypatch.setenv("STUBSMITH_API_KEY", "a-project-key")
    monkeypatch.setattr(urllib.request, "urlopen", _http_error_opener(401))

    assert af.main([]) == 1
    err = capsys.readouterr().err
    assert "$STUBSMITH_API_KEY" in err
    assert "org" in err
    assert "STUBSMITH_ORG_API_KEY" in err


def test_403_gets_the_same_hint(monkeypatch, capsys):
    monkeypatch.setenv("STUBSMITH_ORG_API_KEY", "scopeless-org-key")
    monkeypatch.setattr(urllib.request, "urlopen", _http_error_opener(403))

    assert af.main([]) == 1
    assert "$STUBSMITH_ORG_API_KEY" in capsys.readouterr().err


def test_500_does_not_get_the_auth_hint(monkeypatch, capsys):
    monkeypatch.setenv("STUBSMITH_ORG_API_KEY", "org-key")
    monkeypatch.setattr(urllib.request, "urlopen", _http_error_opener(500))

    assert af.main([]) == 1
    err = capsys.readouterr().err
    assert "HTTP 500" in err
    assert "review:approve" not in err


# ---------------------------------------------------------------------------
# Project scoping
#
# An org API key sees every project in the org, and the review queue does not
# report which project a row belongs to. Approving unscoped therefore applies
# this example's keep rules to whatever other project happens to share a request
# shape, with no way to report that it happened.
# ---------------------------------------------------------------------------

def test_refuses_to_run_without_a_project(monkeypatch, capsys):
    called = []

    def _opener(req, *a, **kw):
        called.append(req.full_url)
        return _FakeResponse(json.dumps({"queue": []}).encode())

    monkeypatch.setenv("STUBSMITH_ORG_API_KEY", "org-key")
    monkeypatch.delenv("STUBSMITH_PROJECT_ID", raising=False)
    monkeypatch.setattr(urllib.request, "urlopen", _opener)

    assert af.main([]) == 2
    assert called == [], "must not reach the API before a project is chosen"
    assert "--project-id" in capsys.readouterr().err


def test_project_id_from_the_environment_satisfies_the_guard(monkeypatch):
    seen = {}

    def _opener(req, *a, **kw):
        seen["url"] = req.full_url
        return _FakeResponse(json.dumps({"queue": []}).encode())

    monkeypatch.setenv("STUBSMITH_ORG_API_KEY", "org-key")
    monkeypatch.setenv("STUBSMITH_PROJECT_ID", "proj-from-env")
    monkeypatch.setattr(urllib.request, "urlopen", _opener)

    assert af.main([]) == 0
    assert "projectId=proj-from-env" in seen["url"]


def test_all_projects_is_an_explicit_opt_in(monkeypatch):
    seen = {}

    def _opener(req, *a, **kw):
        seen["url"] = req.full_url
        return _FakeResponse(json.dumps({"queue": []}).encode())

    monkeypatch.setenv("STUBSMITH_ORG_API_KEY", "org-key")
    monkeypatch.delenv("STUBSMITH_PROJECT_ID", raising=False)
    monkeypatch.setattr(urllib.request, "urlopen", _opener)

    assert af.main(["--all-projects"]) == 0
    assert "projectId" not in seen["url"]
