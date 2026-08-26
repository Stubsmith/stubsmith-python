"""
Golden-vector tests: verify the Python field-rules masker matches every
vector in tests/vectors/field-rules-vectors.json.

The vectors are the cross-language contract for the masking spec: any other
SDK, and the ingest service, must produce identical output for them. They live
inside this repo so the suite is self-contained - before the SDK was split out
of the monorepo this file reached back to a shared fixtures/ directory at the
repo root, which no longer exists here.

If a vector exposes a semantic mismatch, the vectors are wrong - the Python
implementation is the source of truth and must not be modified.
"""

from __future__ import annotations

import json
import urllib.parse
from pathlib import Path
from typing import Any, Dict, Tuple

import pytest

from stubsmith.privacy.field_rules import (
    apply_field_rules,
    apply_resp_field_rules,
    compile_field_rules,
)

# ---------------------------------------------------------------------------
# Load fixture file
# ---------------------------------------------------------------------------

_FIXTURES_PATH = Path(__file__).parent / "vectors" / "field-rules-vectors.json"

def _load_vectors():
    with open(_FIXTURES_PATH.resolve(), encoding="utf-8") as f:
        data = json.load(f)
    return data["vectors"]


_VECTORS = _load_vectors()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalise_ct(ct: str) -> str:
    """Mirror field_rules._normalise_ct."""
    return (ct or "").lower().split(";")[0].strip()


def _parse_params(qs: str) -> Dict[str, list]:
    """Parse a query / form-encoded string into {name: [values]} dict."""
    if not qs:
        return {}
    return dict(urllib.parse.parse_qs(qs, keep_blank_values=True))


def _assert_body(
    actual: str,
    expected: Any,
    ct: str,
    label: str,
) -> None:
    """Compare a masked body against the expected fixture value.

    - application/json (non-empty): parse both sides and compare structures.
    - application/x-www-form-urlencoded: parse both sides as param maps.
    - Otherwise: compare as plain strings.
    """
    norm = _normalise_ct(ct)
    if norm == "application/json" and actual != "":
        assert json.loads(actual) == expected, f"{label}: JSON body mismatch"
    elif norm == "application/x-www-form-urlencoded":
        assert _parse_params(actual) == expected, f"{label}: form body mismatch"
    else:
        assert actual == expected, f"{label}: body string mismatch"

# ---------------------------------------------------------------------------
# Parametrised vector tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("vector", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_field_rules_vector(vector: Dict[str, Any]) -> None:
    inp = vector["input"]
    exp = vector["expected"]

    compiled = compile_field_rules(vector["field_rules"])

    # --- Request side ---
    masked_body, masked_headers, masked_query = apply_field_rules(
        inp["body"],
        inp["headers"],
        inp["query"],
        inp["content_type"],
        compiled,
    )

    _assert_body(masked_body, exp["masked_body"], inp["content_type"], f'{vector["name"]} req_body')
    assert masked_headers == exp["masked_headers"], f'{vector["name"]}: req headers mismatch'

    actual_query = _parse_params(masked_query)
    assert actual_query == exp["masked_query"], f'{vector["name"]}: masked query mismatch'

    # --- Response side ---
    # resp_status is optional in the vector; when absent, None is passed so that
    # the call behaves identically to the pre-status-scoped API (backward-compat).
    resp_status = vector.get("resp_status", None)
    masked_resp_body, masked_resp_headers = apply_resp_field_rules(
        inp["resp_body"],
        inp["resp_headers"],
        inp["resp_content_type"],
        compiled,
        resp_status=resp_status,
    )

    _assert_body(
        masked_resp_body,
        exp["masked_resp_body"],
        inp["resp_content_type"],
        f'{vector["name"]} resp_body',
    )
    assert masked_resp_headers == exp["masked_resp_headers"], \
        f'{vector["name"]}: resp headers mismatch'
