"""
The operations that the shared masking vectors name.

Every case in tests/vectors/{masking,masking-pipeline,masking-values,fail-closed}-vectors.json
has an ``op`` that selects one function below and an ``input`` that is that
function's only argument. The function returns a plain-JSON value, which the
generator stores as ``expected`` and tests/test_shared_vectors.py compares
against.

Another SDK implements the same operations over its own masker and runs the same
files; the op contracts are documented in each vector file's ``description``.
The Python implementation is the source of truth: if a case disagrees with
another SDK, the case is right and the SDK is not.
"""

from __future__ import annotations

import base64
import contextlib
import importlib
import json
import logging
import os
import warnings
from typing import Any, Dict, Iterator, List, Optional, Tuple

fpm = importlib.import_module("stubsmith.privacy.fingerprint")
fr = importlib.import_module("stubsmith.privacy.field_rules")
masking = importlib.import_module("stubsmith.privacy.masking")
placeholders = importlib.import_module("stubsmith.privacy.placeholders")
binary = importlib.import_module("stubsmith.privacy.binary")
from stubsmith._version import __version__
from stubsmith.privacy.pipeline import PrivacyPipeline
from stubsmith.privacy.rules_cache import RulesCache


# ---------------------------------------------------------------------------
# Long strings
# ---------------------------------------------------------------------------

def expand(x: Any) -> Any:
    """Expand the two long-string forms used to keep the files small.

    ``{"$repeat": "a", "times": 65537}`` is that text repeated, and
    ``{"$concat": [...]}`` is the expansion of each part joined together.
    Anything else is returned as it is, with its children expanded.
    """
    if isinstance(x, list):
        return [expand(e) for e in x]
    if isinstance(x, dict):
        if set(x) == {"$repeat", "times"}:
            return x["$repeat"] * x["times"]
        if set(x) == {"$concat"}:
            return "".join(expand(p) for p in x["$concat"])
        return {k: expand(v) for k, v in x.items()}
    return x


# ---------------------------------------------------------------------------
# Typed scalars (int versus float versus string matters for placeholders)
# ---------------------------------------------------------------------------

def typed(v: Any) -> Dict[str, Any]:
    if v is None:
        return {"type": "none"}
    if isinstance(v, bool):
        return {"type": "bool", "value": v}
    if isinstance(v, int):
        return {"type": "int", "text": str(v)}
    if isinstance(v, float):
        return {"type": "float", "text": repr(v)}
    if isinstance(v, str):
        return {"type": "str", "value": v}
    raise TypeError(v)


def from_typed(t: Dict[str, Any]) -> Any:
    kind = t["type"]
    if kind == "none":
        return None
    if kind == "bool":
        return t["value"]
    if kind == "int":
        return int(t["text"])
    if kind == "float":
        return float(t["text"])
    if kind == "str":
        return t["value"]
    raise ValueError(kind)


@contextlib.contextmanager
def env_salt(salt: Optional[str]) -> Iterator[None]:
    old = os.environ.get("STUBSMITH_MASK_SALT")
    if salt is None:
        os.environ.pop("STUBSMITH_MASK_SALT", None)
    else:
        os.environ["STUBSMITH_MASK_SALT"] = salt
    try:
        yield
    finally:
        if old is None:
            os.environ.pop("STUBSMITH_MASK_SALT", None)
        else:
            os.environ["STUBSMITH_MASK_SALT"] = old


@contextlib.contextmanager
def _quiet() -> Iterator[None]:
    """Keep the SDK's own warnings (invalid rule, sync 404) out of the output."""
    logger = logging.getLogger("stubsmith")
    old = logger.disabled
    logger.disabled = True
    masking._reset_masking_warnings_for_tests()
    try:
        with warnings.catch_warnings():
            # A pattern such as "[[[" is meant to be unusable; Python also warns about it.
            warnings.simplefilter("ignore")
            yield
    finally:
        logger.disabled = old
        masking._reset_masking_warnings_for_tests()


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------

def _scoped(pairs: Any) -> List[List[Any]]:
    return [[status, path] for status, path in sorted(pairs)]


def op_compile_field_rules(i: Dict[str, Any]) -> Dict[str, Any]:
    c = fr.compile_field_rules(i["field_rules"])
    return {
        "keep_body": sorted(c.keep_body),
        "keep_query": sorted(c.keep_query),
        "keep_header": sorted(c.keep_header),
        "keep_resp": sorted(c.keep_resp),
        "keep_resp_header": sorted(c.keep_resp_header),
        "keep_resp_status": _scoped(c.keep_resp_status),
        "mask_resp_status": _scoped(c.mask_resp_status),
        "keep_resp_header_status": _scoped(c.keep_resp_header_status),
        "mask_resp_header_status": _scoped(c.mask_resp_header_status),
        "body_mask_types": dict(c.body_mask_types),
        "query_mask_types": dict(c.query_mask_types),
        "resp_mask_types": dict(c.resp_mask_types),
    }


def _defaults(project_defaults: Optional[Dict[str, Any]]) -> Any:
    if project_defaults is None:
        return None
    return masking.compile_rules(project_defaults.get("field_masks"), project_defaults.get("regex_masks"))


def op_apply_field_rules(i: Dict[str, Any]) -> Dict[str, Any]:
    compiled = fr.compile_field_rules(i["field_rules"])
    with _quiet(), env_salt(i["salt"]):
        body, headers, query = fr.apply_field_rules(
            i["body"], i["headers"], i["query"], i["content_type"], compiled,
            extra_rules=_defaults(i["project_defaults"]), email_domain=i["email_domain"],
        )
    return {"body": body, "headers": headers, "query": query}


def op_apply_resp_field_rules(i: Dict[str, Any]) -> Dict[str, Any]:
    compiled = fr.compile_field_rules(i["field_rules"])
    with _quiet(), env_salt(i["salt"]):
        body, headers = fr.apply_resp_field_rules(
            i["body"], i["headers"], i["content_type"], compiled,
            extra_rules=_defaults(i["project_defaults"]), resp_status=i["resp_status"],
            email_domain=i["email_domain"],
        )
    return {"body": body, "headers": headers}


def op_compile_and_mask(i: Dict[str, Any]) -> Dict[str, Any]:
    with _quiet():
        rules = masking.compile_rules(i["field_masks"], i["regex_masks"])
        body, headers, query = masking.mask_known(i["body"], i["headers"], i["query"], i["content_type"], rules)
    return {
        "rules": {
            "unusable": rules.unusable,
            "field_masks": sorted(rules.field_masks),
            "regex_replacements": [replace for _, replace in rules.regex_masks],
        },
        "body": body,
        "headers": headers,
        "query": query,
    }


def op_mask_all(i: Dict[str, Any]) -> Dict[str, Any]:
    body, headers, query = masking.mask_all(i["body"], i["headers"], i["query"], i["content_type"])
    return {"body": body, "headers": headers, "query": query}


def op_parse_form(i: Dict[str, Any]) -> Dict[str, Any]:
    return {"result": masking.parse_form(i["body"])}


def op_binary_placeholder(i: Dict[str, Any]) -> Dict[str, Any]:
    content_type = i["content_type"]
    is_image = binary.is_image(content_type)
    out: Dict[str, Any] = {"is_image": is_image, "subtype": None, "data_base64": None}
    if is_image:
        data, subtype = binary.placeholder_for(content_type)
        out["subtype"] = subtype
        out["data_base64"] = base64.b64encode(data).decode("ascii")
    return out


class _ScriptedCache(RulesCache):
    """A rules cache whose sync endpoint answers from a list, one entry per poll."""

    def __init__(self, polls: List[Dict[str, Any]]) -> None:
        super().__init__(api_key="sk-test", backend_url="http://fake")
        self._script = list(polls)

    def _http_get(self, url: str) -> Tuple[int, Optional[Dict[str, Any]]]:
        poll = self._script.pop(0)
        return (poll["status"], poll["body"])


def op_pipeline_process(i: Dict[str, Any]) -> Dict[str, Any]:
    with _quiet(), env_salt(i["salt"]):
        cache = _ScriptedCache(i["polls"])
        for _ in i["polls"]:
            cache._poll_once()
        payload = None
        request = i["request"]
        if request is not None:
            payload = PrivacyPipeline(rules_cache=cache).process(
                request["method"], request["url"], request["req_headers"], request["req_body"],
                request["resp_status"], request["resp_headers"], request["resp_body"],
            )
            if payload is not None:
                # The version is the SDK's own; each SDK checks its own.
                assert payload["sdk_version"] == __version__
                payload = {k: v for k, v in payload.items() if k != "sdk_version"}
        defaults = cache.get_project_defaults()
        return {
            "payload": payload,
            "cache": {
                "cursor": cache.get_cursor(),
                "first_sync_done": cache._first_sync_done.is_set(),
                "project_defaults": None if defaults is None else {
                    "field_masks": sorted(defaults.field_masks),
                    "regex_count": len(defaults.regex_masks),
                    "unusable": defaults.unusable,
                },
            },
        }


def op_placeholder(i: Dict[str, Any]) -> Dict[str, Any]:
    with env_salt(i["salt"]):
        key = placeholders.get_salt()
    outputs = []
    for value in i["values"]:
        first = placeholders.generate(i["semantic_type"], from_typed(value), key, email_domain=i["email_domain"])
        second = placeholders.generate(i["semantic_type"], from_typed(value), key, email_domain=i["email_domain"])
        assert typed(first) == typed(second), f"non-deterministic output for {i['semantic_type']!r}"
        outputs.append(typed(first))
    return {"salt_key_hex": key.hex() if key is not None else None, "outputs": outputs}


def op_classify_scalar(i: Dict[str, Any]) -> Dict[str, Any]:
    return {"label": fpm.classify_scalar(json.loads(i["json"]))}


def op_extract_keypaths(i: Dict[str, Any]) -> Dict[str, Any]:
    return {"key_paths": fpm.extract_keypaths(i["body"], i["content_type"])}


def op_extract_value_types(i: Dict[str, Any]) -> Dict[str, Any]:
    return {"value_types": fpm.extract_value_types(i["body"], i["content_type"])}


OPS = {
    "compile_field_rules": op_compile_field_rules,
    "apply_field_rules": op_apply_field_rules,
    "apply_resp_field_rules": op_apply_resp_field_rules,
    "compile_and_mask": op_compile_and_mask,
    "mask_all": op_mask_all,
    "parse_form": op_parse_form,
    "binary_placeholder": op_binary_placeholder,
    "pipeline_process": op_pipeline_process,
    "placeholder": op_placeholder,
    "classify_scalar": op_classify_scalar,
    "extract_keypaths": op_extract_keypaths,
    "extract_value_types": op_extract_value_types,
}


def run_op(op: str, inp: Dict[str, Any]) -> Any:
    """Run one case's operation on its (already expanded) input."""
    return OPS[op](inp)
