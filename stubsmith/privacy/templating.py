"""
URL path templating - heuristic segment normalisation and curated template matching.

Heuristic rules (applied per path segment)
-------------------------------------------
- A segment that is entirely numeric (``str.isdigit()``) → ``{id}``
- A segment that matches the UUID pattern (8-4-4-4-12 hex) → ``{id}``
- A segment of 16 or more hex characters → ``{id}``
- Everything else is kept literal.

Curated templates
-----------------
Templates are fetched from the cloud (in a later work package) and passed into
:func:`load_curated_templates`.  Matching is deterministic:

1. Only templates with the **same segment count** as the concrete path are
   considered.
2. A template segment matches the corresponding concrete segment when it is
   equal OR is a wildcard segment - any segment of the form ``{name}``
   (i.e. surrounded by braces), such as ``{id}``, ``{userId}``, ``{p1}``.
3. Among matching templates, the one with the **most literal segments** wins;
   ties are broken lexicographically (ascending).  This ordering is
   precomputed by :func:`load_curated_templates` so the hot-path is a simple
   first-match scan.
4. Fallback: the heuristic is applied when no curated template matches.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Sequence


# ---------------------------------------------------------------------------
# Patterns for heuristic ID detection
# ---------------------------------------------------------------------------

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_HEX_RE = re.compile(r"^[0-9a-f]+$", re.IGNORECASE)
# Matches any named wildcard segment such as {id}, {userId}, {p1}.
# Note: {} (empty braces) is intentionally NOT matched - it is never a valid
# wildcard and would be a malformed template segment.
_WILDCARD_SEG_RE = re.compile(r"^\{[^{}]+\}$")


# ---------------------------------------------------------------------------
# Public types and functions
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CuratedTemplate:
    """A curated path template with its literal-segment count precomputed."""

    template: str
    literal_count: int


def load_curated_templates(templates: Sequence[str]) -> List[CuratedTemplate]:
    """Parse raw template strings and return them sorted for hot-path matching.

    Parameters
    ----------
    templates:
        Iterable of path template strings, e.g. ``["/users/{id}/orders"]``.

    Returns
    -------
    list[CuratedTemplate]
        Sorted: more literal segments first; lexicographic tie-break on the
        template string itself (ascending).
    """
    curated: List[CuratedTemplate] = []
    for t in templates:
        segs = [s for s in t.split("/") if s]
        literal_count = sum(1 for s in segs if not _WILDCARD_SEG_RE.match(s))
        curated.append(CuratedTemplate(template=t, literal_count=literal_count))
    return sorted(curated, key=lambda c: (-c.literal_count, c.template))


def template_path(path: str, curated: Sequence[CuratedTemplate]) -> str:
    """Return the templated form of *path*.

    The curated list is tried first (segment-count exact match, first match
    wins).  Falls back to the heuristic when no curated template applies.

    Parameters
    ----------
    path:
        Concrete URL path, e.g. ``/users/123/orders``.
    curated:
        Pre-sorted curated template list from :func:`load_curated_templates`.

    Returns
    -------
    str
        Templated path, e.g. ``/users/{id}/orders``.
    """
    path_segs = [s for s in path.split("/") if s]
    for ct in curated:
        t_segs = [s for s in ct.template.split("/") if s]
        if len(t_segs) != len(path_segs):
            continue
        if all(ts == ps or _WILDCARD_SEG_RE.match(ts) for ts, ps in zip(t_segs, path_segs)):
            return ct.template
    return _heuristic_template(path)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_id_segment(seg: str) -> bool:
    """Return True when *seg* looks like a dynamic ID component."""
    if seg.isdigit():
        return True
    if _UUID_RE.match(seg):
        return True
    if len(seg) >= 16 and _HEX_RE.match(seg):
        return True
    return False


def _heuristic_template(path: str) -> str:
    """Replace ID-looking path segments with ``{id}`` placeholders."""
    parts = path.split("/")
    return "/".join("{id}" if p and _is_id_segment(p) else p for p in parts)
