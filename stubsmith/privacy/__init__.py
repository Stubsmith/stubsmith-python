"""
StubSmith privacy package - edge-agent masking, fingerprinting, templating,
image handling, and the PrivacyPipeline orchestrator.

Masking is applied entirely client-side at the edge: raw values never cross
the process boundary.  The ``PrivacyPipeline`` orchestrates the full flow
(image replacement → fingerprinting → path templating → cache lookup →
masking → payload assembly) for every captured exchange.

Public names re-exported from sub-modules
------------------------------------------
fingerprint
    :func:`~stubsmith.privacy.fingerprint.extract_keypaths`,
    :func:`~stubsmith.privacy.fingerprint.fingerprint`,
    :func:`~stubsmith.privacy.fingerprint.resp_fingerprint`

templating
    :class:`~stubsmith.privacy.templating.CuratedTemplate`,
    :func:`~stubsmith.privacy.templating.load_curated_templates`,
    :func:`~stubsmith.privacy.templating.template_path`

masking
    :class:`~stubsmith.privacy.masking.CompiledRules`,
    :func:`~stubsmith.privacy.masking.compile_rules`,
    :func:`~stubsmith.privacy.masking.mask_known`,
    :func:`~stubsmith.privacy.masking.mask_all`,
    :data:`~stubsmith.privacy.masking.HEADER_ALLOWLIST`

field_rules
    :class:`~stubsmith.privacy.field_rules.CompiledFieldRules`,
    :func:`~stubsmith.privacy.field_rules.compile_field_rules`,
    :func:`~stubsmith.privacy.field_rules.apply_field_rules`,
    :func:`~stubsmith.privacy.field_rules.apply_resp_field_rules`

binary
    :data:`~stubsmith.privacy.binary.PNG_1X1`,
    :data:`~stubsmith.privacy.binary.GIF_1X1`,
    :data:`~stubsmith.privacy.binary.JPEG_1X1`,
    :func:`~stubsmith.privacy.binary.is_image`,
    :func:`~stubsmith.privacy.binary.placeholder_for`

rules_cache
    :class:`~stubsmith.privacy.rules_cache.RulesCache`

pipeline
    :class:`~stubsmith.privacy.pipeline.PrivacyPipeline`
"""

from .fingerprint import extract_keypaths, fingerprint, resp_fingerprint
from .templating import CuratedTemplate, load_curated_templates, template_path
from .masking import (
    CompiledRules,
    HEADER_ALLOWLIST,
    compile_rules,
    mask_all,
    mask_known,
)
from .field_rules import (
    CompiledFieldRules,
    compile_field_rules,
    apply_field_rules,
    apply_resp_field_rules,
)
from .binary import GIF_1X1, JPEG_1X1, PNG_1X1, is_image, placeholder_for
from .rules_cache import RulesCache
from .pipeline import PrivacyPipeline

__all__ = [
    # fingerprint
    "extract_keypaths",
    "fingerprint",
    "resp_fingerprint",
    # templating
    "CuratedTemplate",
    "load_curated_templates",
    "template_path",
    # masking
    "CompiledRules",
    "HEADER_ALLOWLIST",
    "compile_rules",
    "mask_all",
    "mask_known",
    # field_rules
    "CompiledFieldRules",
    "compile_field_rules",
    "apply_field_rules",
    "apply_resp_field_rules",
    # binary
    "GIF_1X1",
    "JPEG_1X1",
    "PNG_1X1",
    "is_image",
    "placeholder_for",
    # rules_cache
    "RulesCache",
    # pipeline
    "PrivacyPipeline",
]
