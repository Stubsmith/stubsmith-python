"""
StubSmith Python SDK.

Quickstart - capture instrumentation::

    import stubsmith

    client = stubsmith.install(api_key="sk-your-project-key")

``install`` instruments both ``requests`` and ``httpx`` (whichever is
importable) so every outbound HTTP call is captured, privacy-processed, and
forwarded to the StubSmith ingest service in the background.  Sending is
non-blocking and fire-and-forget; any failure is silently swallowed.

Privacy / masking
-----------------
Anonymisation is applied **client-side at the edge** - inside this SDK
process - before any data is transmitted.  Raw field values never cross the
process boundary.

The pipeline:

1. Replaces ``image/*`` bodies with canonical 1×1 placeholders (pixel data
   and EXIF metadata can carry PII).
2. Fingerprints the request body key-paths, query parameter names, and
   content-type to produce a stable structural identity.
3. Looks up per-fingerprint field rules synced from the backend
   (``GET /v1/sdk/sync``).  Unknown fingerprints are masked entirely
   (fail-closed) and flagged ``novel=True``.
4. Applies field rules (keep/mask decisions) for known fingerprints, plus
   a belt-and-suspenders regex pass on remaining string values.

Quickstart - fetch fixtures for testing::

    import stubsmith

    fxs = stubsmith.fixtures("POST /v1/charges/{id}", distinct="status")
    for fx in fxs:
        data = fx.response.json()   # parsed response body
        print(fx.status, data)

    # Full envelope with request_type metadata (path_pattern, is_dynamic):
    bundle = stubsmith.fixtures_bundle("GET /v1/users/{id}", distinct="status")
    print(bundle.request_type)   # {"id": ..., "method": "GET", "path_pattern": ..., "is_dynamic": True}
    fx_200 = bundle.by_status(200)

Set ``STUBSMITH_API_URL`` and ``STUBSMITH_API_KEY`` before calling
:func:`fixtures` or :func:`fixtures_bundle`, or pass them as keyword arguments.

Quickstart - use fixtures as test stubs::

    from stubsmith import testing
    import responses

    @responses.activate
    def test_get_user():
        bundle = testing.load_bundle("fixtures/get_user.json")
        testing.register_template(responses, bundle, base_url="http://api")
        result = client.get_user(99)
        assert result["id"] == 99

:mod:`stubsmith.testing` is not imported here to keep ``import stubsmith``
free of the optional ``responses`` dependency.
"""

from .client import StubSmith, _DEFAULT_URL as DEFAULT_INGEST_URL, _DEFAULT_BACKEND_URL as DEFAULT_API_URL
from .fixtures import Fixture, FixtureBundle, fixtures, fixtures_bundle
from .instrument import install, is_installed
from .privacy.pipeline import PrivacyPipeline
from .replay import ReplayContext, StubNotFound, replay

__all__ = [
    "StubSmith",
    "DEFAULT_INGEST_URL",
    "DEFAULT_API_URL",
    "Fixture",
    "FixtureBundle",
    "fixtures",
    "fixtures_bundle",
    "install",
    "is_installed",
    "PrivacyPipeline",
    "ReplayContext",
    "StubNotFound",
    "replay",
]

from ._version import __version__  # noqa: F401 - re-exported for `stubsmith.__version__`
