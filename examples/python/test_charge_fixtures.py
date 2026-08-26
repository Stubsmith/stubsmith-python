#!/usr/bin/env python3
"""
Example: parametrize tests over every recorded charge-response fixture.

Required environment variables
-------------------------------
STUBSMITH_API_URL   Base URL of the StubSmith backend  (e.g. http://localhost:3000)
STUBSMITH_API_KEY   Project API key issued by StubSmith

Important
---------
The ``stubsmith.fixtures()`` call at module level is executed by pytest during
collection, so the StubSmith API must be reachable at that point.  In CI, set
the environment variables and ensure the StubSmith service is running before
pytest discovers this file.

Usage
-----
    STUBSMITH_API_URL=http://localhost:3000 \
    STUBSMITH_API_KEY=sk-your-key \
    pytest examples/python/test_charge_fixtures.py -v

The ``distinct="status"`` argument returns at most one fixture per HTTP status
code (newest-first), giving you one representative example per response variant
without duplicating identical cases.
"""

import pytest
import stubsmith

# Fetch one fixture per distinct status code recorded for POST /v1/charges/{id}.
# Replace the pattern with the path_pattern configured in your StubSmith project.
FIXTURES = stubsmith.fixtures("POST /v1/charges/{id}", distinct="status")


@pytest.mark.parametrize("fx", FIXTURES, ids=lambda f: str(f.status))
def test_handles_every_recorded_charge_response(fx):
    """
    This test is called once per fixture - once per distinct HTTP status code.

    ``fx`` is a :class:`stubsmith.Fixture` with:
      - fx.status          - HTTP status code (int)
      - fx.method          - "POST"
      - fx.path            - concrete path, e.g. "/v1/charges/ch_abc123"
      - fx.response.body   - raw response body string (or None)
      - fx.response.json() - parsed response body (raises ValueError if not JSON)
      - fx.request.body    - raw request body string (or None)
      - fx.request.headers - dict of request headers
    """
    # Replace `my_app.handle_charge_response` with your actual application code.
    # The fixture gives you a real response body recorded from production traffic.
    body = fx.response.json()  # raises ValueError if body is not valid JSON

    # Example assertions - adapt to your application's contract:
    if fx.status == 200 or fx.status == 201:
        assert "id" in body, f"Expected 'id' in successful charge response, got: {body}"
    elif fx.status == 402:
        assert "error" in body or "code" in body, (
            f"Expected error details in 402 response, got: {body}"
        )
    elif fx.status >= 400:
        # Any 4xx/5xx should include some error indication
        assert body is not None, f"Expected non-empty body for status {fx.status}"
