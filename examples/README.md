# Examples

## fixtures-testing (Python) - hermetic

`examples/fixtures-testing/` shows the full Stubsmith fixture workflow:

- `.stubsmith/bundle.json` - committed replay bundle produced by `stubsmith pull`
- `tests/` - hermetic offline tests using `stubsmith.replay()`; pass with no API key

```sh
# Install the package with test extras from the repo root:
pip install -e '.[test]'

# Run just the example tests:
pytest examples/fixtures-testing/tests/ -q

# Or run the full suite (includes the example):
pytest -q
```

Live tests (those marked `@pytest.mark.live`) are skipped automatically unless
`STUBSMITH_API_KEY` is set.  See `examples/fixtures-testing/README.md` for the
full walkthrough.

## python/replay_example.py - requires requests

A small script that shows how to replay a captured fixture.  Requires `requests`:

```sh
pip install requests
python3 examples/python/replay_example.py
```

## python/test_charge_fixtures.py - requires live API key

Demonstrates calling `stubsmith.fixtures()` directly.  Calls the live backend at
module import time and **fails at collection** without `STUBSMITH_API_KEY` set.
It is intentionally excluded from the default `testpaths` in `pyproject.toml`.

## node/capture-example.js

Node.js capture example.

```sh
node examples/node/capture-example.js
```
