# StubSmith Python SDK

Instrument **outbound** HTTP calls made by your Python application and forward
them, request **and** response, to the StubSmith ingest service for capture,
anonymization, and replay.

Supports both `requests` and `httpx` (sync and async).  Sending is
non-blocking and fire-and-forget: a background daemon thread drains a bounded
queue; any failure (network, serialization, queue overflow) is silently
discarded and never propagates to your application.

Anonymization / masking is applied **server-side** by the Go ingest service
(`ingest-go`) - do not pre-mask data client-side.

---

## Install

```bash
# with requests support
pip install "stubsmith[requests]"

# with httpx support
pip install "stubsmith[httpx]"

# both
pip install "stubsmith[requests,httpx]"
```

---

## Quickstart

```python
import stubsmith

# One-liner: instruments both requests and httpx (whichever is importable)
client = stubsmith.install(api_key="sk-your-project-key")

# Now every outbound call is captured automatically:
import requests
resp = requests.get("https://api.stripe.com/v1/charges")

import httpx
resp = httpx.get("https://api.example.com/users")
```

Or configure via environment variables and call `install()` with no arguments:

```bash
export STUBSMITH_URL="http://ingest:8081/v1/captures"
export STUBSMITH_API_KEY="sk-your-project-key"
```

```python
import stubsmith
stubsmith.install()
```

---

## Selective instrumentation

```python
from stubsmith import StubSmith

client = StubSmith(url="...", api_key="sk-...")
client.instrument_requests()   # only requests
# client.instrument_httpx()    # only httpx

# Remove patches later:
client.uninstrument()
```

---

## Configuration

| Parameter        | Default                        | Description                                                   |
|------------------|--------------------------------|---------------------------------------------------------------|
| `url`            | `$STUBSMITH_URL` / `https://ingest.stubsmith.dev/v1/captures` | Full URL of the ingest endpoint |
| `api_key`        | `$STUBSMITH_API_KEY`           | Bearer token; empty value auto-disables the client            |
| `enabled`        | `True`                         | Master switch (also auto-disabled when `api_key` is absent)   |
| `timeout`        | `5` (seconds)                  | HTTP timeout for ingest POST                                  |
| `max_body_bytes` | `65536` (64 KiB)               | Truncate captured bodies to this size before sending          |
| `sample_rate`    | `1.0`                          | Fraction of calls to forward (0.0 - 1.0)                     |
| `queue_maxsize`  | `1000`                         | Bound on the background queue; excess items are dropped       |
| `flush_timeout`  | `$STUBSMITH_FLUSH_TIMEOUT` / `1.0` (seconds) | How long process exit waits for queued captures to drain. `0` disables the wait |

### install() is idempotent and fork-safe

Calling `install()` again returns the client already installed in this process
rather than building another one, so a plugin registry or framework hook that
fires repeatedly cannot accumulate threads. Arguments are ignored on those
subsequent calls; call `close()` on the existing client first to reconfigure.

`fork()` copies only the calling thread, so a forked child would otherwise
inherit a dead sender and a queue nothing drains. The client re-arms itself in
the child, which is what makes `install()` in a pre-fork master work: `gunicorn
--preload`, uWSGI and Celery all capture in every worker. The child starts from
an empty queue, because the parent still holds anything that was pending at the
moment of the fork and will send it itself.

### An outage cannot block your application

Captures are masked on the calling thread (CPU only, no I/O) and handed to a
bounded queue with a non-blocking `put`. A daemon thread does the HTTP POST and
swallows every exception. If the ingest service is slow, unreachable or
returning errors, your request path is unaffected: the queue fills, excess
captures are dropped, and nothing propagates to your code.

Measured with the ingest host blackholed, so every POST runs to its timeout: a
median of 0.32 ms and a p95 of 0.45 ms added to an instrumented call.

The one place an outage is visible is process exit, where an `atexit` hook waits
for the queue to drain. That wait is capped at `flush_timeout`, and is abandoned
as soon as a send fails, so an unreachable endpoint costs about a second rather
than the full budget. Set `STUBSMITH_FLUSH_TIMEOUT=0` in a serverless function or
anywhere else exit latency is billed; captures still in the queue are discarded.

---

## How it works

1. `install()` / `instrument_requests()` / `instrument_httpx()` monkey-patches
   the relevant HTTP client (idempotent; safe to call multiple times).
2. Each call is timed; request headers/body and response status/headers/body
   are captured **without consuming streams** - if you opened a streaming
   response the SDK skips the body rather than interfering.
3. Captures are placed on an in-process `queue.Queue`; a daemon thread drains
   it and POSTs to `POST /v1/captures` with `Authorization: Bearer <api_key>`.
4. On process exit an `atexit` handler flushes the queue (bounded timeout).

---

## Fingerprint value discrimination

By default the SDK fingerprints each request by its body structure (key-paths),
query parameter names, and Content-Type.  Endpoints that multiplex operations via a
body field (e.g. `{"action": "login"}` vs `{"action": "delete_user"}`) therefore
produce a single fingerprint, which means a single review and a single privacy-rule
set for both variants.

Enable value discrimination on `action` in the StubSmith UI or via the API and the
SDK will automatically include that field's value in the hash:

```python
# No SDK change required - configure via the UI or API, then the SDK picks up the
# new value paths on its next rules-sync poll (default: every 60 seconds).
import stubsmith
stubsmith.install(url="...", api_key="sk-...")

import requests
requests.post("https://api.example.com/rpc", json={"action": "login", "username": "alice"})
# → fingerprint A  (action=login)

requests.post("https://api.example.com/rpc", json={"action": "delete_user", "user_id": 42})
# → fingerprint B  (action=delete_user) - separate review, separate rules
```

See [`docs/fingerprint-value-discrimination.md`](../../docs/fingerprint-value-discrimination.md)
for a full walkthrough including the hash mechanics, all three configuration methods,
and the privacy guarantees.

---

## Offline replay in tests

`stubsmith.replay()` serves recorded responses to your code's outbound HTTP
calls.  Inside the block no network call is made and the dependency does not
need to be running.

```python
import stubsmith

def test_charge_is_declined():
    with stubsmith.replay():
        with pytest.raises(CardDeclined):
            PaymentClient().charge(amount_cents=950_000, currency="USD")
```

Fetch the bundle once and commit it:

```sh
export STUBSMITH_API_KEY=<your project key>
stubsmith pull --out .stubsmith/bundle.json
```

`python -m stubsmith pull` does the same thing.  It resolves the package from
`sys.path`, so it runs a checkout without installing it, and it cannot pick up a
stale installed copy in place of the one you are working on.

From then on the test suite needs no key, no network and no `pull` step - it
reads the committed file.  Refresh it when the recording should change: the
upstream API's shape changed, you added a call the bundle does not cover, or you
approved new fingerprints.  Treat it like a lockfile or a golden file: an
occasional, reviewed, committed change.

`replay()` finds the bundle without configuration - an explicit path, then
`$STUBSMITH_BUNDLE`, then an upward search from the working directory that stops
at the first directory containing `.git` or `pyproject.toml`.  Pass a path or a
dict to be explicit:

```python
with stubsmith.replay("tests/data/bundle.json"):
    ...
```

### Matching

A request is matched on `(domain, method, path_template, fingerprint)`.  The
fingerprint covers body key-paths, query parameter names and the normalised
content-type - not values, and not the host or path, which is why the other
three parts of the key are needed.  Every body-less `GET` shares one
fingerprint.

Dynamic path segments are templated from the recording, so `/api/users/4821`
matches a stub recorded as `/api/users/{id}`.

### When nothing matches

`StubNotFound` is raised with a diff of what was sent against the closest
recording, naming the fields that differ.  It never falls through to the
network, so a test cannot silently start calling a real service.

A stub whose fingerprint has no recorded captures is reported as `degraded` by
`stubsmith pull` and raises the same error at replay time, rather than serving an
empty response.

See `examples/fixtures-testing/` for a complete worked example: a real service, a
client instrumented with the SDK, traffic captured and reviewed, and a test suite
that passes with the service stopped.

### Single-fixture helpers

`stubsmith.testing` handles individual fixture files rather than a whole bundle,
for cases where you want one recorded exchange registered against `responses`:

```sh
pip install "stubsmith[testing]"
```

```python
from stubsmith import testing

bundle = testing.load_bundle("fixtures/get_user.json")
testing.register_template(responses, bundle, base_url="http://api")
```

It also provides `assert_request_matches_fixture` and
`assert_body_schemas_match` as contract guards.  For a normal test suite
`replay()` is the simpler path - it covers every recorded endpoint at once and
needs no per-fixture registration.

---

## Masking and placeholders

Values are masked in the SDK, before a capture is uploaded: the server never
receives the originals.  A field with no `keep` rule is replaced.

By default the replacement is a constant (`"<masked>"`, `0`, `False`) matching
the original's type.

Setting `STUBSMITH_MASK_SALT` to any non-empty string switches on
format-preserving placeholders for fields carrying a semantic type hint
(`email`, `uuid`, `iso8601`, `e164`, `iban`, `url`, `decimal_amount`,
`integer_id`, `opaque_token`, `free_text`).  The replacement then has the same
*shape* as the original - a parseable timestamp, an RFC 4122 UUID, an IBAN with a
correct mod-97 checksum - so code that parses or validates these values still
works against a recording.  The same salt and value always produce the same
placeholder, which preserves uniqueness and cross-field references. The salt
never leaves the process.

Two types are never format-preserved, regardless of salt: `currency_code` and
`country_code`.  Booleans are refused for the same reason.  Their domains are
small enough that a keyed hash could be reversed with a lookup table.  Use
`action: keep` for those fields instead - they are rarely sensitive.

---

## Changelog

### 0.2.0

**Captures are no longer lost in forked workers.** Threads do not survive
`fork()`, so a child inherited a dead sender and a queue nothing would drain:
under `gunicorn --preload`, uWSGI or Celery, where `install()` runs in a master
and workers are forked, every capture in every worker was enqueued and silently
discarded. The client now re-arms itself in the child.

**`install()` is idempotent.** It returns the client already installed in this
process instead of building another one. Previously each call added a sender
thread, a rules-cache poller, an `atexit` hook and a 60-second backend poll,
and left every client but the most recent inert while still polling.

**Key paths are reported from every array element, not just the first.** For an
array whose first entry is a scalar or `null`, the shape of the objects after it
was never reported, so those fields could not be given a keep rule and stayed
masked with no way to discover why. **This changes the fingerprint** of any
request or response containing arrays whose elements differ in shape: those
endpoints reappear in the review queue as novel and need approving once more.
Approvals for every other endpoint are unaffected.

**Process exit no longer waits on an unreachable ingest host.** The at-exit
flush had the same five-second budget as an explicit `flush()`, so a short-lived
script or serverless invocation paid it in full whenever Stubsmith was
unreachable. The budget is now one second, configurable with
`flush_timeout` or `$STUBSMITH_FLUSH_TIMEOUT`, and abandoned as soon as a send
fails.

---

## Development / tests

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[test]'
python -m pytest -q
```
