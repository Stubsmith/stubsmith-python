# StubSmith Python SDK

Instrument **outbound** HTTP calls made by your Python application and forward
them, request **and** response, to the StubSmith ingest service for capture,
anonymization, and replay.

Supports both `requests` and `httpx` (sync and async).  Sending is
non-blocking and fire-and-forget: a background daemon thread drains a bounded
queue; any failure (network, serialization, queue overflow) is silently
discarded and never propagates to your application.

Masking is applied **in this SDK**, in your own process, before any capture
leaves it: the ingest service receives masked bodies plus structural names
(field paths, header names, query-parameter names), never original values.  A
field with no explicit `keep` rule is masked, so a field the rules do not
mention cannot leak.  The server runs pattern backstops on what arrives, but it
is a second line of defence, not the masking layer.

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
| `backend_url`    | `$STUBSMITH_BACKEND_URL` / `https://app.stubsmith.dev/api` | API the masking rules are fetched from. A **second host**, not the ingest host |
| `rules_poll_interval` | `60.0` (seconds)         | How often the rules cache re-polls the API for rule changes                    |
| `wait_for_rules` | `0` (do not wait)              | Seconds `install()` blocks for the first rules sync. Raise it for short scripts (see below) |
| `debug`          | `$STUBSMITH_DEBUG`             | Log send and sync failures to stderr. Does not change the fire-and-forget contract |

**An explicit argument always wins over the environment variable**, which is
read only when the argument is omitted, and only once, when the client is
built. `install(api_key="sk-from-arg")` authenticates with `sk-from-arg` even if
`$STUBSMITH_API_KEY` is set to something else; nothing re-reads the environment
later. That matters when the key comes from a database row or a settings table
rather than the process environment.

Every parameter above is accepted by `stubsmith.install()`. All of them except
`wait_for_rules`, which is a property of installation rather than of the client,
are also accepted by `StubSmith()`.

### What gets patched

`install()` patches exactly four things, and only those:

| Patched | Not patched |
|---------|-------------|
| `requests.sessions.Session.request` | `requests.request`, `requests.get`, `requests.post`, ... |
| `requests.sessions.Session.send` | `urllib`, `urllib3`, `http.client` |
| `httpx.Client.send` | `aiohttp` |
| `httpx.AsyncClient.send` | anything below the adapter (sockets, retries) |

The module-level `requests` helpers need no patch of their own: every one of
them builds a `Session` and calls `Session.request`. Patching `Session.send` as
well covers the other entry point, a caller that builds its own
`PreparedRequest` and sends it, which some client libraries do.

Both patch points route through each other, and `send()` re-enters itself once
per redirect hop, so capture happens in the **outermost patched frame only**:
one call produces one capture, and a redirect chain produces one capture
describing the request you made rather than the hop it landed on. The guard is
per-thread, so concurrent calls do not mask each other.

Nothing below the `requests` adapter is patched. urllib3 retries and socket
level behaviour are invisible to the SDK, and traffic sent through `urllib`,
`http.client` or `aiohttp` is not captured at all.

Because the patch lands on `Session.request` and not on the helpers, the
obvious hand-rolled health check is wrong:

```python
# WRONG - reports a working install as broken. requests.request is never patched.
assert requests.request.__module__ != "requests.api"

# Right
assert stubsmith.is_installed()
```

`stubsmith.is_installed()` returns `True` only while a live client is installed
in this process: `False` before `install()`, `False` after `close()`, and
`False` in a forked child whose client could not be revived.

### Network egress and background threads

`install()` talks to **two** hosts, which matters if you allow-list egress:

| Host | Direction | Purpose |
|------|-----------|---------|
| `ingest.stubsmith.dev` | outbound POST | masked captures (`POST /v1/captures`) |
| `app.stubsmith.dev` | outbound GET | masking rules (`GET /v1/sdk/sync`), polled every `rules_poll_interval` seconds (default 60) |

Both are overridable (`url` and `backend_url`) for a project pointed at a
different environment.

It also starts exactly two daemon threads, named so they are identifiable in a
thread dump: `stubsmith-sender` (drains the capture queue) and
`stubsmith-rules-cache` (polls for rules).

**An unreachable rules API degrades open, not closed.** A failed sync is
logged at debug level and leaves the last known-good rules in place; it never
raises and never stops capture. Because masking is fail-closed, a client that
has never reached the API masks everything and still delivers captures: you get
`novel=true` and no cleartext, not silence. A rejected key (`401`) behaves the
same way.

### install() is idempotent and fork-safe

Calling `install()` again returns the client already installed in this process
rather than building another one, so a plugin registry or framework hook that
fires repeatedly cannot accumulate threads. Arguments are ignored on those
subsequent calls; call `close()` on the existing client first to reconfigure.

`fork()` copies only the calling thread, so a forked child would otherwise
inherit a dead sender and a queue nothing drains. The client re-arms itself in
the child, which is what makes `install()` in a pre-fork master work: `gunicorn
--preload`, uWSGI, Celery's default pool and Odoo's worker model all capture in
every worker. The child starts from an empty queue, because the parent still
holds anything that was pending at the moment of the fork and will send it
itself.

Both properties matter together in an embedded plugin. Odoo, for example, calls
a module's `post_load` once in the pre-fork master and `_register_hook` on every
registry load: the first needs fork safety to capture anything at all under
`workers > 0`, the second needs idempotence not to leak a pair of threads per
reload. Either call site works, and calling from both is harmless. On a version
before 0.2.0 neither holds, so install per worker instead and guard on the pid.

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

1. `install()` / `instrument_requests()` / `instrument_httpx()` patches
   `requests.sessions.Session.request` and `.send`, plus `httpx.Client.send` /
   `httpx.AsyncClient.send` (idempotent; repeated calls are a no-op, see
   [What gets patched](#what-gets-patched)).
2. Each call is timed; request headers/body and response status/headers/body
   are captured **without consuming streams** - if you opened a streaming
   response the SDK skips the body rather than interfering.
3. Captures are placed on an in-process `queue.Queue`; a daemon thread drains
   it and POSTs to `POST /v1/captures` with `Authorization: Bearer <api_key>`.
4. On process exit an `atexit` handler flushes the queue (bounded timeout).

---

## What a capture looks like on the wire

This is the artifact to hand a security reviewer. Given this call, against an
endpoint whose fingerprint has not been approved yet (the worst case for
disclosure, since no `keep` rule exists):

```python
requests.get(
    "https://api.example.com/v1/orders/1042?limit=50&include=customer",
    headers={"X-Request-Id": "abc-123"},
)
```

returning this response body:

```json
{
  "id": "4c1f2a80-2f1e-4a2f-9f7a-2b1c6f0d9e11",
  "customer": {"name": "Alice Martin", "email": "alice@example.com"},
  "iban": "NL91ABNA0417164300",
  "amount": "149.95",
  "paid": true
}
```

the SDK sends exactly this to `POST https://ingest.stubsmith.dev/v1/captures`,
with `Authorization: Bearer <your project key>` and
`User-Agent: stubsmith-sdk/0.3.0`:

```json
{
  "sdk_version": "0.3.0",
  "sdk_masked": true,
  "sdk_rule_version": "0",
  "domain": "api.example.com",
  "path_template": "/v1/orders/{id}",
  "path": "/v1/orders/{id}?limit=%3Cmasked%3E&include=%3Cmasked%3E",
  "method": "GET",
  "status": 200,
  "req_fingerprint": "0ac4da02636b9927",
  "resp_fingerprint": "2004bc1bf2471fe533f",
  "key_paths": [],
  "resp_key_paths": [
    "id", "customer", "customer.name", "customer.email",
    "iban", "amount", "paid"
  ],
  "req_header_names": ["accept", "accept-encoding", "connection", "user-agent", "x-request-id"],
  "resp_header_names": ["content-type", "date", "server"],
  "query_names": ["limit", "include"],
  "headers": {
    "User-Agent": "python-requests/2.34.2",
    "Accept-Encoding": "gzip, deflate, zstd",
    "Accept": "*/*",
    "Connection": "<masked>",
    "X-Request-Id": "<masked>"
  },
  "req_body": "<masked>",
  "resp_headers": {
    "Server": "<masked>",
    "Date": "<masked>",
    "content-type": "application/json"
  },
  "resp_body": "{\"id\": \"<masked>\", \"customer\": {\"name\": \"<masked>\", \"email\": \"<masked>\"}, \"iban\": \"<masked>\", \"amount\": \"<masked>\", \"paid\": false}",
  "novel": true,
  "resp_value_types": {
    "id": "uuid",
    "customer.name": "free_text",
    "customer.email": "email",
    "iban": "iban",
    "amount": "decimal_amount"
  },
  "source": "python-requests",
  "duration": 2
}
```

Reading it:

- **No original value appears anywhere**, including in the URL: the path is
  templated (`1042` becomes `{id}`) and query *values* are masked while their
  names survive. `paid: true` masked to `false` because a boolean's masked form
  is `false`, not because the value was read.
- **`key_paths` and `resp_key_paths` are names only.** They are what you review
  in the Request Types editor, and what a `field_rules` entry addresses.
- **`novel: true` and `sdk_rule_version: "0"`** say no approved rules were in
  effect, which is why everything is masked. Once you approve the fingerprint
  with `keep` rules, the kept scalars appear here verbatim - that is the point
  of the review step, and the only way a real value ever reaches Stubsmith.
- **`resp_value_types` reports recognizable formats, not content.** `"iban"`
  means the string parsed as an IBAN. Character composition is never inspected,
  so no label is derived from the value beyond its format.
- **`sdk_masked: true`** is what the ingest service requires; a payload without
  it is rejected with `400 sdk_required`, so an unmasked body cannot be posted
  through this endpoint at all.

To see this for your own traffic before pointing the SDK at Stubsmith, run
`python -m http.server`-style ingest of your own: set
`url="http://127.0.0.1:PORT/v1/captures"` and log what arrives.

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

See the [fingerprinting documentation](https://docs.stubsmith.dev/) for the
hash mechanics, all three configuration methods, and the privacy guarantees.

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

### Every recorded response, not just the newest

`replay()` serves **one** response per request shape: the newest recording of
the status that occurred most often. That leaves everything else in the
recording unexercised, which is usually where the bugs are. Stubsmith keeps a
rolling window of recent samples for each distinct response a shape returned, so
the 429 and the 500 your API really produced are sitting there unused.

`replay_all()` runs the block once per recorded response:

```python
def test_survives_every_recorded_response():
    for attempt in stubsmith.replay_all():
        with attempt:
            result = connector.sync_orders()
        assert result.ok or result.retried
```

You never name an endpoint. Which ones a pass touches is discovered by running
your code, so this works for a connector whose call sequence you would rather
not spell out, and for one whose sequence *changes* between passes because it
branches on the response it got: an endpoint first reached on pass four still
gets looped from its own first recording.

Pass one serves exactly what `replay()` serves, so a test that passes under
`replay()` still passes on the first pass. Iteration stops when every shape
that was actually touched has served its last recording. A shape with a shorter
window keeps serving its final recording rather than raising, so one endpoint's
thin history never truncates the loop for everything else.

What this asks of the test body is real: it runs against a 200 on one pass and
possibly a 500 on the next, so the assertions have to hold across the whole
recorded range. That is the point, and it is also why `replay()` remains the
right tool for a test written against one known response.

To pin a single response instead, pass `select`:

```python
def test_backs_off_when_rate_limited():
    with stubsmith.replay(select=stubsmith.by_status(429)):
        with pytest.raises(RateLimited):
            connector.sync_orders()
```

`by_status` raises `StubNotFound` when no recording of that status exists,
rather than quietly serving a different one - a rate-limit test that silently
ran against a 200 would pass while testing nothing. `select` receives every
recording as a list and returns one, so any other rule is a lambda away.

Either way, `served()` reports what actually ran, so a test can assert coverage
instead of assuming it:

```python
with stubsmith.replay() as r:
    connector.sync_orders()
assert {s.status for s in r.served()} == {200}
```

Each entry carries `endpoint`, `status`, `capture_id`, `captured_at`, and
`index`/`total`/`exhausted` describing its place in the shape's window.

#### Getting the window into the bundle

A default bundle holds one recording per response, so `replay_all()` would give
one pass per status. Ask for the window explicitly:

```sh
stubsmith pull --endpoint "GET /admin/orders" --samples all \
  --out tests/bundles/admin-orders.json
```

`--samples` above 1 requires `--endpoint`: the full window for a whole project
is not served, and per-endpoint files are what you want anyway, since a
project-wide bundle is capped at 2000 request shapes and silently drops the
rest.

Or fetch at collection time, with no file involved:

```python
BUNDLE = stubsmith.fetch_bundle("GET /admin/orders", samples="all")

def test_every_recorded_response():
    for attempt in stubsmith.replay_all(BUNDLE):
        with attempt:
            connector.list_orders()
```

Fetch once at module level, not per test - it is a blocking HTTP call. It needs
a live key wherever the tests run, and live recordings roll as the window rolls,
so a failure you see today may not reproduce next week. Fetch live while
iterating locally; commit a pulled bundle for CI.

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

The salt only affects fields that carry a semantic type hint, and those hints
come from an approved fingerprint's `field_rules`. Before a fingerprint has been
reviewed the capture reports `sdk_rule_version: 0`, no field has a type hint,
and every masked value is the constant form no matter what the salt is set to.
Setting a salt and seeing `"<masked>"` therefore means "not approved yet", not
"salt ignored".

Two types are never format-preserved, regardless of salt: `currency_code` and
`country_code`.  Booleans are refused for the same reason.  Their domains are
small enough that a keyed hash could be reversed with a lookup table.  Use
`action: keep` for those fields instead - they are rarely sensitive.

---

## Changelog

### 0.3.0

**New: `replay_all()`, for looping every recorded response.** `replay()` serves
one response per request shape, the newest recording of the most frequent
status, which leaves the rest of the rolling sample window unexercised: the 429
and the 500 the API really returned are recorded and never tested against.
`replay_all()` runs a block once per recording.

No endpoint is named: which shapes a pass touches is discovered by running your
code, so a connector whose call sequence changes between passes, because it
branches on the response it got, still works. An endpoint first reached on a
later pass is looped from its own first recording rather than starting partway
through. Pass one serves exactly what `replay()` serves, so moving an existing
test to `replay_all()` does not change what the first pass asserts.

**New: `replay(select=...)` and `by_status()`.** Pin a single recorded response,
for a test written against one known outcome. `by_status()` raises
`StubNotFound` when no recording of that status exists rather than serving a
different one, so a rate-limit test cannot silently pass against a 200.

**New: `ReplayContext.served()`.** Reports which recordings actually ran, with
the endpoint, status, `capture_id`, `captured_at` and position in the shape's
window, so a test can assert its coverage instead of assuming it.

**New: `fetch_bundle()` and `stubsmith pull --samples`.** A bundle carries one
recording per response by default, so `--samples N` or `--samples all` is what
puts the window into one; it requires `--endpoint`, since the full window for a
whole project is not served. `fetch_bundle()` fetches without going through a
file, for a suite that wants current recordings at collection time. Previously
the only route to that was importing `stubsmith.cli._fetch_bundle`, which is
private and carried no compatibility promise.

Nothing in this release changes existing behaviour: `replay()` with no
arguments serves the same response it did in 0.2.0, and a bundle pulled without
`--samples` is byte-identical.

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

**A prepared request sent with `Session.send()` is now captured.** Only
`Session.request` was patched, so a caller that built its own `PreparedRequest`
was silently invisible: no error, no fingerprint. Both entry points are patched
now, with capture in the outermost frame only, so a single call still produces
exactly one capture and a redirect chain still produces one.

**`install()` accepts `flush_timeout`.** It was settable only by constructing
`StubSmith` directly or through `$STUBSMITH_FLUSH_TIMEOUT`, which a process that
does not control its own environment could not use.

**New: `stubsmith.is_installed()`.** A supported way to assert that capture is
armed, instead of guessing at which attribute the patch replaced.

**Documented: what gets patched, both egress hosts, both thread names, argument
versus environment precedence, and an annotated capture payload.** The README
previously said masking was applied server-side, which is the opposite of what
the SDK does.

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
