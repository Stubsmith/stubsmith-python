# fixtures-testing example

This example shows the full Stubsmith loop: a real shop service, a client
instrumented with the SDK, traffic captured and reviewed, and a bundle pulled
for offline test replay.

```
shop_service/server.py     real HTTP service (eight routes, real validation)
    |
    v  (generate_traffic.py calls ShopClient with the SDK patched in)
SDK captures               request types fingerprinted, bodies masked at the edge
    |
    v  (review fingerprints in the Stubsmith UI; add keep rules for non-sensitive paths)
stubsmith pull             fetch the approved bundle
    |
    v
.stubsmith/bundle.json     committed replay bundle - one file, all routes
    |
    v  (stubsmith.replay() loads it and patches requests.Session.send)
pytest test suite          passes with the shop service DOWN - no network call made
```

`shopclient/` is the code under test.  It has no knowledge of Stubsmith; it is
ordinary `requests`-based code.  Stubsmith captures **outbound** calls, so the
instrumented side is the client - `generate_traffic.py` plus `shopclient/`,
standing in for your application.  `shop_service/` is the dependency being
recorded and is never instrumented.  `stubsmith.replay()` is the SDK's offline
replay module that intercepts outbound HTTP calls and serves recorded responses.

## Running the tests

The committed bundle is enough to run the tests.  The shop service does not
need to be running.

```sh
# From the repo root:
pip install -e '.[test]'
pytest examples/fixtures-testing/tests/ -q

# Or as part of the full suite:
pytest -q

# Or from inside this directory:
pytest tests/ -q
```

The replay-based tests (test_auth, test_charges, test_orders, test_users) all
use `stubsmith.replay()` with no arguments and require no API key or network
access.  Live tests are skipped automatically unless `STUBSMITH_API_KEY` is
set.

### Why the conftest sets $STUBSMITH_BUNDLE

`stubsmith.replay()` with no arguments searches upward from the current
working directory for `.stubsmith/bundle.json` - the same convention git and
ruff use for their config files.  In a normal project (bundle at the project
root, tests in a subdirectory) this works without any configuration.

This example is different: it is a nested project inside the SDK repository.
When pytest runs from the repo root, the upward search starts there and walks
toward the filesystem root - it never descends into
`examples/fixtures-testing/`.  The `_bundle_env` fixture in `conftest.py`
bridges that gap by setting `$STUBSMITH_BUNDLE` for the session.  If you
copy this example into its own repository, you can delete the `_bundle_env`
fixture and the `stubsmith.replay()` calls will find the bundle
automatically.

## Running the full loop

**The committed bundle already exists.**  You can clone the repo, install, and
run pytest right now - no account, no network access, and no running service
needed.  See "Running the tests" above.

The steps below capture fresh responses from the real shop service, review them
in the Stubsmith UI, and regenerate the bundle.  You need a Stubsmith account:
sign up at <https://app.stubsmith.dev> (there is a free plan).  Create a
**dedicated project** for this example; each run appends fingerprints to
whatever project the key belongs to, so a shared or reused project accumulates
stale captures.

The script produces **9 fingerprints across 8 endpoints** - well within the
free plan's cap for a single throwaway project.

> **Self-hosted Stubsmith?**  Set `STUBSMITH_API_URL` to your backend URL before
> running Step 2.  The script defaults to the hosted service at
> `https://app.stubsmith.dev/api`; the env-var table at the end of this
> document lists the available overrides.

### Step 1 - start the shop service

```sh
python3 examples/fixtures-testing/shop_service/server.py
# [shop] listening on http://localhost:8081
```

The service stands in for a third-party API you depend on.  **It is not
instrumented and produces no captures** - it only sits there answering
requests.  Nothing appears in your Stubsmith dashboard until Step 2, which
runs the *client*.  Leave this terminal open and continue in another.

### Step 2 - generate traffic

```sh
export STUBSMITH_API_KEY=<your-project-api-key>
python3 examples/fixtures-testing/generate_traffic.py
```

This calls all eight routes and drives the 401 (wrong-password login) and 402
(card declined) error paths explicitly.  Bodies are masked at the edge before
anything leaves this process.

The hosted service uses two distinct hosts: captures are POSTed to
`https://ingest.stubsmith.dev` (the ingest service) while the review UI and
API keys live at `https://app.stubsmith.dev` (the backend).  No environment
variable overrides are needed when using the hosted service - both defaults
are built in.  Self-hosted deployments should set `STUBSMITH_API_URL` (and
optionally `STUBSMITH_INGEST_URL`); see the env-var table at the bottom of this
document.

The script runs a pre-flight check before sending any captures.  If the ingest
URL returns a 404 the script exits with an actionable error naming the URL
tried and the likely fix - a misconfigured `STUBSMITH_INGEST_URL` produces a
loud failure rather than silent capture loss.

### Step 3 - approve fingerprints

Approving a fingerprint records which response fields are kept as recorded
values rather than masked placeholders.  **The committed bundle and the test
assertions depend on exactly the rule set below; a different set produces
different values and failing tests.**

There are two routes.  The script is recommended - it is thirty rules across
nine fingerprints, and CI cannot click.

```sh
export STUBSMITH_ORG_API_KEY=<org API key with review:read and review:approve>
export STUBSMITH_PROJECT_ID=<this example's project id, from its dashboard URL>
python3 examples/fixtures-testing/approve_fingerprints.py --dry-run   # inspect
python3 examples/fixtures-testing/approve_fingerprints.py             # apply
```

The run **aborts without approving anything** if the queue holds a fingerprint
this example does not document - that almost always means the wrong project, and
these keep rules must not be applied to another project's traffic.  A clean run
against this example's project reports exactly 9 and nothing else.
`--ignore-unknown` approves the recognised ones anyway.

The project id is **required**.  An org API key sees every project in the org,
and the review queue does not report which project a fingerprint belongs to -
so an unscoped run can approve a same-shaped fingerprint in an unrelated
project, applying this example's keep rules there, and cannot even tell you it
did.  Fingerprints are matched on `(method, path_template, fingerprint)`, none
of which is project-specific.  `--all-projects` overrides the check for the rare
case where that is genuinely wanted.

An **org API key** is required; a project key authenticates capture upload only.
Mint one under **Settings → API keys** with the `review:read` and
`review:approve` scopes.  It goes in `STUBSMITH_ORG_API_KEY`, kept separate from
the project key in `STUBSMITH_API_KEY` that Step 2 needs, so both can stay
exported across the whole loop.  The script exits non-zero if any queued fingerprint is
not in its table, rather than leaving a field quietly masked.

Or do it by hand: open your project at <https://app.stubsmith.dev>, go to the
**Review** screen, and supply the `field_rules` listed below for each of the 9
fingerprints across 8 endpoints.

> **Then run Step 2 again.**  This is not optional, for two independent reasons.
>
> Ingest stores **no capture row at all** for a pending fingerprint - only
> approved fingerprints may produce captures (`ingest-go/main.go`, the pending
> branch).  A fingerprint approved after its traffic ran therefore has nothing
> recorded, and `stubsmith pull` reports it as `degraded`: the stub exists, has
> no variants, and replay raises `StubNotFound` for it.
>
> And masking happens in the SDK, at the edge - values are replaced *before* the
> capture is uploaded, so the server never held the originals.  A keep rule
> affects only captures recorded **after** it is approved; it cannot recover a
> value from a capture already stored under a stricter rule set.
>
> So: approve, re-run `generate_traffic.py`, and only then pull.  Skip it and
> newly approved fingerprints come back degraded while every identity field
> stays at its placeholder (`0`, `false`, `"<masked>"`) - Step 6 then fails on
> values and on missing stubs rather than on shapes.

**GET /api/users/{id} - fingerprint `fc552c95a0bb0d3e`**
```json
[
  {"path": "resp.id",     "action": "keep"},
  {"path": "resp.plan",   "action": "keep"},
  {"path": "resp.active", "action": "keep"}
]
```

**POST /api/users - fingerprint `90dc0baeeee2ad16`**
```json
[
  {"path": "resp.id",      "action": "keep"},
  {"path": "resp.created", "action": "keep"}
]
```

**POST /api/auth/login - fingerprint `88a4c74a696c6e89`**
```json
[
  {"path": "resp.expires_in", "action": "keep"},
  {"path": "resp.user_id",    "action": "keep"}
]
```

**POST /api/orders - fingerprint `67193bd52728bfbb`**
```json
[
  {"path": "resp.order_id",         "action": "keep"},
  {"path": "resp.status",           "action": "keep"},
  {"path": "resp.total_cents",      "action": "keep"},
  {"path": "resp.items.[].sku",     "action": "keep"},
  {"path": "resp.items.[].qty",     "action": "keep"},
  {"path": "resp.items.[].price_cents", "action": "keep"}
]
```

**GET /api/orders/{id} - fingerprint `fc552c95a0bb0d3e`**
```json
[
  {"path": "resp.order_id",         "action": "keep"},
  {"path": "resp.status",           "action": "keep"},
  {"path": "resp.total_cents",      "action": "keep"},
  {"path": "resp.items.[].sku",     "action": "keep"},
  {"path": "resp.items.[].qty",     "action": "keep"},
  {"path": "resp.items.[].price_cents", "action": "keep"}
]
```

**GET /api/orders - fingerprint `15d2fd0d27a9595f`**
```json
[
  {"path": "resp.total",                 "action": "keep"},
  {"path": "resp.orders.[].order_id",    "action": "keep"},
  {"path": "resp.orders.[].status",      "action": "keep"},
  {"path": "query.status",               "action": "keep"},
  {"path": "query.limit",                "action": "keep"}
]
```

**PUT /api/orders/{id} - fingerprint `e314d5b772be48b5`**
```json
[
  {"path": "resp.order_id", "action": "keep"},
  {"path": "resp.status",   "action": "keep"}
]
```

**POST /api/payments/charges WITH `idempotency_key` - fingerprint `79148562d5fb5ae8`**
```json
[
  {"path": "resp.charge_id",    "action": "keep"},
  {"path": "resp.status",       "action": "keep"},
  {"path": "resp.amount_cents", "action": "keep"},
  {"path": "resp.currency",     "action": "keep"},
  {"path": "resp.card.last4",   "action": "keep"},
  {"path": "resp.card.brand",   "action": "keep"}
]
```

**POST /api/payments/charges WITHOUT `idempotency_key` - fingerprint `4a17ca4d93dddd7d`**
```json
[
  {"path": "resp.charge_id", "action": "keep"},
  {"path": "resp.code",      "action": "keep"}
]
```

`approve_fingerprints.py` submits exactly these rules to:

```
POST /v1/review/<fingerprint_id>/decision
Content-Type: application/json
Authorization: Bearer <org API key>

{"decision": "approve", "field_rules": <see above>}
```

Its table is keyed on `(method, path_template, fingerprint)`, not on the
fingerprint alone: `fc552c95a0bb0d3e` above belongs to **two** endpoints, since
the fingerprint hashes body key-paths, query names and content-type - not the
host or path.  Two body-less GETs therefore collide by construction.

Endpoints with `fingerprint_value_paths` need a keep rule at `body.<path>` for
each one; the backend rejects the approval otherwise.  The script adds those
automatically.

**Array-element path syntax:** nested scalars inside arrays use the `.[].`
segment - e.g. `resp.items.[].sku`, not `resp.items.sku`.  A keep rule on a
parent object (e.g. `resp.items`) does **not** keep the nested scalars; each
kept scalar needs its own exact path.

Sensitive fields (`body.password`, `body.card.number`,
`req_header.authorization`) get no keep rule and are left masked.

### Step 4 - pull the bundle

> Re-run Step 2 before pulling if you have just changed any keep rules - see
> the note in Step 3.

```sh
stubsmith pull --out examples/fixtures-testing/.stubsmith/bundle.json
```

This writes the replay bundle.  Review the diff before committing - a new or
changed key means your shop service or field rules drifted from the committed state.

### Step 5 - stop the shop service

```sh
# Ctrl-C in the shop service terminal
```

### Step 6 - run the tests

```sh
pytest examples/fixtures-testing/tests/ -q
```

All replay-based tests pass with the service stopped.  This is the point: the
client's test suite runs against responses that genuinely came from the real
service, not hand-crafted mocks.

## The committed bundle

The `.stubsmith/bundle.json` in this repository was produced from a real
capture run against a live Stubsmith stack.  If you change the shop service
routes or field rules you must regenerate it:

```sh
export STUBSMITH_API_KEY=<project key>        # where captures go
export STUBSMITH_ORG_API_KEY=<org key>        # review:read + review:approve
export STUBSMITH_PROJECT_ID=<project id>      # where approvals go

python3 examples/fixtures-testing/generate_traffic.py      # fingerprints; records nothing
python3 examples/fixtures-testing/approve_fingerprints.py  # expect exactly 9
python3 examples/fixtures-testing/generate_traffic.py      # this run is the one that records
python3 -m stubsmith pull --out examples/fixtures-testing/.stubsmith/bundle.json
```

Both traffic runs are needed.  Pulling after the first one reports
`variants : 0` and `9 stub(s) marked degraded`, because no capture row exists
for a fingerprint that was pending when the traffic ran - see the note in
Step 3.  `python3 -m stubsmith pull` rather than the `stubsmith` console script
runs the SDK from this checkout instead of whatever is installed.

### Use a dedicated project for this example

Each run appends fingerprints to whatever project the API key belongs to.
Running the script against a shared project, or against the same project twice
with a different shop-service configuration, leaves stale endpoints in the UI
and may pull them into the bundle via `stubsmith pull`.  Use a project created
specifically for this example and delete it when you are done.

### Re-running traffic without corrupting the capture

`generate_traffic.py` resets the shop service to its startup state at the
beginning of every run by calling `POST /admin/reset`.  This ensures that a
second run produces the same captured responses as the first: without the
reset, `PUT /api/orders/5234 → "cancelled"` on the first run causes a
subsequent `GET /api/orders/5234` to return `"cancelled"`, which contradicts
the `"shipped"` response recorded in the bundle and expected by the tests.

## Test file overview

| File | Approach | Why |
|---|---|---|
| `test_auth.py` | `stubsmith.replay()` | Shows the 200 happy path and the inline-bundle pattern for testing a non-modal 401 status |
| `test_charges.py` | `stubsmith.replay()` | Shows how different body structures (with/without `idempotency_key`) produce distinct fingerprints, routing to 201 vs 402 stubs without any test-level configuration |
| `test_orders.py` | `stubsmith.replay()` | Shows dynamic path templating, query-param fingerprinting, and the same stub serving any concrete id |
| `test_users.py` | `stubsmith.replay()` | Shows the inline-bundle pattern for a non-modal 404 status on a dynamic route, and masking assertions on response body fields |
| `test_live_fixtures.py` | live API (opt-in) | Skipped without an API key; validates that the live backend envelope is well-formed |

## How replay() works

`stubsmith.replay()` patches `requests.Session.send` at the transport layer.
When the context manager is active, every outbound call from `ShopClient` is
intercepted before it reaches the network.  The lookup key is
`(domain, method, path_template, fingerprint)` where `fingerprint` is the same
structural hash the capture path computed from the body key-paths, query
parameter names, and content-type - not from any values.

`_select_variant` returns the variant with the highest `count` (most frequently
observed in captured traffic), breaking ties by lowest status code.  This means
`replay()` mirrors the real-world response distribution: if 87 % of login calls
succeeded and 13 % failed, replay serves 200 by default.

To test a non-modal status code (one with a lower count), pass a focused inline
bundle dict containing only the variant you need, as shown in `test_auth.py`
for the 401 case.

## How masking works

Stubsmith uses **fail-closed, path-based masking** at the SDK edge - inside the
SDK process, before any data leaves the caller's machine.

Every scalar in the request and response body is replaced with a type-appropriate
placeholder **unless** the operator has explicitly added a `keep` rule for that
field path.

Placeholder values:
- strings  → `"<masked>"`
- numbers  → `0`
- booleans → `False`
- null     → left as null

Kept strings still pass through a **regex backstop**.  The SDK's embedded
backstop masks email addresses and 16-digit card numbers.  A project can sync
additional regex rules via `anonymizer/rules.json`.

**What this means for test assertions:**

- Do NOT `assert result["email"] == "user@example.com"`.  Email values are
  always masked by the regex backstop.
- DO `assert "email" in result` (presence check only).
- DO `assert result["token"] == "<masked>"` to verify masking ran - but only
  when you need to assert the masking, not as a general-purpose equality check.

**Request headers** follow an allowlist: only `content-type`, `content-length`,
`accept`, `accept-encoding`, `accept-language`, `user-agent`, `host`,
`cache-control`, and `transfer-encoding` pass through; every other request
header becomes `"<masked>"`.

## Path templating and dynamic routes

The SDK templates path segments before fingerprinting:

- Entirely numeric segment  → `{id}`
- UUID-shaped segment        → `{id}`
- 16+ hex characters         → `{id}`

A call to `GET /api/users/4821` is stored with `path_template = "/api/users/{id}"`.

`replay()` applies the same templating to incoming test requests, so a call to
`/api/orders/5234` or `/api/orders/6102` both match the same bundle stub for
`/api/orders/{id}` - one recorded stub covers every concrete integer id.

## Query-string fingerprinting

`ShopClient.list_orders` bakes query parameters into the URL rather than
passing them via `requests`'s `params=` keyword.  The SDK patches
`Session.request` and fingerprints the URL it is handed; `params=` values are
merged later during request preparation and would be invisible to the
fingerprint.

The fingerprint for `GET /api/orders?status=shipped&limit=20` is computed from
the query parameter **names** `[limit, status]` - not their values.  Any
request with those two names matches the same stub, regardless of the filter
value passed.

## Portability

The demo loop is designed so other language SDKs can mirror it.  A port needs:

1. A shop service with the same eight route shapes and four business rules
   (user 9042 → 404, wrong password → 401, amount > 500 000 cents → 402,
   charges with idempotency_key → different fingerprint).
2. A client library equivalent to `shopclient/` that calls those routes.
3. A traffic-generation script equivalent to `generate_traffic.py`.
4. An offline replay mechanism equivalent to `stubsmith.replay()`.

Python-specific details that do not need porting: stdlib `http.server`,
`socketserver.ThreadingMixIn`, the `responses` library used by `test_users.py`.

## CI integration

Running this loop in CI requires a Stubsmith project API key - either from a
project on the hosted service at `https://app.stubsmith.dev`, or from a
self-hosted instance reachable by the CI environment.  This is documented as a
follow-up.

## wait_for_rules and short capture scripts

`stubsmith.install()` starts a background thread that polls `/v1/sdk/sync` for
approved field rules.  On localhost that first sync takes ~74 ms.  A short
capture script that finishes all its HTTP calls in ~50 ms races the sync: every
capture lands as `novel=True` with every field masked.

`generate_traffic.py` passes `wait_for_rules=5.0` to `install()`:

```python
stubsmith.install(url=_INGEST_URL, api_key=_API_KEY, wait_for_rules=5.0)
```

This blocks `install()` for up to 5 seconds until the rules cache reports that
its first sync has completed.  If the backend is unreachable the call returns
after the timeout rather than hanging; it never raises.

Long-running services (web servers, workers) should leave `wait_for_rules` at
its default of `0`.  By the time the first real request arrives the background
sync has already completed; adding a startup delay serves no purpose and slows
down boot.

## Environment variables

| Variable                | Purpose                                                |
|-------------------------|--------------------------------------------------------|
| `STUBSMITH_API_KEY`     | Project API key (Bearer token). Required for Step 2.   |
| `STUBSMITH_PROJECT_ID`  | Project to approve in. Required by `approve_fingerprints.py` unless `--all-projects` is passed. Found in the project's dashboard URL. |
| `STUBSMITH_ORG_API_KEY` | Org API key with the `review:read` and `review:approve` scopes. Required for Step 3's `approve_fingerprints.py`. Kept separate from `STUBSMITH_API_KEY` so both keys can stay exported across the loop. |
| `STUBSMITH_API_URL`     | Backend base URL. Default: `https://app.stubsmith.dev/api`. Used verbatim - the SDK appends `/v1/sdk/sync` to it, and no path component is stripped. Point it at your own instance to self-host (e.g. `http://localhost:3000`). |
| `STUBSMITH_INGEST_URL`  | Ingest URL. Default: `https://ingest.stubsmith.dev/v1/captures` (hosted service) or `STUBSMITH_API_URL + /v1/captures` (self-hosted, when `STUBSMITH_API_URL` is set to a non-hosted URL). The hosted backend and ingest are separate hosts; setting only `STUBSMITH_API_URL` does not change the ingest target for hosted deployments. |
| `STUBSMITH_BUNDLE`      | Override path to the replay bundle file.               |
