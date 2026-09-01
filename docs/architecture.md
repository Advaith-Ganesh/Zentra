# Architecture

Zentra is a small system with three moving parts: an API, a background worker,
and a browser application. Everything else is a datastore or an external
provider. The design goal throughout is that the interesting logic — scanning,
scoring, entitlements, tenancy — lives in one place, is testable without a
network, and cannot be bypassed by talking to a different layer.

---

## 1. Shape of the system

```
                      ┌──────────────────────────────┐
   Browser  ────────► │  Next.js app (apps/web)      │
                      │  Typed API client only       │
                      └───────────────┬──────────────┘
                                      │ HTTPS + Bearer token
                                      ▼
   Stripe ──webhook──► ┌──────────────────────────────┐ ◄── API key (Scale)
   Slack  ──command──► │  FastAPI (apps/api)          │
                      │  auth · tenancy · entitlements│
                      └───┬──────────────┬────────────┘
                          │              │ enqueue
                          │              ▼
                          │      ┌──────────────────┐
                          │      │  Redis (broker)  │
                          │      └────────┬─────────┘
                          │               │
                          │               ▼
                          │      ┌──────────────────────────────┐
                          │      │  Celery worker (+ beat)      │
                          │      │  scanners → scoring → verdict│
                          │      └───────┬──────────────────────┘
                          │              │
                          ▼              ▼
                      ┌──────────────────────────────┐
                      │  PostgreSQL (Supabase)       │
                      │  RLS on every tenant table   │
                      └──────────────────────────────┘
                                     ▲
                                     │ passive, SSRF-guarded
                      ┌──────────────┴───────────────┐
                      │ SSL Labs · HIBP · Shodan     │
                      │ NVD · public DNS · HTTP head │
                      └──────────────────────────────┘
```

## 2. Repository layout

```
apps/api/zentra/
  config.py            Settings; refuses unsafe production configuration
  logging.py           Structured logging with secret redaction
  errors.py            Error taxonomy → the single API error envelope
  db/                  SQLAlchemy models, session, migration runner
  core/                Security primitives, rate limiting, entitlements,
                       feature flags, domain validation, audit logging
  auth/                Local and Supabase auth providers; FastAPI dependencies
  scanners/            The scanning engine (see docs/scanning-engine.md)
  scoring/             Deterministic scoring and plain-English verdicts
  services/            Business logic: vendors, scans, findings, reports,
                       alerts, billing, API keys, benchmarking
  integrations/        Email, Slack, Teams
  reports/             WeasyPrint templates and PDF rendering
  api/v1/              HTTP routes; thin, delegating to services
  workers/             Celery app, tasks, dispatch
  scripts/             Demo seeder

apps/web/src/
  app/                 Next.js App Router pages
  components/          Design system and domain components
  lib/                 Typed API client, types, presentation helpers
  hooks/               Session and data-loading hooks

supabase/migrations/   Ordered SQL; the single source of truth for schema
infrastructure/        Dockerfiles and deployment configuration
docs/                  This documentation
```

### Why the worker shares the API's Python package

The worker is not a separate codebase. It imports the same `zentra` package and
ships in the same Docker image, with a different start command. A worker running
different scanner or scoring code from the API that queued the job is a class of
bug worth designing out rather than monitoring for.

## 3. Request lifecycle

1. **Middleware** assigns a request ID (echoed as `X-Request-ID` and attached to
   every log line and audit record), applies security headers, enforces a body
   size limit, and applies a coarse per-client rate limit.
2. **Authentication** resolves a `Principal` from either a session bearer token
   or an API key. A principal always carries exactly one organization, so no
   handler has to work out tenancy for itself.
3. **Authorization** happens in two places, deliberately: the route declares a
   minimum role, and every service query scopes by `organization_id` *in the
   WHERE clause* rather than fetching and then comparing. A cross-tenant read is
   therefore impossible even if a handler forgets to check.
4. **Entitlements** are re-derived from the subscription row on each request.
   The frontend's view of the plan is never trusted.
5. **The service layer** performs the work and writes an audit record.
6. **Errors** are converted to one envelope. Stack traces never leave the
   server.

## 4. Tenancy

Every tenant-owned row carries an `organization_id`. Three independent controls
enforce isolation:

- **Query scoping.** `get_vendor(session, organization_id, vendor_id)` filters
  on both columns. There is no accessor that takes an ID alone.
- **Row Level Security.** Every tenant table has RLS enabled *and forced*, with
  policies keyed on `auth.uid()`. `force` means the policies apply to the table
  owner too, so a service-configuration mistake cannot silently expose rows.
- **Column grants.** The `authenticated` role has no `SELECT` on `key_hash`,
  `encrypted_secret` or `encrypted_bot_token`. Even a correctly authenticated
  end-user session cannot read a credential.

Cross-tenant access returns **404, not 403**, so the API does not confirm that a
resource exists in another organization. The one exception is an explicit
attempt to switch organization via `X-Zentra-Organization`, which returns 403
because the caller has already proved identity.

`tests/test_rls.py` exercises the database layer directly as the `authenticated`
role with a forged JWT claim, and `tests/test_tenant_isolation.py` exercises
every route that accepts an identifier.

## 5. Authentication

Two providers behind one interface (`auth/providers.py`):

- **`LocalAuthProvider`** — real email/password authentication against Zentra's
  own `users` table: Argon2id hashing at OWASP parameters, signed HS256 session
  tokens. It exists so the product runs end-to-end with no external account.
  It is a genuine implementation, not a stub.
- **`SupabaseAuthProvider`** — the production path. Credentials live in Supabase
  Auth; Zentra verifies the JWTs Supabase issues locally against
  `SUPABASE_JWT_SECRET` (no network round trip per request) and mirrors a
  profile row into `public.users`.

Switching is a single environment variable. Nothing outside `auth/` knows which
is in use.

## 6. Scanning and the worker

Covered in detail in [docs/scanning-engine.md](./scanning-engine.md). In short:

- Scans **never** run inside an HTTP request. The API creates a `queued` scan
  row and hands the ID to Celery.
- The orchestrator runs independent scanners in parallel, then a second pass for
  scanners that depend on the first (CVE lookup needs technology signals).
- One scanner failing can never fail a scan: `BaseScanner.execute` normalizes
  any exception or timeout into an `error` result.
- A scan that dies with its worker is reaped by a scheduled task and marked
  `failed` — it never disappears.

Scheduled work (Celery beat): daily rescans, stuck-scan reaping, benchmark
recomputation, weekly summaries, retention purges.

## 7. Billing

Two rules govern `services/billing.py`:

1. **Subscription state is only ever written from a verified Stripe webhook or
   a direct Stripe API read.** Never from a request body.
2. **Webhook processing is idempotent.** Every event is recorded in
   `webhook_events` under a unique `(provider, event_id)` constraint; the
   constraint, not application logic, is what makes a redelivery a no-op.

Entitlements are centralised in `core/entitlements.py`. Nothing else in the
codebase compares against a plan name.

## 8. Reporting

Reports are generated by the worker, not the request. `reports/pdf.py` renders a
Jinja template through WeasyPrint with `base_url=None`, so the renderer cannot
resolve any external resource — a crafted branding value cannot cause an
outbound fetch. White-label input is sanitized hard: brand colour must match a
strict hex pattern, and a logo is identified by magic bytes and re-encoded as a
data URI at upload time.

Report files are written `0600`, reads are confined to the configured storage
directory, and exports expire after 30 days.

## 9. Security boundaries

| Boundary | Control |
| --- | --- |
| Browser → API | CORS allow-list, bearer token, no cookies, strict CSP on the web app |
| API → database | Query scoping, RLS, column grants, parameterized queries only |
| API → worker | Signed job IDs only; the worker re-reads all state from the database |
| Scanner → internet | SSRF guard: validate, resolve once, vet every address, pin the connection, re-validate redirects, http/https on 80/443 only |
| Stripe → API | Signature verification before parsing; raw body preserved |
| Slack → API | v0 signature with a five-minute replay window |
| Teams webhook | URL must be an https Microsoft host; stored encrypted |
| Customer branding → PDF | Hex-only colours, magic-byte logo validation, no external resource resolution |
| Logs | Redaction processor strips credentials, tokens and breach detail |

## 10. Observability

Structured logs (`structlog`) with a request ID on every line, JSON in
production. Key events: `scan_started`, `scan_completed`, `scan_failed`,
`vendor_created`, `report_generated`, `subscription_changed`, `alert_sent`,
`api_error`, `ssrf_blocked`, `rate_limited`.

Audit records go to the database as well as the log stream, so a customer can
answer "who changed this finding?" without access to infrastructure logs.

The internal admin API (`/api/v1/admin/*`) exposes scan health, provider
failures, queue depth, webhook processing and API usage. It is gated on
`users.is_platform_admin`, which is only ever set server-side from
`ZENTRA_ADMIN_EMAILS`, and returns 404 to everyone else so the surface is not
discoverable.

## 11. Deliberate simplifications

Recorded honestly rather than presented as complete:

- **Report storage is on local disk.** Fine for a single API instance with a
  mounted volume. Move to object storage before scaling past one replica.
- **Rate limiting is a fixed window, not a sliding one.** Simpler, and adequate
  at this scale; a burst can straddle a boundary.
- **MSSP support is data model and feature flag only.** The schema carries
  `parent_organization_id` and the RLS policy honours it, but no MSSP UI exists.
- **Benchmarking recomputes on a schedule** rather than incrementally.
- **The public API is versioned by path** (`/api/v1`) with no deprecation
  machinery yet.
