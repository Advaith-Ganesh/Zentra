# Zentra

**Vendor risk intelligence for UK startups and SMBs.**

Zentra continuously assesses a company's third-party vendors against publicly
available security signals, and turns the result into a 0–100 risk score, a
plain-English explanation, a specific recommended action, and an
auditor-friendly vendor risk register — without requiring a security analyst
on staff.

[![CI](https://github.com/Advaith-Ganesh/Zentra/actions/workflows/ci.yml/badge.svg)](https://github.com/Advaith-Ganesh/Zentra/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6.svg?logo=typescript&logoColor=white)](apps/web/tsconfig.json)
[![Next.js 16](https://img.shields.io/badge/Next.js-16-black.svg?logo=next.js&logoColor=white)](https://nextjs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.141-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1.svg?logo=postgresql&logoColor=white)](https://www.postgresql.org/)

---

## Overview

Small UK companies increasingly have to answer "how do you manage third-party
risk?" — from an enterprise customer's security questionnaire, an insurer, or
their own board — and most have no security team and no budget for one.
Spreadsheets tracking vendor risk go stale the day they're written, because
nobody re-checks fifty vendors by hand every month.

Zentra is a small, opinionated tool built to close that gap: point it at a
vendor's domain, and it keeps watching public security signals (TLS posture,
breach history, exposed services, known vulnerabilities, email/DNS hardening,
web security headers) and re-scores the vendor whenever something changes,
with the reasoning behind every score shown, not hidden behind a single
number.

**Who it's for:** a founder, ops lead, or compliance owner at a UK SMB or
fintech (roughly 10–80 people) who needs a defensible, continuously-updated
vendor risk register — not a security team running their own scanning
infrastructure.

**What it deliberately is not:** see [What Zentra is not](#what-zentra-is-not)
below — that distinction matters more here than in most projects, because the
product's credibility depends on never overstating what an automated,
public-signal-only scan can actually tell you.

---

## Contents

- [Overview](#overview)
- [Key features](#key-features)
- [Screenshots](#screenshots)
- [How it works](#how-it-works)
- [What Zentra is not](#what-zentra-is-not)
- [Architecture](#architecture)
- [Technology stack](#technology-stack)
- [Project structure](#project-structure)
- [Getting started](#getting-started)
- [Environment variables](#environment-variables)
- [External accounts and API keys](#external-accounts-and-api-keys)
- [Database and migrations](#database-and-migrations)
- [Usage](#usage)
- [API](#api)
- [Security](#security)
- [Testing](#testing)
- [Code quality](#code-quality)
- [Deployment](#deployment)
- [Troubleshooting](#troubleshooting)
- [Known limitations](#known-limitations)
- [Roadmap](#roadmap)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [Licence](#licence)

---

## Key features

Every item below is implemented and exercised by the test suite — nothing
here is aspirational.

- **Continuous vendor scanning.** Add a vendor by domain; Zentra scans it
  immediately and on a schedule, across six categories: TLS/certificate
  posture, breach history, internet exposure, known vulnerabilities, DNS
  security (SPF/DMARC/DNSSEC), and web/browser security headers.
- **Deterministic, explainable scoring.** A 0–100 score with a full
  category-by-category breakdown of where every point came from — no opaque
  ML model, and a scan that only partly completes is never presented as a
  confident "Low risk".
- **Plain-English verdicts.** Each score comes with a headline explanation,
  a specific recommended action, and every finding's "what to do about it".
- **Auditor-ready PDF reports.** A vendor risk register a compliance owner
  can hand to an auditor or an enterprise customer's security team, with
  optional white-label branding.
- **Material-change alerting.** Zentra tracks each vendor's score over time
  and raises an alert when the risk level changes materially, not on every
  minor fluctuation.
- **Unauthenticated free scan.** A rate-limited, no-signup entry point at
  `/scan` for prospects to try the product against a real domain.
- **Multi-tenant from the ground up.** Postgres Row Level Security enforced
  (`ENABLE` *and* `FORCE`) on every tenant table, on top of query-level
  scoping — cross-tenant access is structurally impossible, not just checked.
- **Billing and plan entitlements.** Stripe Checkout, the customer portal,
  webhook-driven subscription state, and entitlements re-derived from the
  database on every request rather than trusted from the client.
- **Public API and integrations.** API keys for the Scale plan, a Slack
  slash command (`/zentra check <domain>`), and Microsoft Teams webhook
  alerts.
- **Anonymized benchmarking.** Compare a vendor's score against its peer
  cohort, withheld below a minimum cohort size to prevent re-identification.
- **SSRF-hardened scanning.** The scan target is never trusted: resolved IPs
  are validated against every RFC1918/loopback/link-local/cloud-metadata
  range, the outbound connection is pinned to the validated IP to defeat
  DNS-rebinding, and only passive checks are ever performed — no
  authentication attempts, exploitation, or brute force, against any target.

## What Zentra is not

Being precise about this matters more than marketing copy.

- Zentra **does not** make you ISO 27001 or SOC 2 compliant, and no software
  can. It produces compliance-*supporting* documentation: evidence that you
  operate a third-party risk process, in a form an auditor can read.
- Zentra **is not** a security audit or a penetration test of your vendors. It
  observes signals from public sources.
- Zentra **never** performs intrusive testing. No authentication attempts, no
  exploitation, no brute force — against any system, under any configuration.
- Zentra **does not** claim a vendor is secure or insecure. It reports the
  signals it observed and how confident it is in them.

## Screenshots

Captured from the running application against the seeded demo dataset. Every
score and finding shown is produced by Zentra's mock providers, which is why the
demo workspace carries a banner saying so.

![Landing page](docs/screenshots/landing.png)

**Landing page** — the public marketing page, with the free scan as the
primary call to action.

| | |
| --- | --- |
| ![Dashboard overview](docs/screenshots/dashboard.png) | ![Vendor list](docs/screenshots/vendor-list.png) |
| **Overview** — portfolio position, vendors needing attention, recent scans. | **Vendors** — every monitored third party with score, risk level and trend. |

![Vendor detail](docs/screenshots/vendor-detail.png)

**Vendor detail** — the score with its per-category breakdown, every check with
its source, date and confidence, and each finding with a recommended action.

![Public scan](docs/screenshots/public-scan.png)

**Free scan** — the unauthenticated entry point, rate limited to three per hour
per requester.

## How it works

1. **Add a vendor** by domain from the dashboard, or try one anonymously via
   the free scan.
2. **Zentra scans it immediately**, then on a recurring schedule: TLS
   certificate and configuration, breach history, exposed internet-facing
   services, known CVEs against disclosed software, DNS/email hardening, and
   web security headers — each through a dedicated scanner with a real
   provider adapter and a deterministic mock fallback (see
   [Environment variables](#environment-variables)).
3. **Results are scored**, not just collected: each category contributes a
   weighted, capped number of points, severe findings enforce a score floor,
   and coverage/confidence are tracked so a half-completed scan is never
   presented as a confident result.
4. **A plain-English verdict is generated** — the biggest problem, why it
   matters, and what to do about it — alongside the full point-by-point
   breakdown for anyone who wants it.
5. **If the risk level changed materially**, an alert is raised and (if
   configured) delivered to Slack or Microsoft Teams.
6. **The vendor risk register** — every vendor, its current score, and its
   history — can be exported as a PDF at any time.

See [docs/scanning-engine.md](docs/scanning-engine.md) for the full scan
lifecycle sequence diagram and [docs/risk-scoring.md](docs/risk-scoring.md)
for the complete scoring methodology.

## Architecture

Three moving parts — an API, a background worker, and a browser application —
plus a datastore and a set of external providers. The worker is not a separate
codebase: it imports the same `zentra` Python package and ships in the same
Docker image, so a worker running different scanning or scoring logic than the
API that queued the job is a class of bug designed out rather than monitored
for.

```mermaid
flowchart TB
    Browser["Browser"] -->|"HTTPS + Bearer token"| Web["Next.js app (apps/web)"]
    Web --> API
    Stripe["Stripe webhook"] --> API
    Slack["Slack slash command"] --> API
    APIKey["API key (Scale plan)"] --> API
    API["FastAPI (apps/api)\nauth · tenancy · entitlements"] -->|enqueue| Redis["Redis (broker)"]
    Redis --> Worker["Celery worker + beat\nscanners → scoring → verdict"]
    API --> DB[("PostgreSQL / Supabase\nRow Level Security enforced")]
    Worker --> DB
    Worker -->|"passive, SSRF-guarded"| Providers["SSL Labs · HIBP · Shodan\nNVD · public DNS · HTTP headers"]

    classDef store fill:#1f2430,stroke:#6b7280,color:#e5e7eb;
    class DB store;
```

See [docs/architecture.md](docs/architecture.md) for the full request
lifecycle, tenancy model and authentication design;
[docs/scanning-engine.md](docs/scanning-engine.md) for the scanner design and
SSRF protection; and [docs/risk-scoring.md](docs/risk-scoring.md) for the
complete scoring methodology.

## Technology stack

| Layer | Technology | Why |
| --- | --- | --- |
| Frontend | Next.js 16 (App Router), React 19, TypeScript, Tailwind CSS, Recharts, Zod | App Router for server components on data-heavy pages; Zod validates every form against the same shape the API expects. |
| API | Python 3.11, FastAPI, Pydantic v2, SQLAlchemy 2 | FastAPI's dependency injection is what makes tenancy and entitlements structurally hard to skip in a route handler; Pydantic gives one validation layer for requests, responses and settings. |
| Worker | Celery + Redis | Scans and PDF generation must never block an HTTP request; Celery's task retry and idempotency primitives are used directly rather than reimplemented. |
| Database | PostgreSQL (Supabase-compatible), Row Level Security | RLS enforced with `FORCE` puts tenant isolation in the database itself, not only in application code. |
| Auth | Supabase Auth in production; a real local email/password provider for development | The product runs end-to-end with zero external accounts in development — the local provider is a genuine implementation (Argon2id, signed sessions), not a stub. |
| Payments | Stripe Checkout, Customer Portal, webhooks | Webhook-driven subscription state with idempotent event handling, rather than trusting the client's view of its own plan. |
| PDF | WeasyPrint | HTML/CSS templating for the vendor risk register, rendered server-side with no remote resource fetching (SSRF-hardened). |
| Email | A provider abstraction with a Resend adapter and a console adapter | The console adapter means the whole app works with zero email credential in development. |

## Project structure

<details>
<summary>Expand the full directory layout</summary>

```
apps/web/src/
  app/                 Next.js App Router pages
  components/          Design system and domain components
  lib/                 Typed API client, types, presentation helpers
  hooks/                Session and data-loading hooks

apps/api/zentra/
  config.py            Settings; refuses unsafe production configuration
  logging.py           Structured logging with secret redaction
  errors.py            Error taxonomy -> the single API error envelope
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
  api/v1/               HTTP routes; thin, delegating to services
  workers/             Celery app, tasks, dispatch
  scripts/             Demo seeder

supabase/migrations/   Ordered SQL — the single source of truth for schema
infrastructure/        Dockerfiles and deployment configuration (Railway, Vercel)
docs/                  Architecture, scanning engine, risk scoring, API reference
scripts/               Local developer helper scripts
```

</details>

## Getting started

**Prerequisites:** Python 3.11+, Node 20+, Docker (or a local PostgreSQL 16 and
Redis 7).

The fastest path — one command, everything in containers:

```bash
git clone https://github.com/Advaith-Ganesh/Zentra.git
cd Zentra
make demo
```

`make demo` builds the images, starts Postgres, Redis, the API, a Celery worker,
the beat scheduler and the frontend, applies migrations, waits for the API to
report healthy, loads the demo dataset and prints the sign-in credentials. It
needs no `.env` — Compose supplies development defaults for every variable.
Stop everything with `make down`.

If you would rather run the steps yourself:

```bash
cp .env.example .env
docker compose up --build            # migrations run automatically
docker compose exec api python -m zentra.scripts.seed
```

Open <http://localhost:3000> and sign in as `demo@zentra.example` with the
password the seeder prints.

### GitHub Codespaces

The repository ships a devcontainer, so you can run Zentra entirely in the
browser with nothing installed locally. On the GitHub repository page choose
**Code → Codespaces → Create codespace**, wait for it to build, then in the
terminal run:

```bash
make demo
```

`make demo` goes through `scripts/compose.sh`, which detects the Codespace and
points the app at `https://<codespace>-3000.app.github.dev` instead of
localhost. This matters because the frontend bakes the API URL in at build
time, and your browser is not on the container's localhost.

**Set port 8000 to Public.** In the **Ports** panel, right-click port 8000 →
*Port Visibility* → *Public*. The devcontainer requests this, but Codespaces
sometimes falls back to private, and the browser cannot call a private port
cross-origin. Port 3000 can stay private. Then open the forwarded 3000 URL.

### VS Code

Open the folder and use the **Dev Containers: Reopen in Container** command
(requires the Dev Containers extension and Docker Desktop) — this uses the same
devcontainer as Codespaces, so ports 3000 and 8000 forward to your real
localhost and `make demo` behaves exactly as it does natively.

Without Dev Containers, just open the folder and run `make demo` in the VS Code
terminal; only Docker is required. The recommended extensions in
`.devcontainer/devcontainer.json` (Ruff, mypy, ESLint, Prettier, Tailwind) are
worth installing either way, and the Python interpreter to select is
`apps/api/.venv/bin/python` after `make setup`.

### Running natively

```bash
make setup        # virtualenv, Python deps, npm deps, and a .env with generated secrets
make services     # Postgres and Redis in Docker
make migrate      # apply migrations
make seed         # load the demo dataset
```

Then, in four terminals:

```bash
make dev-api      # http://localhost:8000  (docs at /docs)
make dev-worker   # Celery worker
make dev-beat     # scheduled rescans
make dev-web      # http://localhost:3000
```

`make help` lists everything.

### No credentials required

The default configuration sets `USE_MOCK_SCANNERS=true` and
`AUTH_PROVIDER=local`. Every external provider has a deterministic offline
implementation, and authentication runs against Zentra's own user table with
real Argon2id hashing. The entire product — sign-up, scanning, scoring,
findings, PDF reports, alerts — works end to end with no external account.

### Quick reference

| Component | Command | Port |
| --- | --- | --- |
| API | `make dev-api` | 8000 |
| Worker | `make dev-worker` | — |
| Scheduler | `make dev-beat` | — |
| Frontend | `make dev-web` | 3000 |

Interactive API documentation is at <http://localhost:8000/docs> (disabled in
production; the OpenAPI schema remains available at `/openapi.json`).

## Environment variables

`.env.example` is the complete list with comments. The ones that matter most:

| Variable | Purpose |
| --- | --- |
| `ENVIRONMENT` | `development` / `test` / `production`. Production enforces safe settings |
| `USE_MOCK_SCANNERS` | `true` for offline providers. Must be `false` in production |
| `AUTH_PROVIDER` | `local` or `supabase` |
| `JWT_SECRET` | Session signing key. **Required**; at least 32 characters in production |
| `SECRETS_ENCRYPTION_KEY` | Fernet key used to encrypt integration credentials at rest |
| `DATABASE_URL` | PostgreSQL connection string |
| `REDIS_URL`, `CELERY_BROKER_URL` | Redis for rate limiting and the job broker |
| `CORS_ALLOWED_ORIGINS` | Explicit browser origins. A wildcard is rejected in production |
| `STRIPE_*` | Billing. Absent means checkout is unavailable; entitlements still enforced |
| `HIBP_API_KEY`, `SHODAN_API_KEY`, `NVD_API_KEY` | Optional. Absent means the check reports "not assessed" |

Generate the two required secrets:

```bash
openssl rand -hex 32                                                    # JWT_SECRET
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

`zentra.config` validates production configuration at import time. A deployment
with `DEBUG=true`, mock scanners enabled, a short JWT secret, disabled rate
limiting or a wildcard CORS origin **fails to start** rather than running in an
unsafe state.

## External accounts and API keys

Nothing here is required to run or evaluate Zentra.

| Service | Needed for | Without it |
| --- | --- | --- |
| **Supabase** | Production auth and database | Local auth and local Postgres work fully |
| **Stripe** | Subscriptions and the report pack | Checkout returns a clear "billing not configured" error; entitlements are still enforced |
| **Have I Been Pwned** | Breach history (paid API key) | The check reports "not assessed", never "clean" |
| **Shodan** | Internet exposure | The check reports "not assessed" |
| **NIST NVD** | CVE lookups (key optional) | Works unauthenticated at a lower rate limit |
| **Resend** | Transactional email | Emails are logged to the console instead |
| **Slack** | Slack alerts and `/zentra check` | Feature disabled; endpoints return 404 |

SSL Labs needs no key.

### Stripe setup

1. Create products and monthly prices for Starter (£29), Growth (£79) and Scale
   (£249), plus a one-off Report Pack (£99).
2. Put the price IDs in `STRIPE_STARTER_PRICE_ID`, `STRIPE_GROWTH_PRICE_ID`,
   `STRIPE_SCALE_PRICE_ID` and `STRIPE_REPORT_PACK_PRICE_ID`.
3. Add a webhook endpoint at `https://<api>/api/v1/webhooks/stripe` subscribed
   to `checkout.session.completed`, `customer.subscription.created|updated|deleted`,
   `invoice.payment_failed` and `invoice.paid`. Copy the signing secret into
   `STRIPE_WEBHOOK_SECRET`.
4. Locally: `stripe listen --forward-to localhost:8000/api/v1/webhooks/stripe`.

The backend never trusts the frontend for subscription state. Plan and status
are written only from a signature-verified webhook or a direct Stripe read.

## Database and migrations

Schema lives in `supabase/migrations/` as ordered SQL. The same files are
applied by `make migrate` locally and by `supabase db push` to hosted Supabase,
so the two cannot drift.

```bash
make migrate        # development database
make migrate-test   # test database
```

The runner records a checksum per migration and refuses to run if an already-
applied file has changed. To change the schema, add a new numbered file.

Migration `0003_rls.sql` enables **and forces** Row Level Security on every
tenant table, and revokes column-level access to credential columns from the
`authenticated` role.

## Usage

Try the free scan with no account, against the running dev stack:

```bash
curl -X POST http://localhost:8000/api/v1/public/scan \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

Sign in and add a vendor to monitor (the session token comes from
`POST /api/v1/auth/signin`):

```bash
curl -X POST http://localhost:8000/api/v1/vendors \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "Stripe", "domain": "stripe.com", "criticality": "high"}'
```

This queues an immediate scan and returns the vendor record; the score
appears once the worker finishes (usually a few seconds against mock
providers). The same flow is exactly what the dashboard's "Add vendor" form
does.

## API

The full OpenAPI schema is in [docs/openapi.json](docs/openapi.json) and
documented in [docs/api.md](docs/api.md); with the API running locally,
interactive docs are at <http://localhost:8000/docs>.

Two authentication schemes are supported on the same API:

| Scheme | Header | Used by |
| --- | --- | --- |
| Session token | `Authorization: Bearer <access_token>` | The Zentra dashboard |
| API key | `X-API-Key: zk_live_...` | Scale-plan integrations (create one at `POST /api/v1/api-keys`; the secret is shown once and stored only as a hash) |

Every error response uses a single envelope:

```json
{
  "error": {
    "code": "VENDOR_NOT_FOUND",
    "message": "Vendor could not be found.",
    "request_id": "8f0c..."
  }
}
```

## Security

The full policy, threat model and vulnerability reporting process are in
[SECURITY.md](SECURITY.md). The mechanisms actually implemented:

- **SSRF defence in depth for the scanner.** A scan target's domain is
  resolved, every resolved IP is checked against RFC1918, loopback,
  link-local, CGNAT and cloud-metadata ranges, and the outbound connection is
  then *pinned to that validated IP* — so a second DNS answer at connection
  time (DNS rebinding) cannot bypass the check. Redirects are re-validated
  the same way, with a hard redirect limit. See
  [docs/scanning-engine.md § SSRF protection](docs/scanning-engine.md).
- **Passive-only scanning.** No authentication attempts, exploitation, or
  brute force are ever performed against a scanned target, under any
  configuration — this is enforced in code, not only policy.
- **Row Level Security, forced.** Every tenant table has RLS `ENABLE`*d* and
  `FORCE`*d* (the latter is what makes the policies apply even to the table
  owner), on top of query-level tenant scoping in every service function.
- **Argon2id password hashing** at OWASP-recommended parameters, SHA-256
  API-key hashing, and Fernet-encrypted storage for third-party integration
  secrets (Slack bot tokens, Teams webhook URLs).
- **Structured logging with secret redaction.** Log output is scanned for
  known credential patterns (Stripe keys, Slack tokens, JWTs) before it is
  written, regardless of which field they appear under.
- **No fabricated results, ever.** A provider outage reduces coverage and
  confidence — it is never presented as a passing check, and the scoring
  engine refuses to publish a risk level below a minimum coverage threshold
  rather than show a confident "Low risk" from a scan that mostly failed.

## Testing

```bash
make test          # everything
make test-api      # backend tests (439 at time of writing)
make test-web      # frontend tests (49 at time of writing)
make test-api-cov  # with a coverage report
```

The backend suite runs against a real PostgreSQL database — the schema uses
native enums, JSONB, CITEXT, array columns and row-level security, none of which
SQLite can emulate. Faking that would make the tests worth less than nothing.

What is covered:

- **Scoring** — deterministic scenarios for a perfect vendor, a minor DNS
  weakness, an expired certificate, weak TLS, breaches, exposed ports, critical
  CVEs, multiple simultaneous findings, provider outages, partial scans and
  unknown signals. Each asserts that an outage is not a failure, that unknown is
  not risk, and that missing data cannot manufacture an extreme score.
- **SSRF** — every blocked range individually (loopback, RFC1918, CGNAT,
  link-local, cloud metadata, IPv6 equivalents, IPv4-mapped and 6to4 forms),
  fail-closed behaviour on mixed record sets, rejected schemes and ports, and
  that a blocked name never reaches the resolver.
- **Tenant isolation** — every route that accepts an identifier, plus
  organization-header spoofing.
- **Row Level Security** — exercised directly against the database as the
  `authenticated` role with a forged JWT claim.
- **Billing** — signature verification, forged and wrong-secret signatures,
  duplicate event delivery, upgrade, downgrade, payment failure and entitlement
  enforcement after each.
- **API keys** — hashing at rest, single-display secrets, scope enforcement,
  revocation and expiry.
- **Reports** — PDF generation, branding sanitization, markup escaping, path
  confinement and failure recording.
- **Rate limiting**, **authentication**, **authorization**, **failure modes**
  (database down, Redis down, provider timeouts, email failures) and **log
  redaction**.

## Code quality

```bash
make lint        # ruff + eslint
make typecheck   # mypy + tsc
make build       # production frontend build
make security    # bandit, pip-audit, npm audit
make check       # everything CI runs
```

CI runs all of the above on every pull request, plus Docker image builds and a
gitleaks secret scan. A red check blocks a deploy.

## Deployment

- **Backend and worker** — Railway, from
  `infrastructure/docker/api.Dockerfile`. Three services (API, worker, beat)
  share one image so the worker can never run different scanner code from the
  API that queued the job. See
  [infrastructure/railway/README.md](infrastructure/railway/README.md).
- **Frontend** — Vercel, or Railway using
  `infrastructure/docker/web.Dockerfile`.
- **Database and auth** — hosted Supabase. Apply `supabase/migrations/` with
  `supabase db push`.

Health endpoints: `/health` is cheap and touches no dependency (use it for
liveness); `/ready` verifies Postgres and Redis and returns 503 when either is
unreachable (use it for readiness).

## Troubleshooting

**`/ready` returns 503.** One of Postgres or Redis is unreachable; the response
body names which. The API stays up deliberately — a Redis blip should not take
the product offline.

**Scans stay `queued`.** No worker is consuming the queue. Start
`make dev-worker`. In development the API falls back to running the scan inline
if the broker is unreachable; in production it does not, so a broken broker
surfaces rather than being hidden.

**`Migration X has changed after being applied`.** An already-applied migration
file was edited. Add a new migration instead. To reset local data:
`docker compose down -v && docker compose up`.

**PDF generation fails.** WeasyPrint needs Pango and Cairo. On Debian/Ubuntu:
`apt-get install libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libgdk-pixbuf-2.0-0`.
The Docker image already has them.

**"This domain resolves to a network that Zentra will not contact."** Working as
intended: the domain resolves into private, loopback, link-local or
cloud-metadata address space. See
[docs/scanning-engine.md](docs/scanning-engine.md#5-ssrf-protection).

**Everything scores "not assessed".** `USE_MOCK_SCANNERS=false` with no provider
credentials. Either set it to `true` or supply the keys. Zentra reports the gap
rather than inventing a result.

**Free scan returns 429.** By design — three per hour per requester.

**Backend tests fail with `password authentication failed for user "postgres"`.**
The Compose stack publishes Postgres on host port 5432, so it shadows a local
one. Either stop it (`docker compose down`) before running the native test
suite, or point `TEST_DATABASE_URL` at the container:
`postgresql+psycopg://zentra:zentra@localhost:5432/zentra_test`.

## Known limitations

Recorded honestly rather than omitted:

- Report PDFs are written to local disk. Fine for one API instance with a
  mounted volume; move to object storage before scaling to multiple replicas.
- Rate limiting is a fixed window, so a burst can straddle a boundary.
- The dashboard keeps its access token in `localStorage`, so any script
  executing on the page could read it. The alternative — an `httpOnly`,
  `SameSite` cookie — resists that but needs CSRF protection on every state
  change, and the same API also serves API-key clients that cannot use
  cookies. The mitigations are a short token lifetime, a strict CSP, no
  `dangerouslySetInnerHTML` anywhere in the app (enforced by an ESLint
  error), and React's default escaping. `SECURITY.md` records the reasoning
  and the migration path.
- MSSP support is data model and feature flag only — no MSSP UI exists.
- The frontend CSP allows `'unsafe-inline'` for scripts because Next.js emits an
  inline bootstrap into statically prerendered pages and a nonce cannot be
  embedded at build time. The rationale and compensating controls are documented
  in `apps/web/next.config.mjs`.
- Slack support covers OAuth installation, the `/zentra check` command and
  alerts; there is no interactive block UI.
- Benchmarking recomputes on a schedule rather than incrementally.
- The legal documents in `apps/web/src/app/legal/` are **drafts requiring
  solicitor review** before commercial launch, and are labelled as such in the
  product.

## Roadmap

Realistic next steps, not a marketing wishlist:

- **Move report storage to object storage** (S3-compatible) — the current
  local-disk storage is the main blocker to running more than one API
  replica.
- **A vendor questionnaire/evidence-collection workflow** — the human side of
  third-party risk management that automated scanning alone can't cover.
- **An MSSP UI** — the data model and feature flag already exist
  (`Flag.MSSP`); there is no interface built on top of them yet.
- **Real-time scan status** in the dashboard instead of polling, once there's
  a concrete reason polling's simplicity stops being the right tradeoff.
- **A CSP nonce pipeline** for Next.js's inline bootstrap script, replacing
  the current `'unsafe-inline'` allowance — blocked upstream on Next.js not
  yet supporting per-request nonces on statically prerendered pages.
- **Interactive Slack Block Kit UI** for the `/zentra check` command, beyond
  the current plain-text response.

## Documentation

| Document | Contents |
| --- | --- |
| [docs/architecture.md](docs/architecture.md) | System design, tenancy, security boundaries |
| [docs/scanning-engine.md](docs/scanning-engine.md) | Scanner contract, providers, SSRF protection |
| [docs/risk-scoring.md](docs/risk-scoring.md) | The complete scoring methodology |
| [docs/api.md](docs/api.md) | REST API reference |
| [SECURITY.md](SECURITY.md) | Security policy and responsible disclosure |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to work on Zentra |

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
development setup (no external API credentials required — the default
configuration runs entirely on deterministic offline providers), coding
standards, and what CI checks before a pull request can merge.

## Licence

MIT — see [LICENSE](LICENSE).
