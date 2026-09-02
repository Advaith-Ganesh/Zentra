# Zentra

**Vendor risk intelligence for UK startups and SMBs.**

Zentra continuously assesses a company's third-party vendors against security
signals available from public sources, then turns the result into a 0–100 risk
score, a plain-English explanation of the biggest risk, a specific action to
take, and an auditor-friendly vendor risk register.

The product exists to answer three questions per vendor, for someone who is not
a security analyst:

- What is wrong?
- How serious is it?
- What should I do?

---

## Contents

- [What Zentra is not](#what-zentra-is-not)
- [Architecture](#architecture)
- [Local setup](#local-setup)
- [Running the stack](#running-the-stack)
- [Environment variables](#environment-variables)
- [External accounts and API keys](#external-accounts-and-api-keys)
- [Database and migrations](#database-and-migrations)
- [Testing](#testing)
- [Code quality](#code-quality)
- [Deployment](#deployment)
- [Troubleshooting](#troubleshooting)
- [Known limitations](#known-limitations)
- [Documentation](#documentation)

---

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

## Architecture

| Layer | Technology |
| --- | --- |
| Frontend | Next.js 16 (App Router), React 19, TypeScript, Tailwind CSS, Recharts, Zod |
| API | Python 3.11, FastAPI, Pydantic v2, SQLAlchemy 2 |
| Worker | Celery + Redis |
| Database | PostgreSQL (Supabase in production), with Row Level Security |
| Auth | Supabase Auth in production; a real local email/password provider for development |
| Payments | Stripe Checkout, Customer Portal and webhooks |
| PDF | WeasyPrint |
| Email | Resend-compatible abstraction, with a console provider for development |

See [docs/architecture.md](docs/architecture.md) for the full picture,
[docs/scanning-engine.md](docs/scanning-engine.md) for the scanner design, and
[docs/risk-scoring.md](docs/risk-scoring.md) for the complete scoring
methodology.

```
apps/web       Next.js browser application
apps/api       FastAPI service, scanning engine, scoring engine, Celery worker
workers/       Worker entry point documentation (the worker ships in the API image)
supabase/      Ordered SQL migrations — the single source of truth for schema
infrastructure Dockerfiles, Railway and Vercel configuration
docs/          Architecture, scanning engine, risk scoring, API reference
scripts/       Helper scripts
```

## Local setup

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

## Running the stack

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

## Testing

```bash
make test          # everything
make test-api      # 410 backend tests
make test-web      # 49 frontend tests
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

## Documentation

| Document | Contents |
| --- | --- |
| [docs/architecture.md](docs/architecture.md) | System design, tenancy, security boundaries |
| [docs/scanning-engine.md](docs/scanning-engine.md) | Scanner contract, providers, SSRF protection |
| [docs/risk-scoring.md](docs/risk-scoring.md) | The complete scoring methodology |
| [docs/api.md](docs/api.md) | REST API reference |
| [SECURITY.md](SECURITY.md) | Security policy and responsible disclosure |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to work on Zentra |

## Licence

Proprietary. All rights reserved.
