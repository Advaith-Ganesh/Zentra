# Contributing to Zentra

## Getting set up

```bash
make setup        # virtualenv, dependencies, and a .env with generated secrets
make services     # Postgres and Redis in Docker
make migrate
make seed
```

Then `make dev-api`, `make dev-worker` and `make dev-web`. `make help` lists
every command.

You do not need any external API credentials. The default configuration uses
deterministic offline providers and local authentication, and the whole product
works end to end.

## Before you open a pull request

```bash
make check        # lint, typecheck, tests, build — the same set CI runs
```

CI additionally runs `bandit`, `pip-audit`, `npm audit`, a gitleaks secret scan
and Docker image builds.

## Principles

These are the rules the codebase is built on. A change that breaks one of them
needs a very good argument.

### 1. A provider failure is never a security verdict

If a data source is unreachable, the result is `error` or `unknown` — never
`fail`, and never `pass`. This is enforced structurally in
`CheckResult.__post_init__`, not by convention. Missing information reduces the
scan's coverage and confidence; it does not create or remove risk.

### 2. Unknown is not vulnerable

Zentra does not infer facts it cannot support. If a technology's version is not
disclosed, no CVE claim is made about it. If a DKIM selector cannot be found,
DKIM is "not assessed", not "missing".

### 3. Never overclaim

Zentra observes signals from public sources. It does not audit vendors, does not
certify anything, and does not make anyone compliant with any framework. Read
the language rules in `scoring/verdict.py` before writing customer-facing copy —
`tests/test_scoring.py` asserts the absence of forbidden phrasings, so an
overclaim will fail the build.

### 4. Tenancy is enforced in the query

Never fetch a row and then compare its `organization_id`. Scope in the WHERE
clause:

```python
# Correct
vendor = session.execute(
    select(Vendor).where(Vendor.id == vendor_id, Vendor.organization_id == organization_id)
).scalar_one_or_none()
```

There is no accessor that takes an ID alone. Add a test in
`tests/test_tenant_isolation.py` for any new route that accepts an identifier.

### 5. The backend is the authority

Entitlements, scoring and authorization are computed server-side on every
request. The frontend renders what the API returns; it never recomputes a score
or infers a plan. If you find yourself writing scoring logic in TypeScript, stop.

### 6. Nothing user-supplied reaches the network unvalidated

Any outbound request driven by user input goes through
`zentra.scanners.net.ssrf`. Do not add a bare `httpx.get` on a user-supplied
URL. If you need a new outbound path, extend the guard and add tests to
`tests/test_ssrf.py`.

### 7. Secrets stay out of logs and responses

Add any new sensitive key name to `SENSITIVE_KEYS` in `zentra/logging.py`.
Credentials are hashed or encrypted at rest and are never returned by the API.

## Code style

**Python.** Formatted and linted with `ruff`, type-checked with `mypy`. Comments
explain *why*, not *what* — the code already says what. Public functions carry
docstrings that state their invariants.

**TypeScript.** Strict mode, no `any` (enforced by ESLint). Components stay
presentational; data loading goes through `useAsync`/`useSession`, and all
network calls go through `lib/api.ts`.

Match the surrounding code. If a file is written in a particular way, follow it
rather than introducing a second style.

## Tests

Every feature needs tests, and security-relevant behaviour needs tests that
assert the security property directly.

- **Scanners** — cover the provider-unavailable path, not just the happy one.
- **Scoring** — add a deterministic scenario to `tests/test_scoring.py`.
- **Routes** — cover authentication, authorization and cross-tenant access.
- **Anything touching money** — cover the webhook signature and duplicate
  delivery.

The backend suite runs against real PostgreSQL. Do not introduce SQLite: the
schema depends on native enums, JSONB, CITEXT, arrays and RLS, and a test that
does not exercise those is worth less than no test.

Never disable a failing test to make a build pass. Fix the actual problem.

## Database changes

Schema lives in `supabase/migrations/` as ordered SQL, applied identically to
local Postgres and hosted Supabase. Add a new numbered file — the runner
checksums applied migrations and refuses to run if one has changed.

Every new tenant table needs:

1. An `organization_id` foreign key.
2. RLS enabled **and forced**, with a policy in the same migration.
3. Indexes for the queries you actually run.
4. A matching SQLAlchemy model in `db/models.py`.
5. A row in the RLS test's table list.

## Adding a scanner provider

See [docs/scanning-engine.md](docs/scanning-engine.md#8-adding-a-provider).
Every provider needs a real implementation *and* a deterministic mock, so the
product keeps working with no credentials.

## Commit messages

Explain why the change was needed, not just what changed. One logical change per
commit.

## Reporting a security issue

Do not open a public issue. See [SECURITY.md](SECURITY.md).
