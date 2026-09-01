# Zentra API reference

Base URL: `https://api.zentra.example` (locally `http://localhost:8000`).

Interactive documentation is served at `/docs` outside production. The machine-
readable schema is always at `/openapi.json`, and a generated copy lives at
`docs/openapi.json` (`make openapi` regenerates it).

---

## Authentication

Two schemes.

**Session token** — used by the Zentra dashboard.

```http
Authorization: Bearer <access_token>
```

Obtain one from `POST /api/v1/auth/signin`. Tokens are short-lived (one hour by
default).

**API key** — available on the Scale plan.

```http
X-API-Key: zk_live_...
```

Create keys at `POST /api/v1/api-keys`. The secret is returned exactly once;
Zentra stores only a SHA-256 hash and cannot show it again. Keys carry scopes
(`vendors:read`, `vendors:write`, `scans:write`, `reports:read`,
`findings:write`) and can be given an expiry.

**Choosing an organization.** If your account belongs to more than one
organization, send:

```http
X-Zentra-Organization: <organization-uuid>
```

Without it, your first organization is used. Naming an organization you are not
a member of returns `403`.

## Errors

Every error uses one envelope:

```json
{
  "error": {
    "code": "VENDOR_NOT_FOUND",
    "message": "Vendor could not be found.",
    "details": { "…": "…" },
    "request_id": "8f0c4a1b2e3d4f5a6b7c8d9e0f1a2b3c"
  }
}
```

`request_id` is also returned as the `X-Request-ID` response header and appears
on every server log line for that request. Quote it when contacting support.

| Status | Meaning |
| --- | --- |
| 400 | Malformed request, or an unsafe scan target |
| 401 | Missing, invalid or expired credentials |
| 402 | Your plan does not include this |
| 403 | Authenticated, but not permitted |
| 404 | Not found — also returned for another organization's resources |
| 409 | Conflict, e.g. a duplicate vendor domain |
| 413 | Request body too large |
| 422 | Validation failed; `details.fields` names the problems |
| 429 | Rate limited; see `Retry-After` |
| 500 | Server error. The `request_id` identifies it in our logs |
| 502 | An upstream security data provider is unavailable |
| 503 | A required dependency is unavailable |

Stack traces are never returned.

## Rate limits

| Surface | Default |
| --- | --- |
| Public free scan | 3 per hour per requester, 10 per hour per target domain |
| Authentication | 10 per 15 minutes, per IP **and** per account |
| Manual scan triggers | 20 per hour per organization |
| Report generation | 10 per hour per organization |
| API — Growth | 60 requests per minute |
| API — Scale | 300 requests per minute |

Responses carry `X-RateLimit-Limit` and `X-RateLimit-Remaining`; a `429` carries
`Retry-After`.

---

## Endpoints

### Authentication

| Method | Path | Notes |
| --- | --- | --- |
| `POST` | `/api/v1/auth/signup` | Creates the user, their organization, and an owner membership |
| `POST` | `/api/v1/auth/signin` | Returns an access token |
| `POST` | `/api/v1/auth/signout` | Records the sign-out |
| `POST` | `/api/v1/auth/password-reset` | Always returns the same response, whether or not the account exists |
| `POST` | `/api/v1/auth/accept-invite` | Joins an organization from an invitation token |

```bash
curl -X POST https://api.zentra.example/api/v1/auth/signup \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "founder@acme.co.uk",
    "password": "a-long-passphrase-you-chose",
    "full_name": "Ada Lovelace",
    "organization_name": "Acme Fintech",
    "industry": "Fintech",
    "company_size": "10-50"
  }'
```

Passwords must be at least 12 characters and combine three of: lowercase,
uppercase, digits, symbols.

### Account and organization

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/v1/me` | User, organization, role, entitlements, feature flags |
| `GET` | `/api/v1/dashboard` | Summary counters, vendors needing attention, recent alerts and scans |
| `GET` `PATCH` | `/api/v1/organization` | |
| `PUT` | `/api/v1/organization/branding` | White-label branding (Scale) |
| `POST` | `/api/v1/organization/branding/logo` | Logo upload; validated by file signature |
| `GET` | `/api/v1/organization/members` | |
| `POST` | `/api/v1/organization/members/invite` | Admin only |
| `DELETE` | `/api/v1/organization/members/{id}` | Admin only |

### Vendors

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/v1/vendors` | `search`, `status`, `risk_level`, `criticality`, `sort`, `direction`, `limit`, `offset` |
| `POST` | `/api/v1/vendors` | Creates the vendor and queues its first scan |
| `GET` `PATCH` | `/api/v1/vendors/{id}` | |
| `DELETE` | `/api/v1/vendors/{id}` | Admin only |
| `POST` | `/api/v1/vendors/{id}/archive` | |
| `GET` | `/api/v1/vendors/{id}/score` | Score, breakdown, verdict and history |
| `GET` | `/api/v1/vendors/{id}/scans` | |
| `POST` | `/api/v1/vendors/{id}/scan` | Queues a scan; returns `202` |
| `GET` | `/api/v1/vendors/{id}/findings` | |

```bash
curl -X POST https://api.zentra.example/api/v1/vendors \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name": "Stripe", "domain": "stripe.com", "criticality": "critical"}'
```

Domains are normalized (lowercased, punycode, scheme and path stripped) and
validated. IP addresses, internal hostnames and reserved suffixes are rejected
with `422`. A domain is unique per organization, not globally.

### Scans

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/v1/scans/{id}` | The scan with all normalized check results |

Scans are asynchronous. Poll until `status` is `completed`, `partial` or
`failed`.

- `completed` — every scanner produced a conclusive result.
- `partial` — at least one provider was unavailable. `coverage` and `confidence`
  say how much was assessed.
- `failed` — the scan could not run. `error_message` is customer-safe.

`score` and `risk_level` are `null` when coverage was too thin to publish a risk
level. That is not an indication of low risk, and the verdict says so.

### Findings

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/v1/findings` | Across all vendors; filter by `status` and `severity` |
| `PATCH` | `/api/v1/findings/{id}` | Status, note, assignee |
| `GET` | `/api/v1/findings/{id}/history` | Immutable status history |

Statuses: `open`, `in_progress`, `resolved`, `accepted_risk`. A finding that
stops appearing in a completed scan is auto-resolved, unless someone has marked
it accepted-risk.

### Reports

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/v1/reports` | |
| `POST` | `/api/v1/reports` | Queues generation; returns `202`. Growth plan or a report pack |
| `GET` | `/api/v1/reports/{id}` | Poll until `status` is `completed` |
| `GET` | `/api/v1/reports/{id}/download` | The PDF |

Pass `idempotency_key` to make retries safe.

### Alerts

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/v1/alerts` | |
| `POST` | `/api/v1/alerts/{id}/acknowledge` | |

### Billing

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/v1/billing` | Plan, status, entitlements, available plans |
| `POST` | `/api/v1/billing/checkout` | Stripe Checkout session. Admin only |
| `POST` | `/api/v1/billing/portal` | Stripe Customer Portal. Admin only |

Entitlements are always derived server-side from the subscription record.

### API keys

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/v1/api-keys` | Metadata only; the secret is never returned again |
| `POST` | `/api/v1/api-keys` | Scale plan. The response contains the only copy of the secret |
| `DELETE` | `/api/v1/api-keys/{id}` | Revokes immediately |

### Public API (API key)

The stable integration surface for Scale customers. These require an API key —
a session token returns `403 API_KEY_REQUIRED`.

| Method | Path | Scope |
| --- | --- | --- |
| `GET` | `/api/v1/public/vendors` | `vendors:read` |
| `POST` | `/api/v1/public/vendors` | `vendors:write` |
| `POST` | `/api/v1/public/vendors/{id}/scan` | `scans:write` |
| `GET` | `/api/v1/public/vendors/{id}/report` | `reports:read` |

```bash
curl https://api.zentra.example/api/v1/public/vendors \
  -H "X-API-Key: $ZENTRA_API_KEY"
```

### Free scan (no authentication)

| Method | Path | Notes |
| --- | --- | --- |
| `POST` | `/api/v1/public/scan` | Reduced check set, heavily rate limited |

```bash
curl -X POST https://api.zentra.example/api/v1/public/scan \
  -H 'Content-Type: application/json' \
  -d '{"domain": "example.com"}'
```

The response is deliberately redacted: no evidence, no provider names, no
infrastructure detail. Enough to show value, not enough to be a reconnaissance
tool.

### Webhooks and integrations

| Method | Path | Notes |
| --- | --- | --- |
| `POST` | `/api/v1/webhooks/stripe` | Signature verified; idempotent |
| `GET` | `/api/v1/integrations` | |
| `POST` `DELETE` | `/api/v1/integrations/teams` | Microsoft webhook URLs only |
| `GET` | `/api/v1/integrations/slack/install-url` | Requires the Slack feature flag |

### System

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/health` | Liveness. Touches no dependency |
| `GET` | `/ready` | Readiness. Verifies Postgres and Redis; `503` when degraded |

---

## Polling a scan

```bash
VENDOR=$(curl -sX POST "$API/api/v1/vendors" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"Stripe","domain":"stripe.com"}' | jq -r .id)

# The initial scan is queued automatically.
SCAN=$(curl -s "$API/api/v1/vendors/$VENDOR/scans" \
  -H "Authorization: Bearer $TOKEN" | jq -r '.[0].id')

until [ "$(curl -s "$API/api/v1/scans/$SCAN" -H "Authorization: Bearer $TOKEN" \
          | jq -r .status)" != "queued" ]; do sleep 2; done

curl -s "$API/api/v1/vendors/$VENDOR/score" -H "Authorization: Bearer $TOKEN" | jq
```

## A note on interpreting results

Zentra's scores are informational assessments based on signals from publicly
available sources. They are not an audit of a vendor and are not legal,
regulatory or certification advice. Treat a low score as "no signals of elevated
risk were detected", not as "this vendor is secure".
