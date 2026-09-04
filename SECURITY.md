# Security policy

Zentra is a security product. How it is built matters as much as what it
reports.

---

## Reporting a vulnerability

Email **security@zentra.example** with enough detail to reproduce the issue:
what you did, what happened, and what you expected. Include a proof of concept
where one helps.

- We aim to acknowledge within **two working days**.
- We will keep you updated until the issue is resolved, and will tell you when a
  fix ships.
- Please give us a reasonable opportunity to fix an issue before disclosing it
  publicly. We are happy to credit you.

We will not pursue legal action against researchers acting in good faith within
the scope below. Please do not access, modify or destroy data that is not yours,
and stop as soon as you have demonstrated an issue.

Do not report vulnerabilities through public GitHub issues.

## Scope

**In scope**

- The Zentra web application and its REST API.
- Authentication, authorization and tenant isolation.
- The scanner's outbound request controls, particularly the SSRF protections.
- Billing and webhook handling.
- The report generation pipeline, including white-label branding input.
- Anything that causes Zentra to make a request it should refuse to make.

**Out of scope**

- Denial of service, volumetric or load testing.
- Social engineering of Zentra staff or customers.
- Findings that require a compromised device or a stolen credential.
- Automated scanner output with no demonstrated impact.
- Missing headers or best practices with no exploitable consequence.
- Third-party services Zentra depends on — report those to their owners.
- Vendor domains Zentra scans. Those belong to other companies; findings about
  them are not Zentra vulnerabilities.

## Supported versions

Zentra is a hosted service. Security fixes are applied to the running production
version. There are no supported self-hosted releases at this time.

| Version | Supported |
| --- | --- |
| Hosted production | Yes |
| `main` | Yes |
| Tagged releases | No — pre-1.0 |

## What Zentra does to protect customer data

- **Passwords** are hashed with Argon2id at OWASP-aligned parameters
  (m=64 MiB, t=3, p=4). Zentra never stores a password in a recoverable form,
  and password verification does constant work whether or not the account
  exists.
- **API keys** are stored only as SHA-256 hashes. The secret is displayed once
  at creation and cannot be recovered afterwards.
- **Integration credentials** (Slack bot tokens, Teams webhook URLs) are
  encrypted at rest with authenticated encryption (Fernet) and are never
  returned by the API.
- **Tenant isolation** is enforced three times over: every service query scopes
  by `organization_id` in the WHERE clause, PostgreSQL Row Level Security is
  enabled *and forced* on every tenant table, and the `authenticated` database
  role has no column grant on any credential column.
- **Cross-tenant reads return 404**, so the API does not confirm that a resource
  exists in another organization.
- **Logs** pass through a redaction processor that strips credentials, tokens,
  authorization headers and breach detail before anything is written.
- **Audit records** capture who did what, to which resource, when, and under
  which request ID.
- **Requester IP addresses** used for abuse prevention are stored only as an
  irreversible salted hash, never in clear text.

## What Zentra does to protect the systems it scans

Zentra accepts arbitrary domains from unauthenticated users and then makes
outbound requests about them. The controls are structural, not policy:

- **Passive checks only.** No authentication attempts, no exploitation, no
  brute force, no intrusive testing — against any system, under any
  configuration. There is no setting that changes this.
- **Domain validation** before any network activity: IP literals, embedded
  credentials, ports, paths, control characters and reserved or internal
  suffixes are all rejected.
- **Fail-closed resolution.** The name is resolved once and every returned
  address is checked against loopback, RFC1918, CGNAT, link-local, cloud
  metadata, multicast and reserved ranges, including IPv4-mapped and
  6to4-encapsulated IPv6 forms. If *any* record points at non-public space, the
  whole target is refused.
- **Connection pinning.** The validated address is used for the connection, with
  the original hostname supplied for SNI and the `Host` header. The resolver is
  never consulted again, which closes the DNS-rebinding window.
- **Redirects** are never followed automatically; each hop is re-validated and
  the hop count is bounded.
- **Protocol constraints.** http and https only, ports 80 and 443 only,
  size-capped responses, hard timeouts.
- **Aggressive rate limiting** on the unauthenticated free scan, per requester
  and per target domain.

## Authorized scanning

By adding a vendor, a customer confirms they have a legitimate business interest
in assessing that organization. Zentra's checks are equivalent to reading public
DNS records and visiting a website, and are not intrusive.

If you believe Zentra has scanned a domain it should not have, email
**abuse@zentra.example** and we will investigate and, where appropriate,
suppress that domain.

Using Zentra for reconnaissance in support of an attack, or as part of
unauthorised security testing, breaches the Acceptable Use Policy and will end
in account termination.

## Known tradeoffs

### Session tokens are held in `localStorage`

The dashboard stores its access token in `localStorage` and sends it as a
`Bearer` header. Anything that can execute JavaScript on the page can read it.

This was chosen because the same API is consumed by two very different clients:
the browser dashboard and server-side API-key integrations. A cookie-based
session would need CSRF protection on every state-changing route and careful
`SameSite` handling for the cross-origin development setup, while doing nothing
for the API-key path.

Compensating controls:

- Short access-token lifetime, with re-authentication rather than a long-lived
  refresh token in the browser.
- A strict Content-Security-Policy (`object-src 'none'`, `base-uri 'none'`,
  `frame-ancestors 'none'`).
- No use of `dangerouslySetInnerHTML` anywhere in the frontend; the ESLint
  config makes `react/no-danger` an error so it cannot be introduced silently.
- React escapes interpolated values by default, and no user-supplied HTML is
  rendered.

The migration path, if the threat model changes, is an `httpOnly` `Secure`
`SameSite=Lax` cookie for the dashboard plus a double-submit CSRF token, keeping
the `X-API-Key` header for machine clients. This is a deliberate, documented
decision rather than an oversight.

## Security practices in development

- Dependencies are pinned exactly and audited in CI (`pip-audit`, `npm audit`).
  A known vulnerability in a production dependency fails the build.
- Static analysis (`bandit`) runs on every pull request; medium and high
  findings fail the build.
- A gitleaks secret scan runs on every pull request.
- Production configuration is validated at process start. A deployment with
  debug enabled, mock scanners on, a weak signing secret, disabled rate limiting
  or a wildcard CORS origin **fails to start**.
- Security-relevant behaviour is covered by tests that assert the security
  property directly, not just the happy path.

## Contact

| Purpose | Address |
| --- | --- |
| Vulnerability reports | security@zentra.example |
| Scanning concerns and abuse | abuse@zentra.example |
| Privacy and data protection | privacy@zentra.example |
