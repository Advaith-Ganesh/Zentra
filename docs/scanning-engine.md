# The scanning engine

Zentra collects security signals about domains its customers nominate. This
document describes how that works, what the guarantees are, and how to add a
provider.

The code is in `apps/api/zentra/scanners/`.

---

## 1. What Zentra will and will not do

**Passive checks against publicly available sources only.**

Zentra reads public DNS records, completes a TLS handshake, reads HTTP response
headers, and queries third-party indexes of already-published information. It
does not attempt authentication, does not exploit anything, does not brute
force, and does not perform intrusive testing against any system. There is no
configuration option that changes this — the limits are structural, not
policy.

When Shodan reports an open Redis port, Zentra records that Shodan reported it.
Zentra does not connect to that port.

## 2. The contract

Every signal is produced by a `BaseScanner` subclass and returned as one or more
`CheckResult` objects. That normalized shape is what the scoring engine, the
findings generator and the PDF renderer all consume, so adding a provider never
requires touching any of them.

```python
@dataclass
class CheckResult:
    check_type: CheckType      # stable identifier, e.g. TLS_CERTIFICATE
    status: CheckStatus        # pass | warn | fail | unknown | error
    severity: Severity         # info | low | medium | high | critical
    summary: str               # one plain-English sentence
    source: str                # which provider produced this
    details: dict              # structured, check-specific
    evidence: list[Evidence]   # supporting values, each with provenance
    confidence: float          # 0.0–1.0
    provider_status: str       # ok | rate_limited | not_configured | …
    checked_at: datetime
    recommendation: str | None # what to ask the vendor
    title: str | None          # short label for a tracked finding
```

### The invariant that matters most

> A provider failure produces `error` or `unknown` — never `fail`.

An outage is missing information, not evidence of a security weakness. This is
enforced structurally rather than by convention: `CheckResult.__post_init__`
forces the severity of any `error` or `unknown` result down to `info` before it
can reach the scorer. A misbehaving scanner cannot smuggle risk in through a
failed provider.

The five statuses:

| Status | Meaning |
| --- | --- |
| `pass` | Assessed, no problem found |
| `warn` | Assessed, something worth improving |
| `fail` | Assessed, a real problem |
| `unknown` | The check ran and could not conclude. Contributes no risk |
| `error` | The provider could not be reached. Contributes no risk, reduces coverage |

## 3. Provider abstraction

Each scanner talks to a **provider**, and each provider has a real
implementation and a deterministic mock. Providers return a `ProviderResult`
rather than raising for the ordinary "no answer" cases:

```python
class ProviderStatus(StrEnum):
    OK              # got an answer
    NOT_FOUND       # a definite negative: the provider has no record
    RATE_LIMITED    # reachable but declined
    NOT_CONFIGURED  # no credential in this environment
    UNAVAILABLE     # network error, timeout, 5xx, malformed response
    INVALID_TARGET  # the provider rejected the target
```

`NOT_FOUND` and `OK` are conclusive; everything else is not. That distinction is
the whole reason the enum exists: "HIBP has no breach for this domain" and "HIBP
was down" must never collapse into the same outcome.

Selecting a provider is one function:

```python
def get_breach_provider() -> BreachProvider:
    return MockBreachProvider() if get_settings().use_mock_scanners else HibpProvider()
```

With `USE_MOCK_SCANNERS=true` the entire product works end to end with no
external credentials. Mock results are derived from a SHA-256 hash of the
domain, so a given domain always produces the same outcome — repeatable tests
and a coherent demo. Mock sources are labelled `(synthetic demo data)`
everywhere they surface.

## 4. The scanners

| Scanner | Provider (real) | Emits | In free scan |
| --- | --- | --- | --- |
| `SSLScanner` | Qualys SSL Labs API v3 | `tls_certificate`, `tls_configuration` | yes |
| `DNSScanner` | dnspython against public resolvers | `dns_spf`, `dns_dmarc`, `dns_dkim`, `dns_caa` | yes |
| `HIBPScanner` | Have I Been Pwned API v3 | `breach_history` | yes |
| `TechnologyScanner` | HTTP response headers | `technology_stack`, `http_security_headers` | yes |
| `ShodanScanner` | Shodan host API | `internet_exposure` | no |
| `CVEScanner` | NIST NVD REST API 2.0 | `cve_exposure` | no |

### SSL Labs

An asynchronous job API: submit a host, poll until `READY`. Zentra polls with
exponential backoff, honours the documented cool-off responses (503/529), gives
up cleanly inside a fixed budget, and reports `UNAVAILABLE` rather than guessing.
It reports the *worst* grade across endpoints, and decodes the certificate
`issues` bit field into named problems.

### DNS — and being honest about DKIM

SPF, DMARC and CAA are read directly. DKIM is different, and this is the clearest
example of Zentra's approach to uncertainty:

> **There is no DNS record that enumerates a domain's DKIM selectors.**

Zentra probes a short list of selectors used by common mail platforms. If none
matches, the result is `unknown` with confidence 0.0 and a summary that says so
explicitly:

> "DKIM could not be assessed. DKIM keys are published under a selector name
> that cannot be discovered from DNS, so absence here does not mean DKIM is
> missing."

Reporting that as "DKIM missing" would be a fabricated finding. It contributes
no risk points.

### Have I Been Pwned

Uses `/breaches?domain=`, which returns breach *metadata* only. The paid
`/breacheddomain/{domain}` endpoint — which exposes affected local-parts — is
deliberately **not** implemented: it is far more personal data than a vendor risk
score requires. Zentra stores the breach name, date, account count and data
categories, and nothing else. HTTP 404 from this endpoint means "no catalogued
breach", which is a conclusive negative; a timeout is not.

### Shodan

Reads the passive host record for the domain's resolved address. Zentra
classifies ports into ordinary web services, sensitive services (SSH, SMTP,
RDP…) and critical exposures (databases, unauthenticated caches, Docker APIs).
No connection is ever made to a discovered service.

### CVE / technology

The technology scanner reads only what a server volunteers in its own response
headers. A version is recorded **only** when the server states it explicitly;
nothing is inferred from a fingerprint.

The CVE scanner then queries NVD by CPE — but only for technologies with a
stated version. A technology with no version is recorded in
`technologies_skipped_unknown_version` and produces no CVE claim at all.

> **Unknown is not vulnerable.**

Matched CVEs carry confidence 0.7, not 1.0, and the recommendation says why: a
disclosed version matching a CVE is an indicator, not proof — the vendor may
have backported the fix.

## 5. SSRF protection

This is the most security-critical code in Zentra, because an unauthenticated
user can name any domain and cause an outbound request. It lives in
`scanners/net/ssrf.py`.

**Layer 1 — domain validation** (`core/domains.py`). Runs before anything
touches the network. Rejects IP literals, embedded credentials, ports, paths,
control characters, oversized input, and any name under a reserved or internal
suffix (`.local`, `.internal`, `.lan`, `.test`, `.onion`, `.in-addr.arpa`, …) or
matching a known internal hostname (`localhost`, `metadata.google.internal`,
`host.docker.internal`, …). Unicode is normalized to punycode with UTS-46 so
homoglyph tricks resolve to the same string the checks see.

**Layer 2 — resolution, fail-closed.** The name is resolved once, and **every**
returned A/AAAA record is checked against loopback, RFC1918, CGNAT, link-local,
cloud-metadata, multicast, reserved and IPv6-equivalent ranges — including
IPv4-mapped (`::ffff:10.0.0.1`) and 6to4-encapsulated (`2002:a00:1::`) forms.

If *any* record points at non-public space, the whole target is rejected. That
fail-closed behaviour is what defeats a round-robin "one public, one private"
record set: an attacker cannot get the public answer accepted and then win a
race on a later lookup.

**Layer 3 — connection pinning.** The validated address is used for the actual
connection, with the original hostname passed for SNI and the `Host` header. The
resolver is never consulted a second time, which closes the TOCTOU window a
classic DNS-rebinding attack depends on.

**Layer 4 — request constraints.** http/https only, ports 80/443 only, no
automatic redirects (each hop is re-validated through the whole path above,
bounded to three), a response size cap and a hard timeout.

`tests/test_ssrf.py` asserts every blocked range individually, the fail-closed
mixed-record behaviour, and that a blocked name never reaches the resolver at
all.

## 6. Orchestration

```
run_scan(domain)
  ├─ normalize + validate the domain          (last gate before any network I/O)
  ├─ pass 1: SSL · DNS · HIBP · exposure · technology   (asyncio.gather)
  ├─ extract technology versions and referenced CVE IDs
  ├─ pass 2: CVE lookup                        (depends on pass 1)
  ├─ calculate_score(results)
  └─ build_verdict(score, results)
```

Two passes, because CVE lookup needs technology signals. Nothing else is
sequential.

Every scanner runs under `BaseScanner.execute`, which adds timing, a per-scanner
hard timeout, bounded retries with exponential backoff for transient failures,
and a guaranteed-normalized error result. Non-retryable failures — a rejected
target, a malformed domain — are never retried. The whole scan additionally runs
under a total wall-clock budget.

A scan whose scanners all errored is `failed`. A scan where some succeeded is
`partial`, and that status is shown to the customer rather than hidden.

## 7. Scan lifecycle

```
User adds a vendor
   → scan row created (queued)          ← the HTTP request ends here
   → Celery task dispatched
   → worker: status=running
   → scanners run, results normalized
   → score calculated, verdict written
   → scan_results persisted with provenance
   → findings synced (new / refreshed / auto-resolved)
   → previous score compared; alert raised if the change is material
   → vendor's current position updated; next scan scheduled
```

Scans never run inside an HTTP request. The API returns a `queued` scan and the
client polls — no websockets, because a few seconds of polling does not justify
the infrastructure.

Failure handling:

- **Idempotent.** A redelivered Celery message finds the scan already terminal
  and returns.
- **Deduplicated.** A double-clicked "Scan now" returns the in-flight scan
  rather than costing a second provider quota.
- **Reaped.** A scan left `running` for more than 30 minutes is failed by a
  scheduled task, so a lost worker never silently swallows a job.
- **Non-destructive.** An inconclusive or failed scan never overwrites a
  vendor's previous good score.

## 8. Adding a provider

1. Define the normalized data class and a provider interface in
   `scanners/<name>/provider.py`.
2. Implement the real provider. Return `ProviderResult` for expected failures;
   raise only for genuine bugs.
3. Implement a deterministic mock seeded from the domain, with a `SCRIPTED`
   dict so tests and the seeder can force a scenario.
4. Write the scanner in `scanners/<name>/scanner.py`, mapping provider output
   to `CheckResult`. Be explicit about which outcomes are `unknown` versus
   `fail`.
5. Register it in `scanners/registry.py`.
6. Map its check types to a scoring category in `scoring/config.py`, and adjust
   the weights so they still total 100.
7. Add tests, including the provider-unavailable path.

If the new provider needs a credential, add the setting to `config.py` and
`.env.example`, and make sure the scanner returns `not_configured` (`unknown`)
rather than failing when the key is absent.
