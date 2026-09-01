# Risk scoring methodology

This document is the specification for Zentra's risk score. It is deliberately
complete enough that a customer, an auditor or a competitor could reimplement
it. There is nothing proprietary in the weights, and a customer who asks "why
did this vendor get 72?" deserves an answer that does not require reading
source code.

The implementation lives in `apps/api/zentra/scoring/`. Every constant in this
document is defined in `scoring/config.py` and nowhere else.

---

## 1. The score

A vendor's risk score runs from **0 to 100**, where a **higher score means more
observed risk**. This is the opposite orientation to a credit score, and the UI
says so wherever the number appears.

| Score | Risk level |
| --- | --- |
| 0–24 | Low |
| 25–49 | Medium |
| 50–74 | High |
| 75–100 | Critical |

The thresholds are in `RISK_THRESHOLDS`. Changing them changes every vendor's
displayed level, so treat it as a product decision, not a tuning knob.

## 2. Design constraints

The model was built to satisfy five properties, in this order of priority:

1. **Deterministic.** The same normalized inputs always produce the same score.
   There is no model, no inference and no randomness anywhere in the path.
2. **Explainable.** Every point is attributable to a named category and a named
   check. The API returns the full breakdown; the UI renders it.
3. **A provider failure is not risk.** If a data source is unreachable, that is
   missing information. It contributes zero risk points.
4. **An inconclusive answer is not risk.** If a check ran but could not
   conclude — DKIM without a discoverable selector, a technology with no stated
   version — that contributes zero risk points.
5. **Thin coverage is never a clean bill of health.** A scan that could only
   complete a third of its checks must not be presented as "Low risk".

## 3. Categories and weights

Normalized check results roll up into six categories that total exactly 100
points.

| Category | Points | Checks it covers |
| --- | --- | --- |
| TLS / certificate | 25 | `tls_certificate`, `tls_configuration` |
| Breach history | 20 | `breach_history` |
| Internet exposure | 20 | `internet_exposure` |
| Known vulnerabilities | 15 | `cve_exposure` |
| Email / DNS security | 15 | `dns_spf`, `dns_dmarc`, `dns_dkim`, `dns_caa` |
| Web hardening | 5 | `technology_stack`, `http_security_headers` |

The weighting reflects how much a signal actually tells you about a vendor from
outside:

- **TLS is highest** because it is directly observable, unambiguous, and a
  failure is both serious and immediately actionable.
- **Breach history and internet exposure** are high because they describe
  demonstrated outcomes and current attack surface, not configuration
  preferences.
- **CVE exposure is mid-weight** because a version match is an indicator, not
  proof: vendors backport fixes without changing a banner.
- **Email/DNS security is mid-weight.** Missing SPF or DMARC is a genuine
  phishing risk to *your* staff, but it says less about the vendor's ability to
  protect your data.
- **Web hardening is lowest** because missing browser headers are real but
  low-consequence, and are the easiest signal to over-weight.

## 4. How points are assigned

For each category, Zentra takes the conclusive results (`pass`, `warn`, `fail`)
and processes only the problems (`warn` and `fail` with a severity above
`info`), worst-first:

```
points_for_check = category_max
                 × severity_impact[severity]
                 × (0.6 if status is WARN else 1.0)
                 × confidence
                 × decay ^ position_in_category
```

with

| Severity | Impact fraction |
| --- | --- |
| Critical | 1.00 |
| High | 0.72 |
| Medium | 0.40 |
| Low | 0.16 |
| Info | 0.00 |

and `decay = 0.45`.

The **decay** is what stops a single noisy category from swamping the score. If
a vendor fails all four DNS checks, the second contributes 45% of what it
otherwise would, the third 20%, the fourth 9%. A category's total is then capped
at its own maximum, so DNS can never contribute more than 15 points however many
DNS problems exist.

The **confidence multiplier** means a low-confidence signal moves the score less
than a high-confidence one. Below `MIN_CONTRIBUTING_CONFIDENCE` (0.25) a finding
contributes **zero** points — it is still shown to the user, but flagged as
below the threshold and excluded from the arithmetic.

## 5. Severity floors

The weighted sum alone under-states a single decisive problem. No category is
worth more than 25 points, so an expired TLS certificate — an unambiguous,
serious, customer-visible failure — could only ever reach "Medium" on the sum.
That is wrong.

Zentra therefore applies a **floor**: a conclusive finding of a given severity
sets a minimum score.

| Severity | One such finding | Two or more |
| --- | --- | --- |
| Critical | 50 (High) | 75 (Critical) |
| High | 25 (Medium) | 50 (High) |

Floors only apply to findings that are conclusive **and** carry confidence of at
least 0.5, so a provider outage or a speculative signal can never trigger one.
When a floor is applied, the API returns both `base_score` (the weighted sum)
and the `applied_floor` object explaining the jump, and the UI shows that
explanation under the breakdown.

## 6. Coverage, confidence and the refusal to guess

**Coverage** is the fraction of the weighted check surface that produced a
conclusive result:

```
coverage = Σ max_points(assessed categories) / 100
```

Unassessed weight is treated as *unknown*, not as safe and not as risk. Zentra
adds a small, bounded **uncertainty adjustment** so a thin scan cannot present
as a confident clean result:

```
uncertainty = (1 − coverage) × 12, capped at 12 points
```

Twelve points is deliberately modest. It is enough to move a sparse scan out of
a confident "Low", and far too small to manufacture a "Critical" out of missing
data.

**Confidence** blends per-check confidence with coverage:

```
confidence = mean(confidence of assessed categories) × (0.4 + 0.6 × coverage)
```

A highly confident check set that only covers a third of the categories is still
a low-confidence overall assessment, and is reported as one.

**When Zentra declines to score at all.** If fewer than two categories produced
a conclusive result, *or* coverage falls below 0.4, the scan is marked
inconclusive: `score` and `risk_level` come back as `null`, the vendor's stored
score is left untouched, and the UI says "Assessment incomplete. That is not an
indication that it is low risk." Publishing an unreliable number would be worse
than publishing none.

## 7. Normalized check results

Every scanner emits the same structure, whatever provider produced it:

| Field | Meaning |
| --- | --- |
| `check_type` | Stable identifier, e.g. `tls_certificate` |
| `status` | `pass` / `warn` / `fail` / `unknown` / `error` |
| `severity` | `info` / `low` / `medium` / `high` / `critical` |
| `summary` | One plain-English sentence |
| `details` | Structured, check-specific data |
| `evidence` | Supporting values, each with its own source and timestamp |
| `source` | Which provider produced this |
| `confidence` | 0.0–1.0 |
| `checked_at` | When it was observed |

The five statuses carry the load of the whole design:

- **`pass`** — assessed, and no problem found.
- **`warn`** — assessed, something worth improving.
- **`fail`** — assessed, a real problem.
- **`unknown`** — the check ran and reached no conclusion. Contributes nothing.
  Example: DKIM, whose selector names are not discoverable from DNS.
- **`error`** — the provider could not be reached or returned something
  unusable. Contributes nothing, and reduces coverage.

`CheckResult.__post_init__` enforces this structurally: an `error` or `unknown`
result has its severity forced to `info` before it can reach the scorer. A
misbehaving scanner cannot smuggle risk in through a failed provider.

## 8. Worked example

A vendor with an expired certificate, a weak TLS configuration, no DMARC record
and two missing security headers, where the exposure provider was unavailable:

| Category | Result | Points |
| --- | --- | --- |
| TLS / certificate | Certificate expired (critical, conf 1.0) → 25 × 1.00 × 1.0 × 1.0 = 25.0; configuration high, second in category → 25 × 0.72 × 1.0 × 0.45 = 8.1; capped | **25.0 / 25** |
| Breach history | No catalogued breach (pass) | 0.0 / 20 |
| Internet exposure | Provider unavailable | not assessed |
| Known vulnerabilities | No version disclosed | not assessed |
| Email / DNS security | No DMARC (medium, conf 1.0) → 15 × 0.40 = 6.0 | 6.0 / 15 |
| Web hardening | Missing headers (medium, warn, conf 0.9) → 5 × 0.40 × 0.6 × 0.9 = 1.1 | 1.1 / 5 |

- Weighted sum: 32.1
- Coverage: (25 + 20 + 15 + 5) / 100 = 0.65
- Uncertainty: (1 − 0.65) × 12 = 4.2
- Base score: 36
- Floor: one critical finding → minimum 50
- **Final score: 50 — High risk**

The verdict names the expired certificate as the biggest risk, explains that
certificate problems break trust and often precede an outage, gives the vendor
the specific remediation to request, and states that the assessment covers 65%
of Zentra's checks because the exposure provider was unavailable.

## 9. Plain-English verdicts

Every scored scan produces a verdict answering three questions: what is the
biggest risk, why does it matter, and what should you do next. The language
rules are enforced in code and in tests:

- Never assert that a vendor "is insecure", "is safe", or is definitively
  anything. Zentra observes signals; it does not audit vendors.
- Never make a legal, regulatory or certification claim.
- Always state when the assessment is incomplete, and always add that
  incompleteness is not evidence of safety.
- Every verdict carries the standard disclaimer.

`tests/test_scoring.py` asserts the absence of the forbidden phrasings, so a
future change to the wording cannot quietly reintroduce an overclaim.

## 10. Changing the model

The scoring version is recorded on every scan (`scoring_version`, currently
`1.0.0`). If you change weights, thresholds or floors:

1. Change them only in `scoring/config.py`.
2. Bump `ScoringConfig.version`.
3. Update the deterministic scenarios in `tests/test_scoring.py` — they exist
   precisely so a weight change cannot pass unnoticed.
4. Update this document and the methodology section of the PDF report.

Historical scans keep the score they were given, and record the version that
produced it.
