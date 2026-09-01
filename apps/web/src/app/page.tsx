import Link from 'next/link';
import type { Metadata } from 'next';
import { MarketingFooter, MarketingHeader, SectionHeading } from '@/components/marketing';

export const metadata: Metadata = {
  title: 'Vendor risk intelligence for UK startups',
  description:
    'Zentra monitors your third-party vendors against publicly available security signals and gives you a clear risk score, a plain-English explanation and an audit-ready vendor risk register.',
};

const CHECKS = [
  {
    name: 'TLS and certificates',
    weight: '25 points',
    detail:
      'Certificate validity and expiry, protocol versions and cipher strength. The single highest-signal public check.',
  },
  {
    name: 'Breach history',
    weight: '20 points',
    detail:
      'Publicly catalogued breaches associated with the vendor’s domain. Zentra stores breach metadata only — never account-level data.',
  },
  {
    name: 'Internet exposure',
    weight: '20 points',
    detail:
      'Services already visible on the public internet, read from third-party scan data. Zentra never connects to them.',
  },
  {
    name: 'Known vulnerabilities',
    weight: '15 points',
    detail:
      'Published CVEs matched to software versions the vendor’s own servers disclose. Unknown versions are never treated as vulnerable.',
  },
  {
    name: 'Email and DNS security',
    weight: '15 points',
    detail:
      'SPF, DMARC and CAA records, plus DKIM discovery. Zentra reports DKIM honestly: if a selector cannot be found, that is “not assessed”, not “missing”.',
  },
  {
    name: 'Web hardening',
    weight: '5 points',
    detail:
      'Browser security headers on the vendor’s public site. Lowest weight, because it is the lowest-consequence signal.',
  },
];

const STEPS = [
  {
    step: '01',
    title: 'Add your vendors',
    body: 'Enter the companies you already pay — your payment processor, your cloud provider, your CRM. A domain is all Zentra needs.',
  },
  {
    step: '02',
    title: 'Zentra assesses them',
    body: 'Passive checks against publicly available sources run in the background. Nothing is probed, exploited or logged into.',
  },
  {
    step: '03',
    title: 'You get a straight answer',
    body: 'A 0–100 risk score, the biggest risk in one sentence, why it matters, and the specific thing to ask the vendor.',
  },
  {
    step: '04',
    title: 'Zentra keeps watching',
    body: 'Daily rescans. If a vendor’s risk moves materially, you get an alert — not another dashboard to remember to check.',
  },
];

const FAQS = [
  {
    q: 'Does Zentra hack or probe our vendors?',
    a: 'No. Zentra performs passive checks against publicly available sources only: certificate transparency and TLS handshakes, public DNS records, published breach catalogues and third-party internet-scan data. It never attempts authentication, never exploits anything, and never performs intrusive testing.',
  },
  {
    q: 'Will this make us ISO 27001 or SOC 2 compliant?',
    a: 'No, and you should be sceptical of any tool that claims it will. Compliance frameworks require you to operate a third-party risk management process. Zentra gives you the evidence that one is running: a maintained vendor register, dated assessments, tracked remediation and an exportable report. Your auditor decides whether that satisfies a given control.',
  },
  {
    q: 'What happens when a data source is down?',
    a: 'Zentra records the check as “not assessed” and reduces the reported coverage and confidence. It never converts an outage into a security failure, and it never presents a half-completed scan as a clean bill of health. If coverage is too thin to be meaningful, Zentra declines to publish a risk level at all.',
  },
  {
    q: 'How is the score calculated?',
    a: 'Deterministically, from six weighted categories that total 100 points. Every scan shows exactly which category contributed which points and why. There is no model and no black box — the same inputs always produce the same score.',
  },
  {
    q: 'Do we need a security person to use it?',
    a: 'No. That is the point. Every finding says what is wrong, how serious it is and what to ask the vendor, in ordinary English. The technical detail is there if you want it, behind a tooltip.',
  },
  {
    q: 'Can we cancel?',
    a: 'Yes, at any time from the billing portal. Your data remains exportable for the remainder of your billing period.',
  },
];

const PLANS = [
  {
    name: 'Starter',
    price: '£29',
    cadence: '/month',
    summary: 'For a small team getting its vendor list under control.',
    features: ['10 vendors', 'Daily risk scores', 'Full security check set', 'Monthly summary email'],
    cta: 'Start with Starter',
    highlighted: false,
  },
  {
    name: 'Growth',
    price: '£79',
    cadence: '/month',
    summary: 'For teams who need evidence for customers and auditors.',
    features: [
      '50 vendors',
      'Continuous monitoring',
      'Risk-change alerts',
      'PDF vendor risk register',
      'Remediation tracking',
      'Up to 10 users',
    ],
    cta: 'Start with Growth',
    highlighted: true,
  },
  {
    name: 'Scale',
    price: '£249',
    cadence: '/month',
    summary: 'For larger vendor estates and teams that want to automate.',
    features: [
      'Unlimited vendors',
      'REST API and API keys',
      'White-label reports',
      'Unlimited users',
      'Slack and Teams alerts',
      'Benchmarking',
    ],
    cta: 'Start with Scale',
    highlighted: false,
  },
];

export default function LandingPage() {
  return (
    <>
      <MarketingHeader />
      <main id="main">
        {/* ---------------------------------------------------------- hero */}
        <section className="relative overflow-hidden border-b border-ink-800">
          <div aria-hidden="true" className="surface-grid absolute inset-0 opacity-40" />
          <div
            aria-hidden="true"
            className="absolute inset-x-0 top-0 h-64 bg-gradient-to-b from-ink-900/60 to-transparent"
          />
          <div className="relative mx-auto max-w-6xl px-6 py-20 sm:py-28">
            <p className="text-2xs font-semibold uppercase tracking-governance text-silver-500">
              Third-party risk management
            </p>
            <h1 className="mt-5 max-w-3xl text-4xl font-semibold leading-[1.1] tracking-tight text-silver-50 sm:text-5xl lg:text-6xl">
              Know which of your vendors is a security problem.
              <span className="block text-silver-400">Without hiring a security analyst.</span>
            </h1>
            <p className="mt-6 max-w-2xl text-base leading-relaxed text-silver-400">
              Zentra continuously assesses your third-party vendors against publicly available
              security signals, then tells you in plain English what is wrong, how serious it is,
              and what to ask the vendor.
            </p>
            <div className="mt-9 flex flex-col gap-3 sm:flex-row">
              <Link
                href="/scan"
                className="inline-flex h-12 items-center justify-center rounded-sm bg-silver-50 px-7 text-sm font-medium text-ink-950 transition-colors hover:bg-white"
              >
                Scan your first vendor free
              </Link>
              <a
                href="#pricing"
                className="inline-flex h-12 items-center justify-center rounded-sm border border-silver-500/40 px-7 text-sm font-medium text-silver-100 transition-colors hover:border-silver-400 hover:bg-ink-900"
              >
                See pricing
              </a>
            </div>
            <p className="mt-4 text-xs text-silver-600">
              No account needed for the free scan. No credit card.
            </p>

            <dl className="mt-16 grid max-w-3xl grid-cols-2 gap-x-8 gap-y-6 border-t border-ink-800 pt-8 sm:grid-cols-4">
              {[
                ['0–100', 'Explainable risk score'],
                ['6', 'Weighted check categories'],
                ['Daily', 'Automatic rescans'],
                ['1 click', 'Audit-ready PDF register'],
              ].map(([value, label]) => (
                <div key={label}>
                  <dt className="text-xl font-semibold text-silver-50">{value}</dt>
                  <dd className="mt-1 text-xs leading-snug text-silver-500">{label}</dd>
                </div>
              ))}
            </dl>
          </div>
        </section>

        {/* --------------------------------------------------------- value */}
        <section className="border-b border-ink-800">
          <div className="mx-auto max-w-6xl px-6 py-20">
            <SectionHeading
              eyebrow="The problem"
              title="Your vendor list is a spreadsheet, and nobody has looked at it since the last audit."
              description="Most small companies depend on twenty or thirty third parties and have no way to tell which of them is a genuine risk. Zentra answers three questions per vendor, continuously."
            />
            <div className="mt-12 grid gap-px overflow-hidden rounded-sm border border-ink-700 bg-ink-700 md:grid-cols-3">
              {[
                {
                  title: 'What is wrong?',
                  body: 'One sentence, no jargon. “The vendor’s TLS certificate has expired.” Not a wall of CVE identifiers.',
                },
                {
                  title: 'How serious is it?',
                  body: 'A 0–100 score with a Low / Medium / High / Critical band, and a breakdown showing exactly where the points came from.',
                },
                {
                  title: 'What should I do?',
                  body: 'The specific thing to raise with the vendor, written so you can paste it into an email.',
                },
              ].map((item) => (
                <div key={item.title} className="bg-ink-900 p-7">
                  <h3 className="text-sm font-medium text-silver-50">{item.title}</h3>
                  <p className="mt-3 text-sm leading-relaxed text-silver-400">{item.body}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* --------------------------------------------------- how it works */}
        <section id="how-it-works" className="border-b border-ink-800 scroll-mt-20">
          <div className="mx-auto max-w-6xl px-6 py-20">
            <SectionHeading eyebrow="How it works" title="Four steps, then it runs itself." />
            <ol className="mt-12 grid gap-8 md:grid-cols-2 lg:grid-cols-4">
              {STEPS.map((step) => (
                <li key={step.step} className="border-t border-ink-700 pt-5">
                  <span className="font-mono text-2xs text-silver-600">{step.step}</span>
                  <h3 className="mt-2 text-sm font-medium text-silver-50">{step.title}</h3>
                  <p className="mt-2 text-sm leading-relaxed text-silver-400">{step.body}</p>
                </li>
              ))}
            </ol>
          </div>
        </section>

        {/* ------------------------------------------------------- checks */}
        <section id="checks" className="border-b border-ink-800 scroll-mt-20">
          <div className="mx-auto max-w-6xl px-6 py-20">
            <SectionHeading
              eyebrow="Security checks"
              title="Six categories, weighted by how much they actually tell you."
              description="Every category is worth a fixed number of points out of 100. The weights are published, not proprietary."
            />
            <div className="mt-12 grid gap-px overflow-hidden rounded-sm border border-ink-700 bg-ink-700 sm:grid-cols-2 lg:grid-cols-3">
              {CHECKS.map((check) => (
                <article key={check.name} className="bg-ink-900 p-7">
                  <div className="flex items-baseline justify-between gap-3">
                    <h3 className="text-sm font-medium text-silver-50">{check.name}</h3>
                    <span className="shrink-0 font-mono text-2xs text-silver-500">
                      {check.weight}
                    </span>
                  </div>
                  <p className="mt-3 text-sm leading-relaxed text-silver-400">{check.detail}</p>
                </article>
              ))}
            </div>
            <div className="mt-8 rounded-sm border border-ink-700 bg-ink-900 p-6">
              <h3 className="text-sm font-medium text-silver-50">
                When a check cannot be completed, Zentra says so
              </h3>
              <p className="mt-2 max-w-3xl text-sm leading-relaxed text-silver-400">
                A data source being unavailable is missing information, not evidence that a vendor
                is secure. Zentra records it as “not assessed”, reduces the reported coverage and
                confidence, and never converts it into a passing result. If coverage falls too low
                to be meaningful, Zentra declines to publish a risk level rather than showing an
                unreliable one.
              </p>
            </div>
          </div>
        </section>

        {/* ---------------------------------------------------- reporting */}
        <section id="reporting" className="border-b border-ink-800 scroll-mt-20">
          <div className="mx-auto max-w-6xl px-6 py-20">
            <div className="grid gap-12 lg:grid-cols-2 lg:items-center">
              <div>
                <SectionHeading
                  eyebrow="Compliance reporting"
                  title="An auditor-friendly vendor risk register, generated on demand."
                  description="One click produces a dated PDF covering every vendor: risk score, risk level, key findings, recommended actions, the full methodology and the assumptions behind it."
                />
                <ul className="mt-8 space-y-3">
                  {[
                    'Executive summary with the numbers your board asks for',
                    'Per-vendor findings with source, date and confidence',
                    'Full scoring methodology, including how missing data is handled',
                    'Remediation status and history for every tracked finding',
                    'White-label branding on the Scale plan',
                  ].map((item) => (
                    <li key={item} className="flex gap-3 text-sm text-silver-300">
                      <span aria-hidden="true" className="mt-1.5 h-1 w-1 shrink-0 bg-silver-400" />
                      {item}
                    </li>
                  ))}
                </ul>
                <div className="mt-8 rounded-sm border border-ink-700 bg-ink-850 p-5">
                  <p className="text-sm leading-relaxed text-silver-400">
                    <strong className="font-medium text-silver-200">Being precise about this:</strong>{' '}
                    Zentra does not make you ISO 27001 or SOC 2 compliant, and no software can.
                    What it produces is compliance-supporting documentation — evidence that you
                    operate a third-party risk process, in a form an auditor can read.
                  </p>
                </div>
              </div>
              <div className="rounded-sm border border-ink-700 bg-ink-900 p-8">
                <p className="text-2xs uppercase tracking-governance text-silver-500">
                  Report preview
                </p>
                <div className="mt-5 space-y-4 border-l-2 border-silver-500/30 pl-5">
                  <div>
                    <p className="text-xs text-silver-500">Vendor</p>
                    <p className="text-sm text-silver-100">Example Payments Ltd · example-payments.com</p>
                  </div>
                  <div className="flex items-baseline gap-3">
                    <span className="text-3xl font-semibold text-silver-50">72</span>
                    <span className="text-xs text-silver-500">/ 100</span>
                    <span className="rounded-sm border border-risk-high/45 bg-risk-high-dim px-2 py-0.5 text-2xs font-semibold uppercase tracking-governance text-risk-high">
                      ▲ High
                    </span>
                  </div>
                  <div>
                    <p className="text-xs text-silver-500">Key finding</p>
                    <p className="text-sm text-silver-200">
                      Expired TLS certificate and publicly reachable administrative services.
                    </p>
                  </div>
                  <div>
                    <p className="text-xs text-silver-500">Recommended action</p>
                    <p className="text-sm text-silver-200">
                      Ask the vendor to renew the certificate and confirm whether the exposed
                      services are intended to be public.
                    </p>
                  </div>
                </div>
                <p className="mt-6 text-2xs leading-relaxed text-silver-600">
                  Illustrative example. Figures are not a real assessment of any company.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* ------------------------------------------------------ pricing */}
        <section id="pricing" className="border-b border-ink-800 scroll-mt-20">
          <div className="mx-auto max-w-6xl px-6 py-20">
            <SectionHeading
              eyebrow="Pricing"
              title="Priced for a company that does not have a security team."
              description="All plans include the full security check set. Higher plans add vendors, monitoring, reporting and automation."
            />
            <div className="mt-12 grid gap-6 lg:grid-cols-3">
              {PLANS.map((plan) => (
                <div
                  key={plan.name}
                  className={
                    plan.highlighted
                      ? 'relative rounded-sm border border-silver-400/50 bg-ink-900 p-7'
                      : 'rounded-sm border border-ink-700 bg-ink-900 p-7'
                  }
                >
                  {plan.highlighted && (
                    <span className="absolute -top-2.5 left-7 rounded-sm bg-silver-50 px-2 py-0.5 text-2xs font-semibold uppercase tracking-governance text-ink-950">
                      Most chosen
                    </span>
                  )}
                  <h3 className="text-sm font-medium text-silver-50">{plan.name}</h3>
                  <p className="mt-4 flex items-baseline gap-1">
                    <span className="text-3xl font-semibold tracking-tight text-silver-50">
                      {plan.price}
                    </span>
                    <span className="text-sm text-silver-500">{plan.cadence}</span>
                  </p>
                  <p className="mt-3 text-sm text-silver-400">{plan.summary}</p>
                  <ul className="mt-6 space-y-2.5">
                    {plan.features.map((feature) => (
                      <li key={feature} className="flex gap-2.5 text-sm text-silver-300">
                        <span aria-hidden="true" className="mt-1.5 h-1 w-1 shrink-0 bg-silver-500" />
                        {feature}
                      </li>
                    ))}
                  </ul>
                  <Link
                    href="/auth/sign-up"
                    className={
                      plan.highlighted
                        ? 'mt-7 flex h-11 items-center justify-center rounded-sm bg-silver-50 text-sm font-medium text-ink-950 hover:bg-white'
                        : 'mt-7 flex h-11 items-center justify-center rounded-sm border border-silver-500/40 text-sm font-medium text-silver-100 hover:border-silver-400 hover:bg-ink-850'
                    }
                  >
                    {plan.cta}
                  </Link>
                </div>
              ))}
            </div>
            <p className="mt-6 text-sm text-silver-500">
              Also available: a <strong className="text-silver-300">£99 one-off report pack</strong>{' '}
              that unlocks the PDF vendor risk register without a subscription upgrade. Prices
              exclude VAT.
            </p>
          </div>
        </section>

        {/* ---------------------------------------------------------- FAQ */}
        <section className="border-b border-ink-800">
          <div className="mx-auto max-w-3xl px-6 py-20">
            <SectionHeading eyebrow="FAQ" title="Questions worth asking before you buy." />
            <dl className="mt-10 divide-y divide-ink-800 border-t border-ink-800">
              {FAQS.map((faq) => (
                <div key={faq.q} className="py-6">
                  <dt className="text-sm font-medium text-silver-100">{faq.q}</dt>
                  <dd className="mt-2.5 text-sm leading-relaxed text-silver-400">{faq.a}</dd>
                </div>
              ))}
            </dl>
          </div>
        </section>

        {/* ---------------------------------------------------------- CTA */}
        <section>
          <div className="mx-auto max-w-4xl px-6 py-24 text-center">
            <h2 className="text-3xl font-semibold tracking-tight text-silver-50">
              Scan one vendor. Decide in two minutes.
            </h2>
            <p className="mx-auto mt-4 max-w-xl text-sm leading-relaxed text-silver-400">
              Pick the third party you would least like to have a breach. Zentra will tell you what
              it can see from public sources, and what to do about it.
            </p>
            <div className="mt-9 flex flex-col justify-center gap-3 sm:flex-row">
              <Link
                href="/scan"
                className="inline-flex h-12 items-center justify-center rounded-sm bg-silver-50 px-8 text-sm font-medium text-ink-950 hover:bg-white"
              >
                Scan your first vendor free
              </Link>
              <Link
                href="/auth/sign-up"
                className="inline-flex h-12 items-center justify-center rounded-sm border border-silver-500/40 px-8 text-sm font-medium text-silver-100 hover:border-silver-400 hover:bg-ink-900"
              >
                Create an account
              </Link>
            </div>
          </div>
        </section>
      </main>
      <MarketingFooter />
    </>
  );
}
