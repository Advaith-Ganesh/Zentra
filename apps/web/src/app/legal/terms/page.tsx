import type { Metadata } from 'next';

export const metadata: Metadata = { title: 'Terms of Service (draft)' };

export default function TermsPage() {
  return (
    <>
      <h1 className="text-2xl font-semibold tracking-tight text-silver-50">Terms of Service</h1>
      <p className="text-xs text-silver-500">Version 0.1 — draft for solicitor review.</p>

      <Section title="1. About these terms">
        These terms govern your use of Zentra, a vendor risk intelligence service operated by Zentra
        (“we”, “us”). By creating an account you agree to them. If you are agreeing on behalf of a
        company, you confirm you have authority to bind that company.
      </Section>

      <Section title="2. What the service does">
        Zentra collects security signals about domains you nominate from publicly available sources,
        combines them into an informational risk score, and produces reports summarising what it
        observed. The service is a monitoring and documentation tool. It is not a security audit, a
        penetration test, a certification, or professional advice of any kind.
      </Section>

      <Section title="3. What the service does not do">
        <ul className="mt-2 list-disc space-y-1 pl-5">
          <li>
            Zentra does not certify, audit or assure any vendor’s security, and does not make you
            compliant with ISO 27001, SOC 2, or any other standard or framework.
          </li>
          <li>
            Zentra does not guarantee that its findings are complete or current. The absence of a
            finding is not evidence that no issue exists.
          </li>
          <li>
            Zentra does not perform intrusive testing, exploitation, authentication attempts or any
            activity that would interfere with a vendor’s systems.
          </li>
        </ul>
      </Section>

      <Section title="4. Your responsibilities">
        You are responsible for the domains you submit, for keeping your account credentials secure,
        and for the decisions you take on the basis of Zentra’s output. You must only submit domains
        belonging to organizations you have a legitimate business interest in assessing, and you
        must comply with the Acceptable Use Policy.
      </Section>

      <Section title="5. Subscriptions and payment">
        Paid plans are billed monthly in advance through our payment processor. Prices exclude VAT
        unless stated. You may cancel at any time; cancellation takes effect at the end of the
        current billing period, and fees already paid are not refundable except where required by
        law. We may change prices on notice, effective from your next renewal.
      </Section>

      <Section title="6. Availability">
        We aim to keep the service available but do not warrant uninterrupted operation. Some checks
        depend on third-party data sources that may be unavailable; Zentra reports such gaps rather
        than concealing them, and reduced coverage is not a service failure.
      </Section>

      <Section title="7. Intellectual property">
        We retain all rights in the service and its underlying methodology. You retain all rights in
        the data you submit. You may use reports Zentra generates for your own internal, audit and
        customer-assurance purposes.
      </Section>

      <Section title="8. Liability">
        Nothing in these terms excludes liability that cannot be excluded by law, including for
        death or personal injury caused by negligence, or for fraud. Subject to that, our total
        liability arising out of the service is limited to the fees you paid in the twelve months
        before the claim, and we are not liable for indirect or consequential loss, loss of profit,
        or loss arising from a decision you took on the basis of Zentra’s output.
      </Section>

      <Section title="9. Termination">
        You may close your account at any time. We may suspend or terminate an account that breaches
        these terms or the Acceptable Use Policy. On termination we will make your data available
        for export for a reasonable period before deletion.
      </Section>

      <Section title="10. Governing law">
        These terms are governed by the laws of England and Wales, and the courts of England and
        Wales have exclusive jurisdiction.
      </Section>

      <Section title="11. Contact">
        Questions about these terms: <span className="font-mono">legal@zentra.example</span>.
      </Section>
    </>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <h2 className="text-sm font-medium text-silver-100">{title}</h2>
      <div className="mt-2 text-sm leading-relaxed text-silver-400">{children}</div>
    </section>
  );
}
