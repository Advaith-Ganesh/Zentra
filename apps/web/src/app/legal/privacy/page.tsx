import type { Metadata } from 'next';

export const metadata: Metadata = { title: 'Privacy Policy (draft)' };

export default function PrivacyPage() {
  return (
    <>
      <h1 className="text-2xl font-semibold tracking-tight text-silver-50">Privacy Policy</h1>
      <p className="text-xs text-silver-500">Version 0.1 — draft for solicitor review.</p>

      <Section title="1. Who we are">
        Zentra is the data controller for personal data processed through the service. Contact:{' '}
        <span className="font-mono">privacy@zentra.example</span>.
      </Section>

      <Section title="2. What we collect">
        <ul className="mt-2 list-disc space-y-1 pl-5">
          <li>
            <strong className="text-silver-300">Account data:</strong> your name, work email address,
            organization name, industry and company size.
          </li>
          <li>
            <strong className="text-silver-300">Usage data:</strong> the vendors you add, scans you
            run, findings you update and reports you generate, together with audit records of those
            actions.
          </li>
          <li>
            <strong className="text-silver-300">Technical data:</strong> request identifiers,
            timestamps and coarse diagnostic information. Requester IP addresses used for abuse
            prevention are stored only as an irreversible salted hash, never in clear text.
          </li>
          <li>
            <strong className="text-silver-300">Vendor scan data:</strong> security signals about the
            domains you nominate, gathered from publicly available sources. Breach records are
            stored as catalogue metadata only — never individual account data or credentials.
          </li>
        </ul>
      </Section>

      <Section title="3. Why we process it">
        To provide the service, to authenticate you, to prevent abuse of the free scan, to bill you,
        to send service and alert emails, and to meet our legal obligations. Our lawful bases are
        performance of a contract, our legitimate interests in operating and securing the service,
        and consent where required for marketing.
      </Section>

      <Section title="4. What we do not do">
        We do not sell personal data, and we do not use your vendor data to train models. Benchmark
        statistics are computed only from aggregated, anonymized data across organizations that have
        opted in, and are published only where a cohort is large enough that no individual customer
        can be identified.
      </Section>

      <Section title="5. Sharing">
        We share data with the processors needed to run the service: our cloud hosting and database
        provider, our payment processor, and our transactional email provider. Domains you nominate
        are sent to third-party security data sources to perform the checks you requested. Each
        processor is bound by a data processing agreement.
      </Section>

      <Section title="6. Retention">
        Account and vendor data is retained for as long as your account is active, and by default
        for a further period configurable per organization. Anonymous free-scan records are deleted
        after 30 days. Generated report files expire after 30 days. Deleting your organization
        removes its data.
      </Section>

      <Section title="7. Your rights">
        Under UK GDPR you may request access to, correction of, deletion of, or a portable copy of
        your personal data, and you may object to or restrict certain processing. Contact{' '}
        <span className="font-mono">privacy@zentra.example</span>. You may also complain to the
        Information Commissioner’s Office.
      </Section>

      <Section title="8. Security">
        Passwords are hashed with Argon2id. Integration credentials are encrypted at rest. Access is
        segregated by organization at both the application and database layers. See our{' '}
        <a href="/legal/security" className="underline hover:text-silver-200">
          security page
        </a>{' '}
        for detail and for how to report a vulnerability.
      </Section>

      <Section title="9. International transfers">
        Data is processed in the United Kingdom and the European Economic Area where possible. Where
        a processor operates elsewhere, transfers rely on UK adequacy regulations or the
        International Data Transfer Addendum.
      </Section>

      <Section title="10. Changes">
        We will notify account owners by email before any material change to this policy takes
        effect.
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
