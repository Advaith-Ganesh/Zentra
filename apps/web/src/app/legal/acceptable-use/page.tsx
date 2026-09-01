import type { Metadata } from 'next';

export const metadata: Metadata = { title: 'Acceptable Use Policy (draft)' };

export default function AcceptableUsePage() {
  return (
    <>
      <h1 className="text-2xl font-semibold tracking-tight text-silver-50">
        Acceptable Use Policy
      </h1>
      <p className="text-xs text-silver-500">Version 0.1 — draft for solicitor review.</p>

      <Section title="1. Purpose">
        Zentra examines third-party domains on your behalf. This policy sets out what that may and
        may not be used for. It applies to every account, including free scans.
      </Section>

      <Section title="2. Permitted use">
        You may use Zentra to assess organizations you have a legitimate business interest in: your
        suppliers, prospective suppliers, partners, and your own domains. The output is for your
        internal risk management, audit preparation and customer assurance.
      </Section>

      <Section title="3. Prohibited use">
        <ul className="mt-2 list-disc space-y-1 pl-5">
          <li>
            Using Zentra to gather reconnaissance for an attack, or as part of any unauthorised
            security testing.
          </li>
          <li>
            Attempting to make Zentra reach systems it is designed to refuse, including internal
            networks, loopback and private address space, or cloud metadata endpoints.
          </li>
          <li>
            Automating the free scan, evading its rate limits, or otherwise degrading the service
            for others.
          </li>
          <li>
            Publishing Zentra output in a way that misrepresents it as an audit, a certification, or
            a definitive statement about a third party’s security.
          </li>
          <li>
            Reverse engineering the service, or reselling access without a written agreement.
          </li>
        </ul>
      </Section>

      <Section title="4. What Zentra will never do">
        Zentra performs passive checks against publicly available sources only. It does not attempt
        authentication, brute force, exploitation, denial of service, or any intrusive testing
        against any system. These limits are enforced in the product and are not configurable.
      </Section>

      <Section title="5. Reporting misuse">
        Report suspected misuse to <span className="font-mono">abuse@zentra.example</span>. If you
        believe Zentra has scanned a domain it should not have, contact us and we will investigate
        and, where appropriate, suppress that domain.
      </Section>

      <Section title="6. Enforcement">
        We may suspend or terminate access for breach of this policy, and will cooperate with lawful
        requests from law enforcement.
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
