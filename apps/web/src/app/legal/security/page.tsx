import type { Metadata } from 'next';

export const metadata: Metadata = { title: 'Security' };

export default function SecurityPage() {
  return (
    <>
      <h1 className="text-2xl font-semibold tracking-tight text-silver-50">Security at Zentra</h1>
      <p className="text-sm text-silver-400">
        Zentra is a security product, so how we build it matters as much as what it reports.
      </p>

      <Section title="Reporting a vulnerability">
        Email <span className="font-mono text-silver-300">security@zentra.example</span> with enough
        detail to reproduce the issue. We aim to acknowledge within two working days and to keep you
        updated until the issue is resolved. Please give us a reasonable opportunity to fix an issue
        before disclosing it publicly. We will not pursue legal action against researchers who act
        in good faith and within the scope below.
      </Section>

      <Section title="In scope">
        <ul className="mt-2 list-disc space-y-1 pl-5">
          <li>The Zentra web application and its API.</li>
          <li>Authentication, authorization and tenant isolation.</li>
          <li>The scanner’s outbound request controls, including SSRF protections.</li>
          <li>Billing and webhook handling.</li>
        </ul>
      </Section>

      <Section title="Out of scope">
        <ul className="mt-2 list-disc space-y-1 pl-5">
          <li>Denial of service, volumetric testing and social engineering.</li>
          <li>Findings that require a compromised user device or a stolen credential.</li>
          <li>Reports from automated scanners with no demonstrated impact.</li>
          <li>Third-party services Zentra depends on — report those to their owners.</li>
        </ul>
      </Section>

      <Section title="How we protect customer data">
        <ul className="mt-2 list-disc space-y-1 pl-5">
          <li>Passwords are hashed with Argon2id. Zentra never stores a password in a recoverable form.</li>
          <li>API keys are stored as SHA-256 hashes; the secret is shown once and cannot be recovered.</li>
          <li>Integration credentials are encrypted at rest with authenticated encryption.</li>
          <li>
            Every tenant-owned table enforces PostgreSQL row-level security in addition to
            server-side authorization checks in the API.
          </li>
          <li>Logs pass through a redaction layer that strips credentials and tokens.</li>
          <li>Audit records capture who did what, to which resource, and when.</li>
        </ul>
      </Section>

      <Section title="How we protect the systems we scan">
        Zentra performs passive checks against publicly available sources only. Before any outbound
        request, a domain is validated, resolved once, and every resolved address is checked against
        loopback, private, link-local, carrier-grade NAT, reserved and cloud-metadata ranges. The
        validated address is then pinned for the connection, which closes the DNS-rebinding window.
        Redirects are re-validated at each hop. Only http and https on ports 80 and 443 are
        permitted.
      </Section>

      <Section title="Supported versions">
        Zentra is a hosted service. Security fixes are applied to the running production version;
        there are no supported self-hosted releases at this time.
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
