import Link from 'next/link';
import { cn } from '@/lib/utils';

export function Wordmark({ className }: { className?: string }) {
  return (
    <span className={cn('zentra-wordmark text-sm', className)}>ZENTRA</span>
  );
}

export function MarketingHeader() {
  return (
    <header className="sticky top-0 z-40 border-b border-ink-800 bg-ink-950/85 backdrop-blur">
      <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-6">
        <Link href="/" className="flex items-center gap-2 rounded-sm">
          <span aria-hidden="true" className="inline-block h-3.5 w-3.5 border border-silver-200" />
          <Wordmark />
          <span className="sr-only">Zentra home</span>
        </Link>
        <nav aria-label="Primary" className="hidden items-center gap-7 md:flex">
          <a href="#how-it-works" className="text-sm text-silver-400 hover:text-silver-100">
            How it works
          </a>
          <a href="#checks" className="text-sm text-silver-400 hover:text-silver-100">
            Security checks
          </a>
          <a href="#reporting" className="text-sm text-silver-400 hover:text-silver-100">
            Reporting
          </a>
          <a href="#pricing" className="text-sm text-silver-400 hover:text-silver-100">
            Pricing
          </a>
        </nav>
        <div className="flex items-center gap-3">
          <Link
            href="/auth/sign-in"
            className="rounded-sm px-3 py-2 text-sm text-silver-300 hover:text-silver-50"
          >
            Sign in
          </Link>
          <Link
            href="/scan"
            className="rounded-sm bg-silver-50 px-4 py-2 text-sm font-medium text-ink-950 hover:bg-white"
          >
            Scan a vendor
          </Link>
        </div>
      </div>
    </header>
  );
}

export function MarketingFooter() {
  return (
    <footer className="border-t border-ink-800 bg-ink-950">
      <div className="mx-auto max-w-6xl px-6 py-12">
        <div className="grid gap-10 md:grid-cols-4">
          <div>
            <div className="flex items-center gap-2">
              <span aria-hidden="true" className="inline-block h-3 w-3 border border-silver-300" />
              <Wordmark className="text-xs" />
            </div>
            <p className="mt-3 max-w-xs text-xs leading-relaxed text-silver-500">
              Vendor risk intelligence for UK startups and small businesses.
            </p>
          </div>
          <nav aria-label="Product">
            <h2 className="text-2xs font-semibold uppercase tracking-governance text-silver-400">
              Product
            </h2>
            <ul className="mt-3 space-y-2 text-sm text-silver-500">
              <li><a href="#how-it-works" className="hover:text-silver-200">How it works</a></li>
              <li><a href="#checks" className="hover:text-silver-200">Security checks</a></li>
              <li><a href="#pricing" className="hover:text-silver-200">Pricing</a></li>
              <li><Link href="/scan" className="hover:text-silver-200">Free vendor scan</Link></li>
            </ul>
          </nav>
          <nav aria-label="Legal">
            <h2 className="text-2xs font-semibold uppercase tracking-governance text-silver-400">
              Legal
            </h2>
            <ul className="mt-3 space-y-2 text-sm text-silver-500">
              <li><Link href="/legal/terms" className="hover:text-silver-200">Terms of Service</Link></li>
              <li><Link href="/legal/privacy" className="hover:text-silver-200">Privacy Policy</Link></li>
              <li><Link href="/legal/acceptable-use" className="hover:text-silver-200">Acceptable Use</Link></li>
              <li><Link href="/legal/security" className="hover:text-silver-200">Security</Link></li>
            </ul>
          </nav>
          <div>
            <h2 className="text-2xs font-semibold uppercase tracking-governance text-silver-400">
              Responsible disclosure
            </h2>
            <p className="mt-3 text-sm text-silver-500">
              Found a vulnerability in Zentra? Please report it to{' '}
              <span className="font-mono text-silver-300">security@zentra.example</span>.
            </p>
          </div>
        </div>
        <div className="mt-10 border-t border-ink-800 pt-6">
          <p className="text-2xs leading-relaxed text-silver-600">
            Zentra’s risk scores are informational assessments based on signals from publicly
            available sources. They are not an audit of a vendor, and they are not legal,
            regulatory or certification advice. Zentra performs passive checks only and never
            attempts authentication, exploitation or intrusive testing against any vendor.
          </p>
          <p className="mt-3 text-2xs text-silver-600">
            © {new Date().getFullYear()} Zentra. All rights reserved.
          </p>
        </div>
      </div>
    </footer>
  );
}

export function SectionHeading({
  eyebrow,
  title,
  description,
  id,
}: {
  eyebrow?: string;
  title: string;
  description?: string;
  id?: string;
}) {
  return (
    <div className="max-w-2xl">
      {eyebrow && (
        <p className="text-2xs font-semibold uppercase tracking-governance text-silver-500">
          {eyebrow}
        </p>
      )}
      <h2 id={id} className="mt-3 text-2xl font-semibold tracking-tight text-silver-50 sm:text-3xl">
        {title}
      </h2>
      {description && <p className="mt-3 text-sm leading-relaxed text-silver-400">{description}</p>}
    </div>
  );
}
