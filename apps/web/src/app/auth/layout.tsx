import Link from 'next/link';
import { Wordmark } from '@/components/marketing';

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen flex-col">
      <header className="border-b border-ink-800">
        <div className="mx-auto flex h-16 max-w-6xl items-center px-6">
          <Link href="/" className="flex items-center gap-2 rounded-sm">
            <span aria-hidden="true" className="inline-block h-3.5 w-3.5 border border-silver-200" />
            <Wordmark />
            <span className="sr-only">Zentra home</span>
          </Link>
        </div>
      </header>
      <main id="main" className="flex flex-1 items-center justify-center px-6 py-12">
        <div className="w-full max-w-md">{children}</div>
      </main>
      <footer className="border-t border-ink-800 px-6 py-6">
        <p className="mx-auto max-w-6xl text-2xs text-silver-600">
          By continuing you agree to Zentra’s{' '}
          <Link href="/legal/terms" className="underline hover:text-silver-400">
            Terms of Service
          </Link>{' '}
          and{' '}
          <Link href="/legal/privacy" className="underline hover:text-silver-400">
            Privacy Policy
          </Link>
          .
        </p>
      </footer>
    </div>
  );
}
