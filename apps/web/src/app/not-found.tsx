import Link from 'next/link';

export default function NotFound() {
  return (
    <main
      id="main"
      className="flex min-h-screen flex-col items-center justify-center px-6 text-center"
    >
      <p className="text-2xs font-semibold uppercase tracking-governance text-silver-500">404</p>
      <h1 className="mt-3 text-2xl font-semibold tracking-tight text-silver-50">Page not found</h1>
      <p className="mt-3 max-w-sm text-sm text-silver-400">
        That page does not exist, or you do not have access to it.
      </p>
      <Link
        href="/"
        className="mt-7 inline-flex h-10 items-center rounded-sm bg-silver-50 px-5 text-sm font-medium text-ink-950 hover:bg-white"
      >
        Back to Zentra
      </Link>
    </main>
  );
}
