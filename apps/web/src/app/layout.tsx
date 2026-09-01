import type { Metadata, Viewport } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: {
    default: 'Zentra — Vendor risk intelligence',
    template: '%s · Zentra',
  },
  description:
    'Zentra continuously assesses your third-party vendors against publicly available security signals and turns the result into a clear risk score, a plain-English explanation and an auditor-friendly vendor risk register.',
  applicationName: 'Zentra',
  robots: { index: true, follow: true },
  openGraph: {
    title: 'Zentra — Vendor risk intelligence',
    description:
      'Vendor risk visibility for UK startups and SMBs, without hiring a security analyst.',
    type: 'website',
  },
};

export const viewport: Viewport = {
  themeColor: '#08090b',
  width: 'device-width',
  initialScale: 1,
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en-GB">
      <body>
        <a href="#main" className="skip-link">
          Skip to main content
        </a>
        {children}
      </body>
    </html>
  );
}
