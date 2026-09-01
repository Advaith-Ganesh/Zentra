import { MarketingFooter, MarketingHeader } from '@/components/marketing';

export default function LegalLayout({ children }: { children: React.ReactNode }) {
  return (
    <>
      <MarketingHeader />
      <main id="main" className="mx-auto max-w-3xl px-6 py-16">
        <div className="mb-10 rounded-sm border border-risk-medium/35 bg-risk-medium-dim p-4">
          <p className="text-sm text-risk-medium">
            <strong className="font-medium">Draft pending legal review.</strong> This document is an
            initial draft prepared for review by a qualified solicitor. It must not be relied upon
            as the operative agreement, and must be reviewed and approved before Zentra launches
            commercially.
          </p>
        </div>
        <article className="prose-zentra space-y-6">{children}</article>
      </main>
      <MarketingFooter />
    </>
  );
}
