/** @type {import('next').NextConfig} */

const isProduction = process.env.NODE_ENV === 'production';
const apiOrigin = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000';
const supabaseOrigin = process.env.NEXT_PUBLIC_SUPABASE_URL ?? '';

/**
 * Content Security Policy for the browser application.
 *
 * `script-src` includes `'unsafe-inline'`, which is a deliberate, bounded
 * decision rather than an oversight. Next.js emits an inline bootstrap script
 * into every prerendered page; a nonce cannot be embedded in HTML that is
 * generated at build time, so the alternatives are `'unsafe-inline'` or
 * forcing every route to render dynamically. We took the former.
 *
 * The compensating controls are:
 *
 *  - React escapes all interpolated content, and `react/no-danger` is an
 *    error in the ESLint config, so there is no path from customer data to
 *    executed markup.
 *  - `connect-src` is pinned to this origin plus the configured API and
 *    Supabase origins, so even a successful injection has nowhere to send
 *    data.
 *  - `object-src`, `base-uri`, `frame-ancestors` and `form-action` remain
 *    fully locked down.
 *  - The API itself serves `default-src 'none'` and never returns HTML.
 *
 * If Next gains nonce support for statically prerendered output, tighten this
 * to `'self' 'nonce-…'` and drop `'unsafe-inline'`.
 */
const contentSecurityPolicy = [
  "default-src 'self'",
  `script-src 'self' 'unsafe-inline'${isProduction ? '' : " 'unsafe-eval'"}`,
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  `connect-src 'self' ${apiOrigin} ${supabaseOrigin}`.trim(),
  "frame-src 'none'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "object-src 'none'",
  "worker-src 'self' blob:",
  "manifest-src 'self'",
  ...(isProduction ? ['upgrade-insecure-requests'] : []),
].join('; ');

const securityHeaders = [
  { key: 'Content-Security-Policy', value: contentSecurityPolicy },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  {
    key: 'Permissions-Policy',
    value: 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()',
  },
  { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
  {
    key: 'Strict-Transport-Security',
    value: 'max-age=31536000; includeSubDomains',
  },
];

const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  // Emit a self-contained server bundle so the runtime image stays small.
  output: 'standalone',
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }];
  },
};

export default nextConfig;
