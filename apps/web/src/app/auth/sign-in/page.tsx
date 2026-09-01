'use client';

import * as React from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { Banner, Button, Card, CardBody, Field, Input } from '@/components/ui';
import { ApiError, api, session } from '@/lib/api';

export default function SignInPage() {
  const router = useRouter();
  const [email, setEmail] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [error, setError] = React.useState<string | null>(null);
  const [submitting, setSubmitting] = React.useState(false);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const result = await api.auth.signIn({ email: email.trim(), password });
      session.setToken(result.access_token);
      if (result.organization) session.setOrganizationId(result.organization.id);
      router.replace('/dashboard');
    } catch (caught) {
      setError(
        caught instanceof ApiError
          ? caught.message
          : 'Sign in failed. Please try again.',
      );
      setSubmitting(false);
    }
  }

  return (
    <Card>
      <CardBody className="space-y-6">
        <div>
          <h1 className="text-lg font-semibold tracking-tight text-silver-50">Sign in to Zentra</h1>
          <p className="mt-1.5 text-sm text-silver-400">
            Continue monitoring your vendor risk.
          </p>
        </div>

        {error && <Banner tone="danger">{error}</Banner>}

        <form onSubmit={onSubmit} className="space-y-4" noValidate>
          <Field label="Work email" htmlFor="email" required>
            <Input
              id="email"
              name="email"
              type="email"
              autoComplete="email"
              required
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              disabled={submitting}
            />
          </Field>
          <Field label="Password" htmlFor="password" required>
            <Input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              disabled={submitting}
            />
          </Field>
          <Button type="submit" className="w-full" loading={submitting} loadingLabel="Signing in…">
            Sign in
          </Button>
        </form>

        <div className="space-y-2 border-t border-ink-800 pt-5 text-sm">
          <p className="text-silver-400">
            <Link href="/auth/forgot-password" className="underline hover:text-silver-200">
              Forgot your password?
            </Link>
          </p>
          <p className="text-silver-400">
            No account?{' '}
            <Link href="/auth/sign-up" className="text-silver-100 underline hover:text-white">
              Create one
            </Link>
          </p>
        </div>
      </CardBody>
    </Card>
  );
}
