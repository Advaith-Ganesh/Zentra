'use client';

import * as React from 'react';
import Link from 'next/link';
import { Banner, Button, Card, CardBody, Field, Input } from '@/components/ui';
import { api } from '@/lib/api';

export default function ForgotPasswordPage() {
  const [email, setEmail] = React.useState('');
  const [submitted, setSubmitted] = React.useState(false);
  const [submitting, setSubmitting] = React.useState(false);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    try {
      await api.auth.requestPasswordReset(email.trim());
    } catch {
      /* The response is deliberately identical either way. */
    }
    setSubmitting(false);
    setSubmitted(true);
  }

  return (
    <Card>
      <CardBody className="space-y-6">
        <div>
          <h1 className="text-lg font-semibold tracking-tight text-silver-50">Reset your password</h1>
          <p className="mt-1.5 text-sm text-silver-400">
            We will email you a link if an account exists for that address.
          </p>
        </div>

        {submitted ? (
          <Banner tone="success" title="Check your inbox">
            If an account exists for {email}, a password reset email is on its way.
          </Banner>
        ) : (
          <form onSubmit={onSubmit} className="space-y-4" noValidate>
            <Field label="Work email" htmlFor="email" required>
              <Input
                id="email"
                type="email"
                autoComplete="email"
                required
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                disabled={submitting}
              />
            </Field>
            <Button type="submit" className="w-full" loading={submitting} loadingLabel="Sending…">
              Send reset link
            </Button>
          </form>
        )}

        <p className="border-t border-ink-800 pt-5 text-sm text-silver-400">
          <Link href="/auth/sign-in" className="underline hover:text-silver-200">
            Back to sign in
          </Link>
        </p>
      </CardBody>
    </Card>
  );
}
