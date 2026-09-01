'use client';

import * as React from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { z } from 'zod';
import { Banner, Button, Card, CardBody, Field, Input, Select } from '@/components/ui';
import { ApiError, api, session } from '@/lib/api';

const schema = z.object({
  full_name: z.string().trim().max(200).optional(),
  email: z.string().trim().email('Enter a valid work email address.'),
  organization_name: z
    .string()
    .trim()
    .min(1, 'Enter your company name.')
    .max(200, 'That name is too long.'),
  password: z
    .string()
    .min(12, 'Use at least 12 characters.')
    .max(256)
    .refine((value) => {
      const classes = [
        /[a-z]/.test(value),
        /[A-Z]/.test(value),
        /\d/.test(value),
        /[^A-Za-z0-9]/.test(value),
      ].filter(Boolean).length;
      return classes >= 3;
    }, 'Combine at least three of: lowercase, uppercase, numbers, symbols.'),
  industry: z.string().optional(),
  company_size: z.string().optional(),
});

export default function SignUpPage() {
  const router = useRouter();
  const [values, setValues] = React.useState({
    full_name: '',
    email: '',
    organization_name: '',
    password: '',
    industry: 'Fintech',
    company_size: '10-50',
  });
  const [fieldErrors, setFieldErrors] = React.useState<Record<string, string>>({});
  const [error, setError] = React.useState<string | null>(null);
  const [submitting, setSubmitting] = React.useState(false);

  function update(key: keyof typeof values) {
    return (event: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
      setValues((current) => ({ ...current, [key]: event.target.value }));
  }

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    const parsed = schema.safeParse(values);
    if (!parsed.success) {
      const errors: Record<string, string> = {};
      for (const issue of parsed.error.issues) {
        const key = String(issue.path[0]);
        if (!errors[key]) errors[key] = issue.message;
      }
      setFieldErrors(errors);
      return;
    }
    setFieldErrors({});
    setSubmitting(true);
    try {
      const result = await api.auth.signUp(parsed.data);
      if (result.access_token) {
        session.setToken(result.access_token);
        if (result.organization) session.setOrganizationId(result.organization.id);
        router.replace('/dashboard');
        return;
      }
      // Supabase projects with email confirmation enabled withhold the session.
      setError(null);
      router.replace('/auth/sign-in?verify=1');
    } catch (caught) {
      setError(
        caught instanceof ApiError ? caught.message : 'Sign up failed. Please try again.',
      );
      setSubmitting(false);
    }
  }

  return (
    <Card>
      <CardBody className="space-y-6">
        <div>
          <h1 className="text-lg font-semibold tracking-tight text-silver-50">
            Create your Zentra workspace
          </h1>
          <p className="mt-1.5 text-sm text-silver-400">
            Start monitoring your third-party vendors in a couple of minutes.
          </p>
        </div>

        {error && <Banner tone="danger">{error}</Banner>}

        <form onSubmit={onSubmit} className="space-y-4" noValidate>
          <Field label="Your name" htmlFor="full_name">
            <Input
              id="full_name"
              autoComplete="name"
              value={values.full_name}
              onChange={update('full_name')}
              disabled={submitting}
            />
          </Field>
          <Field label="Work email" htmlFor="email" error={fieldErrors.email} required>
            <Input
              id="email"
              type="email"
              autoComplete="email"
              required
              invalid={Boolean(fieldErrors.email)}
              value={values.email}
              onChange={update('email')}
              disabled={submitting}
            />
          </Field>
          <Field
            label="Company name"
            htmlFor="organization_name"
            error={fieldErrors.organization_name}
            required
          >
            <Input
              id="organization_name"
              autoComplete="organization"
              required
              invalid={Boolean(fieldErrors.organization_name)}
              value={values.organization_name}
              onChange={update('organization_name')}
              disabled={submitting}
            />
          </Field>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Industry" htmlFor="industry">
              <Select id="industry" value={values.industry} onChange={update('industry')} disabled={submitting}>
                {['Fintech', 'SaaS', 'E-commerce', 'Healthcare', 'Professional services', 'Other'].map(
                  (option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ),
                )}
              </Select>
            </Field>
            <Field label="Company size" htmlFor="company_size">
              <Select
                id="company_size"
                value={values.company_size}
                onChange={update('company_size')}
                disabled={submitting}
              >
                {['1-9', '10-50', '51-200', '201-500', '500+'].map((option) => (
                  <option key={option} value={option}>
                    {option} employees
                  </option>
                ))}
              </Select>
            </Field>
          </div>
          <Field
            label="Password"
            htmlFor="password"
            hint="At least 12 characters, combining three of: lowercase, uppercase, numbers, symbols."
            error={fieldErrors.password}
            required
          >
            <Input
              id="password"
              type="password"
              autoComplete="new-password"
              required
              invalid={Boolean(fieldErrors.password)}
              value={values.password}
              onChange={update('password')}
              disabled={submitting}
            />
          </Field>
          <Button type="submit" className="w-full" loading={submitting} loadingLabel="Creating…">
            Create workspace
          </Button>
        </form>

        <p className="border-t border-ink-800 pt-5 text-sm text-silver-400">
          Already have an account?{' '}
          <Link href="/auth/sign-in" className="text-silver-100 underline hover:text-white">
            Sign in
          </Link>
        </p>
      </CardBody>
    </Card>
  );
}
