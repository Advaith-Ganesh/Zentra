'use client';

import * as React from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { z } from 'zod';
import { Banner, Button, Card, CardBody, CardHeader, Field, Input, Select, Textarea } from '@/components/ui';
import { ApiError, api } from '@/lib/api';

const schema = z.object({
  name: z.string().trim().min(1, 'Enter the vendor’s name.').max(200),
  domain: z
    .string()
    .trim()
    .min(3, 'Enter the vendor’s domain.')
    .transform((value) =>
      value.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase(),
    )
    .refine((value) => /^[a-z0-9.-]+$/.test(value), 'Enter a bare domain, such as example.com')
    .refine((value) => value.includes('.'), 'Enter a full domain, such as example.com'),
  description: z.string().trim().max(2000).optional(),
  category: z.string().trim().max(100).optional(),
  criticality: z.enum(['low', 'medium', 'high', 'critical']),
  owner_label: z.string().trim().max(200).optional(),
});

const CATEGORIES = [
  'Payments',
  'Infrastructure',
  'Collaboration',
  'CRM & marketing',
  'Customer support',
  'Analytics',
  'Accounting',
  'HR & payroll',
  'Security',
  'Other',
];

export default function AddVendorPage() {
  const router = useRouter();
  const [values, setValues] = React.useState({
    name: '',
    domain: '',
    description: '',
    category: 'Payments',
    criticality: 'medium',
    owner_label: '',
  });
  const [fieldErrors, setFieldErrors] = React.useState<Record<string, string>>({});
  const [error, setError] = React.useState<{ message: string; upgrade: boolean } | null>(null);
  const [submitting, setSubmitting] = React.useState(false);

  function update(key: keyof typeof values) {
    return (
      event: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>,
    ) => setValues((current) => ({ ...current, [key]: event.target.value }));
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
      const vendor = await api.vendors.create(parsed.data);
      router.replace(`/dashboard/vendors/${vendor.id}`);
    } catch (caught) {
      if (caught instanceof ApiError) {
        setError({ message: caught.message, upgrade: caught.isEntitlementError });
      } else {
        setError({ message: 'The vendor could not be added.', upgrade: false });
      }
      setSubmitting(false);
    }
  }

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div>
        <Link
          href="/dashboard/vendors"
          className="text-xs text-silver-400 underline-offset-4 hover:text-silver-100 hover:underline"
        >
          ← Back to vendors
        </Link>
        <h1 className="mt-3 text-xl font-semibold tracking-tight text-silver-50">Add a vendor</h1>
        <p className="mt-1 text-sm text-silver-400">
          Zentra will assess this vendor straight away, then keep monitoring it.
        </p>
      </div>

      {error && (
        <Banner tone={error.upgrade ? 'warning' : 'danger'} title={error.upgrade ? 'Plan limit reached' : undefined}>
          {error.message}
          {error.upgrade && (
            <div className="mt-3">
              <Link
                href="/dashboard/billing"
                className="inline-flex h-9 items-center rounded-sm bg-silver-50 px-4 text-xs font-medium text-ink-950 hover:bg-white"
              >
                View plans
              </Link>
            </div>
          )}
        </Banner>
      )}

      <Card>
        <CardHeader title="Vendor details" description="Only the name and domain are required." />
        <CardBody>
          <form onSubmit={onSubmit} className="space-y-5" noValidate>
            <Field label="Vendor name" htmlFor="name" error={fieldErrors.name} required>
              <Input
                id="name"
                required
                placeholder="Stripe"
                value={values.name}
                invalid={Boolean(fieldErrors.name)}
                onChange={update('name')}
                disabled={submitting}
              />
            </Field>

            <Field
              label="Domain"
              htmlFor="domain"
              hint="The company’s main domain. Zentra assesses this domain’s public security signals."
              error={fieldErrors.domain}
              required
            >
              <Input
                id="domain"
                required
                inputMode="url"
                autoCapitalize="none"
                spellCheck={false}
                placeholder="stripe.com"
                value={values.domain}
                invalid={Boolean(fieldErrors.domain)}
                onChange={update('domain')}
                disabled={submitting}
              />
            </Field>

            <div className="grid gap-5 sm:grid-cols-2">
              <Field label="Category" htmlFor="category">
                <Select id="category" value={values.category} onChange={update('category')} disabled={submitting}>
                  {CATEGORIES.map((option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </Select>
              </Field>
              <Field
                label="Criticality to your business"
                htmlFor="criticality"
                hint="How much damage would a breach here cause you?"
              >
                <Select
                  id="criticality"
                  value={values.criticality}
                  onChange={update('criticality')}
                  disabled={submitting}
                >
                  <option value="low">Low — limited impact</option>
                  <option value="medium">Medium — noticeable impact</option>
                  <option value="high">High — serious impact</option>
                  <option value="critical">Critical — business threatening</option>
                </Select>
              </Field>
            </div>

            <Field label="Internal owner" htmlFor="owner_label" hint="Who owns this relationship?">
              <Input
                id="owner_label"
                placeholder="Head of Finance"
                value={values.owner_label}
                onChange={update('owner_label')}
                disabled={submitting}
              />
            </Field>

            <Field
              label="What do they do for you?"
              htmlFor="description"
              hint="Useful context for your auditor. What data do they hold?"
            >
              <Textarea
                id="description"
                rows={3}
                placeholder="Card acquiring and payouts. Processes cardholder data on our behalf."
                value={values.description}
                onChange={update('description')}
                disabled={submitting}
              />
            </Field>

            <div className="flex gap-3 border-t border-ink-800 pt-5">
              <Button type="submit" loading={submitting} loadingLabel="Adding…">
                Add vendor and scan
              </Button>
              <Link
                href="/dashboard/vendors"
                className="inline-flex h-10 items-center rounded-sm px-4 text-sm text-silver-400 hover:text-silver-100"
              >
                Cancel
              </Link>
            </div>
          </form>
        </CardBody>
      </Card>
    </div>
  );
}
