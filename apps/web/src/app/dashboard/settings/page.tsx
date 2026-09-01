'use client';

import * as React from 'react';
import {
  Badge,
  Banner,
  Button,
  Card,
  CardBody,
  CardHeader,
  Dialog,
  EmptyState,
  ErrorState,
  Field,
  Input,
  LoadingState,
  Select,
  Table,
  Td,
  Th,
} from '@/components/ui';
import { useAsync, useSession } from '@/hooks/useSession';
import { ApiError, api } from '@/lib/api';
import { formatDate, relativeTime } from '@/lib/utils';
import type { ApiKey, Benchmark, Member } from '@/lib/types';

export default function SettingsPage() {
  const { me, loading, refresh } = useSession();
  if (loading) return <LoadingState label="Loading settings…" rows={5} />;
  if (!me) return null;

  const canManage = ['owner', 'admin'].includes(me.role);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-silver-50">Settings</h1>
        <p className="mt-1 text-sm text-silver-400">
          Your organization, team, integrations and API access.
        </p>
      </div>

      <OrganizationCard name={me.organization.name} canManage={canManage} onSaved={refresh} />
      <MembersCard canManage={canManage} multiUser={me.entitlements.features.includes('multi_user')} />
      {me.feature_flags.benchmarking && me.entitlements.features.includes('benchmarking') && (
        <BenchmarkCard />
      )}
      {me.feature_flags.teams && <TeamsCard canManage={canManage} />}
      {me.feature_flags.public_api && (
        <ApiKeysCard canManage={canManage} enabled={me.entitlements.features.includes('public_api')} />
      )}
    </div>
  );
}

function OrganizationCard({
  name,
  canManage,
  onSaved,
}: {
  name: string;
  canManage: boolean;
  onSaved: () => void;
}) {
  const [value, setValue] = React.useState(name);
  const [saving, setSaving] = React.useState(false);
  const [message, setMessage] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  async function save(event: React.FormEvent) {
    event.preventDefault();
    setSaving(true);
    setError(null);
    setMessage(null);
    try {
      await api.organization.update({ name: value.trim() });
      setMessage('Saved.');
      onSaved();
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'Could not save.');
    } finally {
      setSaving(false);
    }
  }

  return (
    <Card>
      <CardHeader title="Organization" description="How your company appears in Zentra and in reports." />
      <CardBody>
        {error && <div className="mb-4"><Banner tone="danger">{error}</Banner></div>}
        {message && <div className="mb-4"><Banner tone="success">{message}</Banner></div>}
        <form onSubmit={save} className="flex flex-col gap-3 sm:flex-row sm:items-end">
          <div className="flex-1">
            <Field label="Company name" htmlFor="org-name">
              <Input
                id="org-name"
                value={value}
                onChange={(event) => setValue(event.target.value)}
                disabled={!canManage || saving}
              />
            </Field>
          </div>
          <Button type="submit" variant="secondary" disabled={!canManage} loading={saving}>
            Save
          </Button>
        </form>
        {!canManage && (
          <p className="mt-3 text-xs text-silver-500">
            Only owners and admins can change organization settings.
          </p>
        )}
      </CardBody>
    </Card>
  );
}

function MembersCard({ canManage, multiUser }: { canManage: boolean; multiUser: boolean }) {
  const [nonce, setNonce] = React.useState(0);
  const { data, loading, error, reload } = useAsync<Member[]>(
    () => api.organization.members(),
    [nonce],
  );
  const [inviteOpen, setInviteOpen] = React.useState(false);
  const [email, setEmail] = React.useState('');
  const [role, setRole] = React.useState('analyst');
  const [inviting, setInviting] = React.useState(false);
  const [inviteError, setInviteError] = React.useState<string | null>(null);
  const [inviteMessage, setInviteMessage] = React.useState<string | null>(null);

  async function invite() {
    setInviting(true);
    setInviteError(null);
    try {
      await api.organization.invite({ email: email.trim(), role });
      setInviteMessage(`Invitation sent to ${email.trim()}.`);
      setInviteOpen(false);
      setEmail('');
      setNonce((n) => n + 1);
    } catch (caught) {
      setInviteError(caught instanceof ApiError ? caught.message : 'The invitation failed.');
    } finally {
      setInviting(false);
    }
  }

  return (
    <>
      <Card>
        <CardHeader
          title="Team"
          description="People who can see and act on your vendor risk register."
          action={
            canManage && multiUser ? (
              <Button size="sm" variant="secondary" onClick={() => setInviteOpen(true)}>
                Invite teammate
              </Button>
            ) : null
          }
        />
        {inviteMessage && (
          <p className="border-b border-ink-800 px-5 py-3 text-sm text-risk-low">{inviteMessage}</p>
        )}
        {!multiUser && (
          <p className="border-b border-ink-800 px-5 py-3 text-sm text-silver-500">
            Multiple users are available on the Growth plan and above.
          </p>
        )}
        {loading && <LoadingState rows={2} />}
        {error && <ErrorState message={error.message} onRetry={reload} />}
        {data && (
          <Table>
            <thead>
              <tr>
                <Th>Person</Th>
                <Th className="w-28">Role</Th>
                <Th className="w-28">Status</Th>
                <Th className="w-32">Joined</Th>
              </tr>
            </thead>
            <tbody>
              {data.map((member) => (
                <tr key={member.id}>
                  <Td>
                    <span className="text-silver-100">{member.full_name ?? member.email}</span>
                    <span className="block text-xs text-silver-500">{member.email}</span>
                  </Td>
                  <Td>
                    <Badge className="border-ink-600 text-silver-300">{member.role}</Badge>
                  </Td>
                  <Td className="text-xs capitalize text-silver-400">{member.status}</Td>
                  <Td className="text-xs text-silver-400">{formatDate(member.created_at)}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>

      <Dialog
        open={inviteOpen}
        onClose={() => setInviteOpen(false)}
        title="Invite a teammate"
        description="They will receive an email with a link that expires in 7 days."
        footer={
          <>
            <Button variant="ghost" onClick={() => setInviteOpen(false)} disabled={inviting}>
              Cancel
            </Button>
            <Button onClick={() => void invite()} loading={inviting} loadingLabel="Sending…">
              Send invitation
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          {inviteError && <Banner tone="danger">{inviteError}</Banner>}
          <Field label="Email address" htmlFor="invite-email" required>
            <Input
              id="invite-email"
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
            />
          </Field>
          <Field label="Role" htmlFor="invite-role">
            <Select id="invite-role" value={role} onChange={(event) => setRole(event.target.value)}>
              <option value="viewer">Viewer — read only</option>
              <option value="analyst">Analyst — can add vendors and update findings</option>
              <option value="admin">Admin — can manage the team and billing</option>
            </Select>
          </Field>
        </div>
      </Dialog>
    </>
  );
}

function BenchmarkCard() {
  const { data, loading, error } = useAsync<Benchmark>(() => api.benchmark(), []);
  return (
    <Card>
      <CardHeader
        title="Benchmarking"
        description="How your vendor stack compares with similar companies, using anonymized aggregate data only."
      />
      <CardBody>
        {loading && <LoadingState rows={2} />}
        {error && <p className="text-sm text-silver-500">{error.message}</p>}
        {data && (
          <>
            <p className="text-sm text-silver-300">{data.message}</p>
            {data.available && (
              <dl className="mt-4 grid grid-cols-2 gap-4 text-xs sm:grid-cols-4">
                <div>
                  <dt className="text-silver-500">Your average</dt>
                  <dd className="mt-1 text-lg font-semibold text-silver-50">
                    {data.your_average_score ?? '—'}
                  </dd>
                </div>
                <div>
                  <dt className="text-silver-500">Cohort median</dt>
                  <dd className="mt-1 text-lg font-semibold text-silver-200">
                    {data.cohort_median ?? '—'}
                  </dd>
                </div>
                <div>
                  <dt className="text-silver-500">Best quartile</dt>
                  <dd className="mt-1 text-lg text-silver-300">{data.cohort_p25 ?? '—'}</dd>
                </div>
                <div>
                  <dt className="text-silver-500">Worst quartile</dt>
                  <dd className="mt-1 text-lg text-silver-300">{data.cohort_p75 ?? '—'}</dd>
                </div>
              </dl>
            )}
            <p className="mt-4 text-2xs leading-relaxed text-silver-600">
              Benchmarks are computed from aggregated, anonymized data across organizations that
              opted in. A cohort is only shown once it contains enough organizations to be
              statistically meaningful; the sample size shown is the real one.
            </p>
          </>
        )}
      </CardBody>
    </Card>
  );
}

function TeamsCard({ canManage }: { canManage: boolean }) {
  const [nonce, setNonce] = React.useState(0);
  const { data } = useAsync(() => api.integrations.list(), [nonce]);
  const [url, setUrl] = React.useState('');
  const [saving, setSaving] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const connected = (data ?? []).find((item) => item.provider === 'teams');

  async function connect(event: React.FormEvent) {
    event.preventDefault();
    setSaving(true);
    setError(null);
    try {
      await api.integrations.connectTeams(url.trim());
      setUrl('');
      setNonce((n) => n + 1);
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'Could not connect Teams.');
    } finally {
      setSaving(false);
    }
  }

  async function disconnect() {
    setSaving(true);
    try {
      await api.integrations.disconnectTeams();
      setNonce((n) => n + 1);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Card>
      <CardHeader
        title="Microsoft Teams alerts"
        description="Send risk-change alerts to a Teams channel using an incoming webhook."
      />
      <CardBody>
        {error && <div className="mb-4"><Banner tone="danger">{error}</Banner></div>}
        {connected ? (
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <Badge className="border-risk-low/45 text-risk-low">Connected</Badge>
              <p className="mt-2 text-sm text-silver-400">
                Alerts are delivered to your configured Teams channel. The webhook URL is stored
                encrypted and is never shown again.
              </p>
            </div>
            <Button variant="ghost" size="sm" onClick={() => void disconnect()} disabled={!canManage} loading={saving}>
              Disconnect
            </Button>
          </div>
        ) : (
          <form onSubmit={connect} className="flex flex-col gap-3 sm:flex-row sm:items-end">
            <div className="flex-1">
              <Field
                label="Incoming webhook URL"
                htmlFor="teams-webhook"
                hint="From Teams: channel → Connectors → Incoming Webhook. Only Microsoft webhook addresses are accepted."
              >
                <Input
                  id="teams-webhook"
                  type="url"
                  placeholder="https://yourcompany.webhook.office.com/webhookb2/…"
                  value={url}
                  onChange={(event) => setUrl(event.target.value)}
                  disabled={!canManage || saving}
                />
              </Field>
            </div>
            <Button type="submit" variant="secondary" disabled={!canManage} loading={saving}>
              Connect
            </Button>
          </form>
        )}
      </CardBody>
    </Card>
  );
}

function ApiKeysCard({ canManage, enabled }: { canManage: boolean; enabled: boolean }) {
  const [nonce, setNonce] = React.useState(0);
  const { data, loading } = useAsync<ApiKey[]>(() => api.apiKeys.list(), [nonce]);
  const [createOpen, setCreateOpen] = React.useState(false);
  const [name, setName] = React.useState('');
  const [creating, setCreating] = React.useState(false);
  const [secret, setSecret] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  async function create() {
    setCreating(true);
    setError(null);
    try {
      const result = await api.apiKeys.create({ name: name.trim() });
      setSecret(result.secret);
      setName('');
      setCreateOpen(false);
      setNonce((n) => n + 1);
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'The key could not be created.');
    } finally {
      setCreating(false);
    }
  }

  async function revoke(id: string) {
    await api.apiKeys.revoke(id);
    setNonce((n) => n + 1);
  }

  return (
    <>
      <Card>
        <CardHeader
          title="API keys"
          description="Programmatic access to your vendor register. Available on the Scale plan."
          action={
            canManage && enabled ? (
              <Button size="sm" variant="secondary" onClick={() => setCreateOpen(true)}>
                Create key
              </Button>
            ) : null
          }
        />
        {!enabled && (
          <p className="border-b border-ink-800 px-5 py-3 text-sm text-silver-500">
            API access is available on the Scale plan.
          </p>
        )}
        {secret && (
          <div className="border-b border-ink-800 px-5 py-4">
            <Banner tone="warning" title="Copy this key now">
              Zentra stores only a hash of your key and cannot show it again.
              <code className="mt-3 block break-all rounded-sm border border-ink-600 bg-ink-950 p-3 font-mono text-xs text-silver-100">
                {secret}
              </code>
              <div className="mt-3">
                <Button size="sm" variant="ghost" onClick={() => setSecret(null)}>
                  I have copied it
                </Button>
              </div>
            </Banner>
          </div>
        )}
        {loading && <LoadingState rows={2} />}
        {data && data.length === 0 && !loading && (
          <EmptyState title="No API keys" description="Create a key to use Zentra's REST API." />
        )}
        {data && data.length > 0 && (
          <Table>
            <thead>
              <tr>
                <Th>Name</Th>
                <Th className="w-44">Key</Th>
                <Th className="w-32">Last used</Th>
                <Th className="w-28">Status</Th>
                <Th className="w-24 text-right">Actions</Th>
              </tr>
            </thead>
            <tbody>
              {data.map((key) => (
                <tr key={key.id}>
                  <Td className="text-silver-100">{key.name}</Td>
                  <Td className="font-mono text-xs text-silver-400">{key.key_prefix}…</Td>
                  <Td className="text-xs text-silver-400">{relativeTime(key.last_used_at)}</Td>
                  <Td>
                    {key.revoked_at ? (
                      <Badge className="border-ink-600 text-silver-500">Revoked</Badge>
                    ) : (
                      <Badge className="border-risk-low/45 text-risk-low">Active</Badge>
                    )}
                  </Td>
                  <Td className="text-right">
                    {!key.revoked_at && canManage && (
                      <Button size="sm" variant="ghost" onClick={() => void revoke(key.id)}>
                        Revoke
                      </Button>
                    )}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>

      <Dialog
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title="Create an API key"
        description="The secret is shown once and cannot be recovered."
        footer={
          <>
            <Button variant="ghost" onClick={() => setCreateOpen(false)} disabled={creating}>
              Cancel
            </Button>
            <Button onClick={() => void create()} loading={creating} loadingLabel="Creating…">
              Create key
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          {error && <Banner tone="danger">{error}</Banner>}
          <Field label="Key name" htmlFor="key-name" hint="Something that says where it is used." required>
            <Input
              id="key-name"
              placeholder="CI pipeline"
              value={name}
              onChange={(event) => setName(event.target.value)}
            />
          </Field>
        </div>
      </Dialog>
    </>
  );
}
