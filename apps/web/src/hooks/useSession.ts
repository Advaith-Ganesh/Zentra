'use client';

import * as React from 'react';
import { useRouter } from 'next/navigation';
import { ApiError, api, session } from '@/lib/api';
import type { Me } from '@/lib/types';

interface SessionState {
  me: Me | null;
  loading: boolean;
  error: ApiError | null;
  refresh: () => Promise<void>;
  signOut: () => Promise<void>;
}

/**
 * Loads the signed-in user's context.
 *
 * `loading` is derived from whether a result has settled rather than stored
 * separately, so no state is written synchronously during the effect body.
 * Redirects to sign-in on 401 so an expired token cannot leave the dashboard
 * in a broken half-state.
 */
export function useSession(options: { redirectOnFailure?: boolean } = {}): SessionState {
  const { redirectOnFailure = true } = options;
  const router = useRouter();
  const [settled, setSettled] = React.useState<{ me: Me | null; error: ApiError | null } | null>(
    null,
  );

  const load = React.useCallback(async () => {
    setSettled(await loadSession(redirectOnFailure, router));
  }, [router, redirectOnFailure]);

  React.useEffect(() => {
    let cancelled = false;
    const run = async () => {
      const result = await loadSession(redirectOnFailure, router);
      if (!cancelled) setSettled(result);
    };
    void run();
    return () => {
      cancelled = true;
    };
  }, [router, redirectOnFailure]);

  const signOut = React.useCallback(async () => {
    try {
      await api.auth.signOut();
    } catch {
      /* the token is discarded either way */
    }
    session.clear();
    router.replace('/auth/sign-in');
  }, [router]);

  return {
    me: settled?.me ?? null,
    loading: settled === null,
    error: settled?.error ?? null,
    refresh: load,
    signOut,
  };
}

/**
 * Performs the account load and resolves the settled state.
 *
 * Kept outside the component so the effect below has no synchronous state
 * write in its body: the result is only applied after the request resolves.
 */
async function loadSession(
  redirectOnFailure: boolean,
  router: ReturnType<typeof useRouter>,
): Promise<{ me: Me | null; error: ApiError | null }> {
  try {
    // Deliberately attempted even without a stored token: the API answers 401
    // and the catch below handles it uniformly.
    const result = await api.me();
    session.setOrganizationId(result.organization.id);
    return { me: result, error: null };
  } catch (caught) {
    const apiError =
      caught instanceof ApiError
        ? caught
        : new ApiError(0, 'UNKNOWN', 'Could not load your account.');
    if (apiError.isAuthError && redirectOnFailure) {
      session.clear();
      router.replace('/auth/sign-in');
    }
    return { me: null, error: apiError };
  }
}

interface AsyncState<T> {
  data: T | null;
  loading: boolean;
  error: ApiError | null;
  reload: () => void;
}

/**
 * A small data-loading helper.
 *
 * `loading` is derived by comparing the settled result's dependency key with
 * the current one, so a dependency change shows a loading state without any
 * synchronous state write inside the effect.
 */
export function useAsync<T>(
  loader: () => Promise<T>,
  deps: React.DependencyList,
): AsyncState<T> {
  const [nonce, setNonce] = React.useState(0);
  const key = `${deps.map((dep) => String(dep)).join('|')}|${nonce}`;
  const [settled, setSettled] = React.useState<{
    key: string;
    data: T | null;
    error: ApiError | null;
  } | null>(null);

  React.useEffect(() => {
    let cancelled = false;
    const run = async () => {
      try {
        const result = await loader();
        if (!cancelled) setSettled({ key, data: result, error: null });
      } catch (caught) {
        if (cancelled) return;
        setSettled({
          key,
          data: null,
          error:
            caught instanceof ApiError
              ? caught
              : new ApiError(0, 'UNKNOWN', 'Something went wrong.'),
        });
      }
    };
    void run();
    return () => {
      cancelled = true;
    };
    // `loader` is recreated on every render by design; `key` captures the
    // inputs that should actually trigger a refetch.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  return {
    data: settled?.data ?? null,
    loading: settled?.key !== key,
    error: settled?.error ?? null,
    reload: () => setNonce((n) => n + 1),
  };
}
