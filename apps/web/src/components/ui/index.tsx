/**
 * Zentra design system.
 *
 * A small, deliberate set of primitives. Everything is keyboard reachable,
 * has a visible focus ring, and never relies on colour alone to convey state.
 */

'use client';

import * as React from 'react';
import { cn } from '@/lib/utils';

// ---------------------------------------------------------------------- Button
const BUTTON_VARIANTS = {
  primary:
    'bg-silver-50 text-ink-950 hover:bg-white active:bg-silver-100 border border-transparent font-medium',
  secondary:
    'bg-ink-800 text-silver-100 hover:bg-ink-750 border border-ink-600 hover:border-ink-500',
  ghost: 'bg-transparent text-silver-300 hover:text-silver-50 hover:bg-ink-800 border border-transparent',
  danger:
    'bg-transparent text-risk-critical border border-risk-critical/45 hover:bg-risk-critical-dim',
  outline:
    'bg-transparent text-silver-100 border border-silver-500/40 hover:border-silver-400 hover:bg-ink-850',
} as const;

const BUTTON_SIZES = {
  sm: 'h-8 px-3 text-xs',
  md: 'h-10 px-4 text-sm',
  lg: 'h-12 px-6 text-sm',
} as const;

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: keyof typeof BUTTON_VARIANTS;
  size?: keyof typeof BUTTON_SIZES;
  loading?: boolean;
  loadingLabel?: string;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { className, variant = 'primary', size = 'md', loading, loadingLabel, children, disabled, ...props },
  ref,
) {
  return (
    <button
      ref={ref}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      className={cn(
        'inline-flex items-center justify-center gap-2 rounded-sm transition-colors',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-silver-200 focus-visible:ring-offset-2 focus-visible:ring-offset-ink-950',
        'disabled:cursor-not-allowed disabled:opacity-45',
        BUTTON_VARIANTS[variant],
        BUTTON_SIZES[size],
        className,
      )}
      {...props}
    >
      {loading && <Spinner className="h-3.5 w-3.5" />}
      {loading && loadingLabel ? loadingLabel : children}
    </button>
  );
});

export function Spinner({ className }: { className?: string }) {
  return (
    <span
      role="status"
      aria-label="Loading"
      className={cn(
        'inline-block animate-spin rounded-full border-2 border-current border-t-transparent',
        className ?? 'h-4 w-4',
      )}
    />
  );
}

// ------------------------------------------------------------------------ Card
export function Card({
  className,
  children,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn('border border-ink-700 bg-ink-900 rounded-sm', className)}
      {...props}
    >
      {children}
    </div>
  );
}

export function CardHeader({
  title,
  description,
  action,
  className,
}: {
  title: React.ReactNode;
  description?: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        'flex items-start justify-between gap-4 border-b border-ink-750 px-5 py-4',
        className,
      )}
    >
      <div className="min-w-0">
        <h2 className="text-sm font-medium text-silver-50">{title}</h2>
        {description && (
          <p className="mt-1 text-xs text-silver-400">{description}</p>
        )}
      </div>
      {action && <div className="shrink-0">{action}</div>}
    </div>
  );
}

export function CardBody({
  className,
  children,
}: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('px-5 py-4', className)}>{children}</div>;
}

// ----------------------------------------------------------------------- Badge
export function Badge({
  children,
  className,
  glyph,
  title,
}: {
  children: React.ReactNode;
  className?: string;
  glyph?: string;
  title?: string;
}) {
  return (
    <span
      title={title}
      className={cn(
        'inline-flex items-center gap-1.5 whitespace-nowrap rounded-sm border px-2 py-0.5',
        'text-2xs font-semibold uppercase tracking-governance',
        className,
      )}
    >
      {glyph && (
        <span aria-hidden="true" className="text-[0.7em] leading-none">
          {glyph}
        </span>
      )}
      {children}
    </span>
  );
}

// ----------------------------------------------------------------------- Input
export interface FieldProps {
  label: string;
  htmlFor: string;
  hint?: React.ReactNode;
  error?: string | null;
  required?: boolean;
  children: React.ReactNode;
}

export function Field({ label, htmlFor, hint, error, required, children }: FieldProps) {
  return (
    <div className="space-y-1.5">
      <label
        htmlFor={htmlFor}
        className="block text-xs font-medium uppercase tracking-governance text-silver-400"
      >
        {label}
        {required && (
          <span className="ml-1 text-risk-high" aria-hidden="true">
            *
          </span>
        )}
      </label>
      {children}
      {hint && !error && <p className="text-xs text-silver-500">{hint}</p>}
      {error && (
        <p role="alert" className="flex items-start gap-1.5 text-xs text-risk-critical">
          <span aria-hidden="true">✕</span>
          {error}
        </p>
      )}
    </div>
  );
}

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement> & { invalid?: boolean }>(
  function Input({ className, invalid, ...props }, ref) {
    return (
      <input
        ref={ref}
        aria-invalid={invalid || undefined}
        className={cn(
          'w-full rounded-sm border bg-ink-850 px-3 py-2 text-sm text-silver-50',
          'placeholder:text-silver-600',
          'focus:outline-none focus:ring-2 focus:ring-silver-300 focus:ring-offset-2 focus:ring-offset-ink-950',
          'disabled:cursor-not-allowed disabled:opacity-50',
          invalid ? 'border-risk-critical/60' : 'border-ink-600 hover:border-ink-500',
          className,
        )}
        {...props}
      />
    );
  },
);

export const Textarea = React.forwardRef<
  HTMLTextAreaElement,
  React.TextareaHTMLAttributes<HTMLTextAreaElement>
>(function Textarea({ className, ...props }, ref) {
  return (
    <textarea
      ref={ref}
      className={cn(
        'w-full rounded-sm border border-ink-600 bg-ink-850 px-3 py-2 text-sm text-silver-50',
        'placeholder:text-silver-600 hover:border-ink-500',
        'focus:outline-none focus:ring-2 focus:ring-silver-300 focus:ring-offset-2 focus:ring-offset-ink-950',
        className,
      )}
      {...props}
    />
  );
});

export const Select = React.forwardRef<
  HTMLSelectElement,
  React.SelectHTMLAttributes<HTMLSelectElement>
>(function Select({ className, children, ...props }, ref) {
  return (
    <select
      ref={ref}
      className={cn(
        'w-full appearance-none rounded-sm border border-ink-600 bg-ink-850 px-3 py-2 text-sm text-silver-50',
        'hover:border-ink-500',
        'focus:outline-none focus:ring-2 focus:ring-silver-300 focus:ring-offset-2 focus:ring-offset-ink-950',
        className,
      )}
      {...props}
    >
      {children}
    </select>
  );
});

// ----------------------------------------------------------------------- Table
export function Table({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className="w-full overflow-x-auto">
      <table className={cn('w-full min-w-[720px] border-collapse text-sm', className)}>
        {children}
      </table>
    </div>
  );
}

export function Th({
  children,
  className,
  scope = 'col',
  ...props
}: React.ThHTMLAttributes<HTMLTableCellElement>) {
  return (
    <th
      scope={scope}
      className={cn(
        'border-b border-ink-700 px-4 py-3 text-left text-2xs font-semibold uppercase tracking-governance text-silver-500',
        className,
      )}
      {...props}
    >
      {children}
    </th>
  );
}

export function Td({
  children,
  className,
  ...props
}: React.TdHTMLAttributes<HTMLTableCellElement>) {
  return (
    <td className={cn('border-b border-ink-800 px-4 py-3 align-middle', className)} {...props}>
      {children}
    </td>
  );
}

// ------------------------------------------------------------------- States
export function EmptyState({
  title,
  description,
  action,
  icon,
}: {
  title: string;
  description: string;
  action?: React.ReactNode;
  icon?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-14 text-center">
      {icon && <div className="mb-4 text-silver-500">{icon}</div>}
      <h3 className="text-sm font-medium text-silver-100">{title}</h3>
      <p className="mt-2 max-w-sm text-sm text-silver-400">{description}</p>
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

export function LoadingState({ label = 'Loading…', rows = 3 }: { label?: string; rows?: number }) {
  return (
    <div className="px-5 py-6" role="status" aria-live="polite">
      <span className="sr-only">{label}</span>
      <div className="space-y-3">
        {Array.from({ length: rows }).map((_, index) => (
          <div
            key={index}
            className="relative h-4 overflow-hidden rounded-sm bg-ink-800"
            aria-hidden="true"
          >
            <div className="absolute inset-0 -translate-x-full animate-shimmer bg-gradient-to-r from-transparent via-ink-700 to-transparent" />
          </div>
        ))}
      </div>
    </div>
  );
}

export function ErrorState({
  title = 'Something went wrong',
  message,
  onRetry,
  requestId,
}: {
  title?: string;
  message: string;
  onRetry?: () => void;
  requestId?: string;
}) {
  return (
    <div role="alert" className="px-5 py-10 text-center">
      <p className="text-sm font-medium text-silver-100">{title}</p>
      <p className="mx-auto mt-2 max-w-md text-sm text-silver-400">{message}</p>
      {requestId && (
        <p className="mt-2 font-mono text-2xs text-silver-600">Reference: {requestId}</p>
      )}
      {onRetry && (
        <div className="mt-5">
          <Button variant="secondary" size="sm" onClick={onRetry}>
            Try again
          </Button>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------- Dialog
export function Dialog({
  open,
  onClose,
  title,
  description,
  children,
  footer,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children: React.ReactNode;
  footer?: React.ReactNode;
}) {
  const panelRef = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
      // Trap focus inside the dialog.
      if (event.key === 'Tab' && panelRef.current) {
        const focusable = panelRef.current.querySelectorAll<HTMLElement>(
          'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])',
        );
        if (focusable.length === 0) return;
        const first = focusable[0]!;
        const last = focusable[focusable.length - 1]!;
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener('keydown', onKeyDown);
    const previouslyFocused = document.activeElement as HTMLElement | null;
    panelRef.current?.querySelector<HTMLElement>('input, button')?.focus();
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      previouslyFocused?.focus?.();
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div
        className="absolute inset-0 bg-ink-950/85 backdrop-blur-sm"
        onClick={onClose}
        aria-hidden="true"
      />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="dialog-title"
        className="relative w-full max-w-lg animate-fade-in border border-ink-700 bg-ink-900 rounded-sm shadow-2xl"
      >
        <div className="border-b border-ink-750 px-5 py-4">
          <h2 id="dialog-title" className="text-sm font-medium text-silver-50">
            {title}
          </h2>
          {description && <p className="mt-1 text-xs text-silver-400">{description}</p>}
        </div>
        <div className="px-5 py-4">{children}</div>
        {footer && (
          <div className="flex justify-end gap-2 border-t border-ink-750 px-5 py-3">{footer}</div>
        )}
      </div>
    </div>
  );
}

// --------------------------------------------------------------------- Tooltip
export function InfoTooltip({ label, children }: { label: string; children?: React.ReactNode }) {
  const [open, setOpen] = React.useState(false);
  const id = React.useId();
  return (
    <span className="relative inline-flex">
      <button
        type="button"
        aria-describedby={open ? id : undefined}
        aria-label={`More information: ${label}`}
        onMouseEnter={() => setOpen(true)}
        onMouseLeave={() => setOpen(false)}
        onFocus={() => setOpen(true)}
        onBlur={() => setOpen(false)}
        onClick={() => setOpen((v) => !v)}
        className="ml-1.5 inline-flex h-4 w-4 items-center justify-center rounded-full border border-silver-600 text-[9px] text-silver-400 hover:border-silver-400 hover:text-silver-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-silver-300"
      >
        {children ?? 'i'}
      </button>
      {open && (
        <span
          id={id}
          role="tooltip"
          className="absolute left-1/2 top-6 z-40 w-64 -translate-x-1/2 rounded-sm border border-ink-600 bg-ink-850 px-3 py-2 text-xs font-normal normal-case tracking-normal text-silver-200 shadow-xl"
        >
          {label}
        </span>
      )}
    </span>
  );
}

// ------------------------------------------------------------------- Banner
export function Banner({
  tone = 'info',
  title,
  children,
  action,
}: {
  tone?: 'info' | 'warning' | 'danger' | 'success';
  title?: string;
  children: React.ReactNode;
  action?: React.ReactNode;
}) {
  const tones = {
    info: 'border-ink-600 bg-ink-850 text-silver-200',
    warning: 'border-risk-medium/40 bg-risk-medium-dim text-risk-medium',
    danger: 'border-risk-critical/45 bg-risk-critical-dim text-risk-critical',
    success: 'border-risk-low/40 bg-risk-low-dim text-risk-low',
  } as const;
  const glyphs = { info: 'i', warning: '!', danger: '✕', success: '✓' } as const;
  return (
    <div
      role={tone === 'danger' ? 'alert' : 'status'}
      className={cn(
        'flex items-start gap-3 rounded-sm border px-4 py-3 text-sm',
        tones[tone],
      )}
    >
      <span aria-hidden="true" className="mt-0.5 text-xs font-bold">
        {glyphs[tone]}
      </span>
      <div className="min-w-0 flex-1">
        {title && <p className="font-medium">{title}</p>}
        <div className={cn(title && 'mt-1', 'text-silver-300')}>{children}</div>
      </div>
      {action && <div className="shrink-0">{action}</div>}
    </div>
  );
}
