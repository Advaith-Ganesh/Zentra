import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import {
  Banner,
  Button,
  Dialog,
  EmptyState,
  ErrorState,
  Field,
  InfoTooltip,
  Input,
} from '@/components/ui';

describe('Button', () => {
  it('is disabled and marked busy while loading', () => {
    render(<Button loading>Save</Button>);
    const button = screen.getByRole('button');
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute('aria-busy', 'true');
  });

  it('does not fire onClick while loading', async () => {
    const onClick = vi.fn();
    render(
      <Button loading onClick={onClick}>
        Save
      </Button>,
    );
    await userEvent.click(screen.getByRole('button'));
    expect(onClick).not.toHaveBeenCalled();
  });
});

describe('Field', () => {
  it('associates the label with its control', () => {
    render(
      <Field label="Vendor domain" htmlFor="domain">
        <Input id="domain" />
      </Field>,
    );
    expect(screen.getByLabelText(/vendor domain/i)).toBeInTheDocument();
  });

  it('announces an error and marks the input invalid', () => {
    render(
      <Field label="Domain" htmlFor="domain" error="Enter a valid domain.">
        <Input id="domain" invalid />
      </Field>,
    );
    expect(screen.getByRole('alert')).toHaveTextContent('Enter a valid domain.');
    expect(screen.getByLabelText('Domain')).toHaveAttribute('aria-invalid', 'true');
  });

  it('hides the hint once an error is shown', () => {
    render(
      <Field label="Domain" htmlFor="d" hint="A hint" error="An error">
        <Input id="d" />
      </Field>,
    );
    expect(screen.queryByText('A hint')).not.toBeInTheDocument();
  });
});

describe('EmptyState', () => {
  it('explains what to do next', () => {
    render(
      <EmptyState
        title="No vendors yet"
        description="Add your first vendor to start monitoring third-party risk."
        action={<Button>Add vendor</Button>}
      />,
    );
    expect(screen.getByText('No vendors yet')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Add vendor' })).toBeInTheDocument();
  });
});

describe('ErrorState', () => {
  it('offers a retry and shows the request reference', async () => {
    const onRetry = vi.fn();
    render(<ErrorState message="Could not load." onRetry={onRetry} requestId="req-1" />);
    expect(screen.getByRole('alert')).toBeInTheDocument();
    expect(screen.getByText(/req-1/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /try again/i }));
    expect(onRetry).toHaveBeenCalledOnce();
  });
});

describe('Banner', () => {
  it('uses an alert role for danger and status otherwise', () => {
    const { rerender } = render(<Banner tone="danger">Bad</Banner>);
    expect(screen.getByRole('alert')).toBeInTheDocument();
    rerender(<Banner tone="info">Note</Banner>);
    expect(screen.getByRole('status')).toBeInTheDocument();
  });
});

describe('Dialog', () => {
  it('renders nothing when closed', () => {
    render(
      <Dialog open={false} onClose={() => {}} title="Update">
        <p>Body</p>
      </Dialog>,
    );
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('is a modal dialog labelled by its title', () => {
    render(
      <Dialog open onClose={() => {}} title="Update finding">
        <p>Body</p>
      </Dialog>,
    );
    const dialog = screen.getByRole('dialog');
    expect(dialog).toHaveAttribute('aria-modal', 'true');
    expect(screen.getByText('Update finding')).toBeInTheDocument();
  });

  it('closes on Escape', async () => {
    const onClose = vi.fn();
    render(
      <Dialog open onClose={onClose} title="Update">
        <p>Body</p>
      </Dialog>,
    );
    await userEvent.keyboard('{Escape}');
    expect(onClose).toHaveBeenCalled();
  });
});

describe('InfoTooltip', () => {
  it('is keyboard reachable and reveals its explanation on focus', async () => {
    render(<InfoTooltip label="DKIM keys live under a private selector." />);
    const trigger = screen.getByRole('button');
    trigger.focus();
    expect(await screen.findByRole('tooltip')).toHaveTextContent(
      'DKIM keys live under a private selector.',
    );
  });
});
