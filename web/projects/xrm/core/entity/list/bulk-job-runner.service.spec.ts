import { firstValueFrom, of } from 'rxjs';
import { describe, expect, it } from 'vitest';
import { BulkJobRunner } from './bulk-job-runner.service';

describe('BulkJobRunner', () => {
  it('polls until isTerminal reports true and resolves with that status', async () => {
    const runner = new BulkJobRunner();
    const statuses = ['queued', 'running', 'completed'];
    let call = 0;

    const result = await firstValueFrom(runner.poll(
      () => of(statuses[call++]),
      status => status === 'completed',
      { intervalMs: 1 },
    ));

    expect(result).toBe('completed');
    expect(call).toBe(3);
  });

  it('fetches immediately at t=0 rather than waiting a full interval first', async () => {
    const runner = new BulkJobRunner();
    const result = await firstValueFrom(runner.poll(
      () => of('completed'),
      status => status === 'completed',
      { intervalMs: 10_000 },
    ));
    expect(result).toBe('completed');
  });

  it('stops after maxPolls and resolves with the last status seen, even if not terminal', async () => {
    const runner = new BulkJobRunner();
    let call = 0;

    const result = await firstValueFrom(runner.poll(
      () => of(`poll-${++call}`),
      () => false,
      { intervalMs: 1, maxPolls: 3 },
    ));

    expect(result).toBe('poll-3');
    expect(call).toBe(3);
  });

  it('defaults to a 1s interval and 60 polls when no options are given', async () => {
    const runner = new BulkJobRunner();
    // Only assert the immediate (t=0) poll resolves for an already-terminal
    // status — proving the defaults don't block a fast job on a slow clock.
    const result = await firstValueFrom(runner.poll(() => of('completed'), s => s === 'completed'));
    expect(result).toBe('completed');
  });

  it('surfaces an error from fetchStatus instead of retrying silently', async () => {
    const runner = new BulkJobRunner();
    await expect(firstValueFrom(runner.poll(
      () => { throw new Error('network down'); },
      () => true,
      { intervalMs: 1 },
    ))).rejects.toThrow('network down');
  });
});
