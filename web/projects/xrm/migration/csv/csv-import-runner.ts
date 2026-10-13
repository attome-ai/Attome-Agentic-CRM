import type { ApiError } from '@attome/base';
import { chunkBody, type ImportChunk } from './csv-chunks';
import type {
  MigrationRunDetail,
  MigrationRunListItem,
  StagedImportResponse,
  ValidationReportItem,
} from './csv-import.service';

/**
 * U11 / D-606 — the staging and approval pump.
 *
 * Resume without duplicates rests on the server, not on this tab:
 * - each chunk becomes one staged import, linked to the import's migration
 *   project as one run, **in chunk order** — chunk k is linked only after
 *   chunk k-1's link succeeded, so the project's `stage`-mode runs are always
 *   exactly chunks 0..n-1 (`planResume` checks their sizes too);
 * - a staged import can be linked to one run only (409 on a second link);
 * - only a linked, `pending_review` import is ever approved, and approving
 *   one that is not `pending_review` is a 404 — the status claim in
 *   `bulk.rs::approve_staged_import` — so no chunk is applied twice;
 * - a chunk staged but never linked is an unapproved staged import: it
 *   writes no record, and a resume re-stages that chunk.
 * `x-idempotency-key` covers the transport: a request retried after a lost
 * response replays the first answer instead of running twice.
 */

/** Requests in flight at once (1–2: bounded, per D-606). */
export const IMPORT_CONCURRENCY = 2;

export interface ImportPort {
  stage(body: object, idempotencyKey: string): Promise<StagedImportResponse>;
  link(stagedImportId: string, idempotencyKey: string): Promise<MigrationRunDetail>;
  listRuns(): Promise<MigrationRunListItem[]>;
  approve(stagedImportId: string, idempotencyKey: string): Promise<unknown>;
}

export interface ResumePlan {
  /** Chunks 0..done-1 are already staged and linked. */
  done: number;
  /** The project's runs do not line up with this file's chunks. */
  mismatch: boolean;
}

/** The project's staged (not dry-run) runs, oldest first — chunk order. */
export function stagedRuns(runs: MigrationRunListItem[]): MigrationRunListItem[] {
  return runs
    .filter(r => r.mode !== 'dry_run')
    .sort((a, b) => a.created_at.localeCompare(b.created_at) || a.id.localeCompare(b.id));
}

export function planResume(runs: MigrationRunListItem[], chunks: ImportChunk[]): ResumePlan {
  const staged = stagedRuns(runs);
  const mismatch =
    staged.length > chunks.length || staged.some((run, k) => run.total !== chunks[k].records.length);
  return { done: mismatch ? 0 : staged.length, mismatch };
}

export interface ChunkResult {
  chunk: number;
  stagedImportId: string;
  passed: number;
  failed: number;
  rejected: number;
  /** Non-passing items of the chunk's validation report. */
  problems: ValidationReportItem[];
}

export interface StageOptions {
  projectId: string;
  /** Differs per start/resume click, so a stale key never blocks a new attempt. */
  attempt: string;
  mappingRef: string;
  fromChunk: number;
  concurrency?: number;
  onChunk: (result: ChunkResult) => void;
  shouldStop?: () => boolean;
}

export class ImportStopped extends Error {
  constructor() {
    super('stopped');
  }
}

function isNetworkError(e: unknown): boolean {
  return (e as ApiError | undefined)?.status === 0;
}

function isConflict(e: unknown): boolean {
  return (e as ApiError | undefined)?.status === 409;
}

function isNotFound(e: unknown): boolean {
  return (e as ApiError | undefined)?.status === 404;
}

/** One retry, same idempotency key, only when no response came back at all. */
async function withRetry<T>(call: () => Promise<T>): Promise<T> {
  try {
    return await call();
  } catch (e) {
    if (!isNetworkError(e)) throw e;
    return call();
  }
}

/**
 * Stages chunks `fromChunk..` with at most `concurrency` staging requests in
 * flight, and links them to the project strictly in order. The first failure
 * stops the pump (no new chunk starts) and is rethrown once every in-flight
 * chunk has settled.
 */
export async function stageChunks(port: ImportPort, chunks: ImportChunk[], opts: StageOptions): Promise<void> {
  const concurrency = Math.max(1, Math.min(opts.concurrency ?? IMPORT_CONCURRENCY, 2));
  const linked: Promise<void>[] = [];
  let next = opts.fromChunk;
  let failure: unknown = null;
  const stopped = () => failure !== null || (opts.shouldStop?.() ?? false);

  const runChunk = (i: number): Promise<void> => {
    const previous = i === opts.fromChunk ? Promise.resolve() : linked[i - 1];
    const done = (async () => {
      const chunk = chunks[i];
      const staged = await withRetry(() =>
        port.stage(chunkBody(chunk, opts.mappingRef, 'stage'), `csv-stage:${opts.projectId}:${i}:${opts.attempt}`),
      );
      await previous;
      if (stopped()) throw new ImportStopped();
      let detail: MigrationRunDetail | null = null;
      try {
        detail = await withRetry(() => port.link(staged.id, `csv-link:${opts.projectId}:${staged.id}`));
      } catch (e) {
        // 409: this staged import is already linked (a retried link whose
        // first response was lost). It is ours and in order; carry on.
        if (!isConflict(e)) throw e;
      }
      opts.onChunk({
        chunk: i,
        stagedImportId: staged.id,
        passed: staged.passed,
        failed: staged.failed,
        rejected: staged.rejected,
        problems: (detail?.validation_report ?? []).filter(item => item.status !== 'passed'),
      });
    })();
    linked[i] = done;
    return done;
  };

  const worker = async () => {
    while (next < chunks.length && !stopped()) {
      const i = next++;
      try {
        await runChunk(i);
      } catch (e) {
        // A real error outranks a stop.
        if (failure === null || (failure instanceof ImportStopped && !(e instanceof ImportStopped))) {
          failure = e;
        }
      }
    }
  };
  await Promise.all(Array.from({ length: concurrency }, worker));
  if (failure !== null) throw failure;
  if (opts.shouldStop?.() && next < chunks.length) throw new ImportStopped();
}

/**
 * Approves every staged run still `pending_review`, at most `concurrency` at
 * a time. A 404 means the import already left `pending_review` (approved by
 * an earlier attempt) and counts as done.
 */
export async function approveRuns(
  port: ImportPort,
  runs: MigrationRunListItem[],
  onApproved: (run: MigrationRunListItem) => void,
  concurrency = IMPORT_CONCURRENCY,
): Promise<void> {
  const pending = stagedRuns(runs).filter(r => r.import_status === 'pending_review');
  let next = 0;
  let failure: unknown = null;
  const worker = async () => {
    while (next < pending.length && failure === null) {
      const run = pending[next++];
      try {
        await withRetry(() => port.approve(run.staged_import_id, `csv-approve:${run.staged_import_id}`));
      } catch (e) {
        if (!isNotFound(e)) {
          failure = e;
          return;
        }
      }
      onApproved(run);
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(concurrency, 2)) }, worker));
  if (failure !== null) throw failure;
}
