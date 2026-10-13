import { describe, expect, it } from 'vitest';
import { chunkRecords, type ImportChunk } from './csv-chunks';
import { approveRuns, ImportStopped, planResume, stageChunks, type ImportPort } from './csv-import-runner';
import type { MigrationRunListItem } from './csv-import.service';

function makeChunks(rows: number): ImportChunk[] {
  return chunkRecords(Array.from({ length: rows }, (_, index) => ({ index, data: { n: index } })));
}

function run(i: number, total: number, overrides: Partial<MigrationRunListItem> = {}): MigrationRunListItem {
  return {
    id: `run-${i}`, project_id: 'p', staged_import_id: `si-${i}`, entity_logicalname: 'contact',
    operation: 'create', mode: 'stage', import_status: 'pending_review', total, rejected: 0,
    rollback_status: 'none', created_by: 'u', created_at: `2026-09-23T10:00:${String(i).padStart(2, '0')}Z`,
    ...overrides,
  };
}

/** A fake server: records every call, links runs, answers like the real routes. */
function fakePort(opts: { failStageAt?: number; stageDelay?: (i: number) => number } = {}) {
  const calls: string[] = [];
  const staged: { id: string; body: { records: unknown[]; mode: string }; key: string }[] = [];
  const linked: string[] = [];
  let inFlight = 0;
  let maxInFlight = 0;
  let stageCount = 0;
  const port: ImportPort = {
    async stage(body, key) {
      const b = body as { records: unknown[]; mode: string };
      const i = stageCount++;
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise(r => setTimeout(r, opts.stageDelay?.(i) ?? 0));
      inFlight--;
      if (opts.failStageAt === i) throw { status: 500, kind: 'internal', message: 'boom' };
      const id = `si-${i}`;
      staged.push({ id, body: b, key });
      calls.push(`stage:${key}`);
      return { id, status: 'pending_review', total: b.records.length, passed: b.records.length, failed: 0, rejected: 0 };
    },
    async link(id) {
      linked.push(id);
      calls.push(`link:${id}`);
      return { validation_report: [{ index: 0, status: 'failed', error: 'bad' }] } as never;
    },
    async listRuns() {
      return [];
    },
    async approve(id) {
      calls.push(`approve:${id}`);
      return {};
    },
  };
  return { port, calls, staged, linked, maxInFlight: () => maxInFlight };
}

describe('stageChunks', () => {
  it('stages every chunk as at most 500 records, 2 in flight, linked in chunk order', async () => {
    const chunks = makeChunks(2300);
    // Chunk 0 is slow, so later chunks finish staging first.
    const f = fakePort({ stageDelay: i => (i === 0 ? 30 : 1) });
    const results: number[] = [];
    await stageChunks(f.port, chunks, {
      projectId: 'p', attempt: 'a1', mappingRef: 'm', fromChunk: 0,
      onChunk: r => results.push(r.chunk),
    });
    expect(f.staged.map(s => s.body.records.length)).toEqual(expect.arrayContaining([500, 300]));
    expect(f.staged.every(s => s.body.records.length <= 500 && s.body.mode === 'stage')).toBe(true);
    expect(f.staged.length).toBe(5);
    expect(f.maxInFlight()).toBe(2);
    // Linked strictly in chunk order even though chunk 0 staged last.
    expect(results).toEqual([0, 1, 2, 3, 4]);
    expect(f.linked).toEqual(results.map(i => f.staged.find(s => s.key === `csv-stage:p:${i}:a1`)!.id));
  });

  it('reports each chunk\'s non-passing rows from its linked run', async () => {
    const f = fakePort();
    const seen: unknown[] = [];
    await stageChunks(f.port, makeChunks(3), {
      projectId: 'p', attempt: 'a', mappingRef: 'm', fromChunk: 0, onChunk: r => seen.push(r.problems),
    });
    expect(seen).toEqual([[{ index: 0, status: 'failed', error: 'bad' }]]);
  });

  it('stops at the first failure and links nothing after it', async () => {
    const f = fakePort({ failStageAt: 2 });
    const done: number[] = [];
    await expect(
      stageChunks(f.port, makeChunks(2500), {
        projectId: 'p', attempt: 'a', mappingRef: 'm', fromChunk: 0, concurrency: 1, onChunk: r => done.push(r.chunk),
      }),
    ).rejects.toMatchObject({ status: 500 });
    expect(done).toEqual([0, 1]);
    expect(f.linked.length).toBe(2);
  });

  it('resumes after a mid-import failure without staging a completed chunk again', async () => {
    const chunks = makeChunks(2500);
    // Chunks 0 and 1 were staged and linked before the failure.
    const plan = planResume([run(0, 500), run(1, 500)], chunks);
    expect(plan).toEqual({ done: 2, mismatch: false });
    const f = fakePort();
    const done: number[] = [];
    await stageChunks(f.port, chunks, {
      projectId: 'p', attempt: 'a2', mappingRef: 'm', fromChunk: plan.done, onChunk: r => done.push(r.chunk),
    });
    expect(done).toEqual([2, 3, 4]);
    expect(f.staged.map(s => s.key).sort()).toEqual(['csv-stage:p:2:a2', 'csv-stage:p:3:a2', 'csv-stage:p:4:a2']);
  });

  it('treats a 409 on link as already linked (a retried link whose answer was lost)', async () => {
    const f = fakePort();
    f.port.link = async () => {
      throw { status: 409, kind: 'conflict', message: 'unique constraint violated' };
    };
    const done: number[] = [];
    await stageChunks(f.port, makeChunks(10), {
      projectId: 'p', attempt: 'a', mappingRef: 'm', fromChunk: 0, onChunk: r => done.push(r.chunk),
    });
    expect(done).toEqual([0]);
  });

  it('retries a request once, with the same key, when no response came back', async () => {
    const f = fakePort();
    const keys: string[] = [];
    const real = f.port.stage;
    let first = true;
    f.port.stage = async (body, key) => {
      keys.push(key);
      if (first) {
        first = false;
        throw { status: 0, kind: 'unknown', message: 'network' };
      }
      return real(body, key);
    };
    await stageChunks(f.port, makeChunks(10), {
      projectId: 'p', attempt: 'a', mappingRef: 'm', fromChunk: 0, onChunk: () => undefined,
    });
    expect(keys).toEqual(['csv-stage:p:0:a', 'csv-stage:p:0:a']);
  });

  it('stops when asked', async () => {
    const f = fakePort();
    let stop = false;
    await expect(
      stageChunks(f.port, makeChunks(2000), {
        projectId: 'p', attempt: 'a', mappingRef: 'm', fromChunk: 0, concurrency: 1,
        shouldStop: () => stop,
        onChunk: () => { stop = true; },
      }),
    ).rejects.toBeInstanceOf(ImportStopped);
    expect(f.linked.length).toBe(1);
  });
});

describe('planResume', () => {
  const chunks = makeChunks(1200);

  it('ignores dry-run runs and orders by creation', () => {
    const runs = [run(1, 500), run(0, 500), run(9, 500, { mode: 'dry_run', created_at: '2026-09-23T09:00:00Z' })];
    expect(planResume(runs, chunks)).toEqual({ done: 2, mismatch: false });
  });

  it('refuses runs that do not line up with this file', () => {
    expect(planResume([run(0, 499)], chunks).mismatch).toBe(true);
    expect(planResume([run(0, 500), run(1, 500), run(2, 200), run(3, 1)], chunks).mismatch).toBe(true);
  });
});

describe('approveRuns', () => {
  it('approves only staged runs still pending review, and counts a 404 as done', async () => {
    const f = fakePort();
    f.port.approve = async id => {
      f.calls.push(`approve:${id}`);
      if (id === 'si-1') throw { status: 404, kind: 'not_found', message: 'gone' };
      return {};
    };
    const approved: string[] = [];
    await approveRuns(
      f.port,
      [
        run(0, 500, { import_status: 'approved' }),
        run(1, 500),
        run(2, 200),
        run(3, 10, { mode: 'dry_run' }),
      ],
      r => approved.push(r.staged_import_id),
    );
    expect(f.calls.filter(c => c.startsWith('approve:')).sort()).toEqual(['approve:si-1', 'approve:si-2']);
    expect(approved.sort()).toEqual(['si-1', 'si-2']);
  });

  it('surfaces any other failure', async () => {
    const f = fakePort();
    f.port.approve = async () => {
      throw { status: 403, kind: 'forbidden', message: 'no' };
    };
    await expect(approveRuns(f.port, [run(0, 1)], () => undefined)).rejects.toMatchObject({ status: 403 });
  });
});
