import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { describe, expect, it } from 'vitest';
import { ConflictDialogComponent, conflictRows, resolvedOp } from './conflict-dialog.component';
import { MemoryBackend, OfflineStore } from './offline-store';
import { OFFLINE_STORE, OfflineQueueService, QueuedOp } from './offline-queue.service';
import { SyncProblem } from './sync.service';

const problem: SyncProblem = {
  op: {
    seq: 3, client_op_id: 'op-1', kind: 'update', entity: 'visit', id: 'v1', base_row_version: 2,
    changed: { notes: 'Pump replaced, customer signed', status: 'done' },
    base_values: { notes: 'Pump', status: 'on_site' },
  },
  result: {
    client_op_id: 'op-1', status: 'conflict', id: 'v1', row_version: 5,
    server_values: { notes: 'Pump checked remotely' }, link: '/xrm/entity/visit/form?id=v1',
  },
};

function setup(dir: 'ltr' | 'rtl' = 'ltr') {
  document.documentElement.dir = dir;
  TestBed.resetTestingModule();
  TestBed.configureTestingModule({
    imports: [ConflictDialogComponent],
    providers: [
      { provide: OFFLINE_STORE, useFactory: () => new OfflineStore(new MemoryBackend()) },
      { provide: LangService, useValue: { translate: (key: string) => key } },
    ],
  });
  const fixture = TestBed.createComponent(ConflictDialogComponent);
  fixture.componentRef.setInput('problem', problem);
  fixture.detectChanges();
  return fixture;
}

describe('ConflictDialogComponent (B18-T9)', () => {
  it('resolving sends new op with server version', async () => {
    expect(conflictRows(problem)).toEqual([
      { field: 'notes', mine: 'Pump replaced, customer signed', server: 'Pump checked remotely' },
    ]);
    expect(resolvedOp(problem, {}), 'nothing is picked for the person').toBeNull();

    const fixture = setup();
    const queue = TestBed.inject(OfflineQueueService);
    const el: HTMLElement = fixture.nativeElement;
    const save = el.querySelector<HTMLButtonElement>('[data-testid="offline-conflict-save"]')!;
    expect(save.disabled).toBe(true);

    let sent: QueuedOp | undefined;
    fixture.componentInstance.resolved.subscribe(op => (sent = op));
    el.querySelector<HTMLInputElement>('[data-testid="offline-conflict-mine"]')!.dispatchEvent(new Event('change'));
    fixture.detectChanges();
    expect(save.disabled).toBe(false);
    await fixture.componentInstance.save();

    expect(sent?.kind).toBe('update');
    expect(sent?.base_row_version).toBe(5);
    expect(sent?.changed).toEqual({ notes: 'Pump replaced, customer signed', status: 'done' });
    expect(sent?.base_values).toEqual({ notes: 'Pump checked remotely', status: 'on_site' });
    expect(await queue.size()).toBe(1);

    expect(resolvedOp(problem, { notes: 'server' })?.changed).toEqual({ notes: 'Pump checked remotely', status: 'done' });
  });

  it('rtl layout keeps Mine at inline-start, before the server value', () => {
    const el: HTMLElement = setup('rtl').nativeElement;
    const row = el.querySelector('[data-testid="offline-conflict-row"]')!;
    const cells = Array.from(row.children);
    expect(cells[1].querySelector('[data-testid="offline-conflict-mine"]')).not.toBeNull();
    expect(cells[2].querySelector('[data-testid="offline-conflict-server"]')).not.toBeNull();
    expect(document.documentElement.dir).toBe('rtl');
    // Both sides are shown in full, so no text is lost.
    expect(row.textContent).toContain('Pump replaced, customer signed');
    expect(row.textContent).toContain('Pump checked remotely');
    document.documentElement.dir = 'ltr';
  });
});
