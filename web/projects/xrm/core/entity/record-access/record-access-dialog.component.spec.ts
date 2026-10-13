import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import type { ApiError } from '@attome/base';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { EntityService } from '../services/entity.service';
import { RecordAccessDialogComponent } from './record-access-dialog.component';
import { RecordSharingService } from './record-sharing.service';

describe('RecordAccessDialogComponent (U7 Phase A)', () => {
  let sharing: Record<'listRecordShares' | 'createRecordShare' | 'deleteRecordShare' | 'reassignOwner', ReturnType<typeof vi.fn>>;
  let entities: { lookupSearch: ReturnType<typeof vi.fn>; get: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    sharing = {
      listRecordShares: vi.fn().mockReturnValue(of([])),
      createRecordShare: vi.fn().mockReturnValue(of({})),
      deleteRecordShare: vi.fn().mockReturnValue(of(undefined)),
      reassignOwner: vi.fn(),
    };
    entities = {
      lookupSearch: vi.fn().mockReturnValue(of({
        data: [{ id: 'u1', entity_id: '', data: { email: 'ann@example.com' }, created_at: '', updated_at: '', row_version: 1 }],
        total: 1, page: 1, limit: 20,
      })),
      get: vi.fn().mockReturnValue(of({ id: 'u1', data: { email: 'ann@example.com' } })),
    };
    TestBed.configureTestingModule({
      imports: [RecordAccessDialogComponent],
      providers: [
        { provide: RecordSharingService, useValue: sharing },
        { provide: EntityService, useValue: entities },
        {
          provide: LangService,
          useValue: {
            intlLocale: () => 'en-US',
            translate: (key: string, params?: Record<string, unknown>) =>
              params ? `${key} ${JSON.stringify(params)}` : key,
          },
        },
      ],
    });
  });

  function render(mode: 'assign' | 'share', recordIds: string[]) {
    const fixture = TestBed.createComponent(RecordAccessDialogComponent);
    fixture.componentRef.setInput('mode', mode);
    fixture.componentRef.setInput('entity', 'ticket');
    fixture.componentRef.setInput('recordIds', recordIds);
    fixture.detectChanges();
    return { fixture, cmp: fixture.componentInstance, el: fixture.nativeElement as HTMLElement };
  }

  it('searches users by email for the picker', () => {
    const { cmp } = render('assign', ['r1']);
    expect(entities.lookupSearch).toHaveBeenCalledWith('user_account', '', 'email');
    expect(cmp.results()).toEqual([{ kind: 'user', id: 'u1', label: 'ann@example.com' }]);
    cmp.setKind('team');
    expect(entities.lookupSearch).toHaveBeenLastCalledWith('team', '', 'name');
  });

  it('assigns each record on its own call and reports successes and failures', async () => {
    const err: ApiError = { kind: 'forbidden', status: 403, message: 'Forbidden' };
    sharing.reassignOwner.mockImplementation((body: { record_id: string }) =>
      body.record_id === 'r2' ? throwError(() => err) : of({}));
    const { cmp, fixture, el } = render('assign', ['r1', 'r2', 'r3']);
    const closed: boolean[] = [];
    cmp.closed.subscribe(v => closed.push(v));
    cmp.pick({ kind: 'user', id: 'u1', label: 'ann@example.com' });
    await cmp.assign();
    fixture.detectChanges();

    expect(sharing.reassignOwner).toHaveBeenCalledTimes(3);
    expect(sharing.reassignOwner.mock.calls.map(c => c[0])).toEqual(expect.arrayContaining([
      { entity: 'ticket', record_id: 'r1', user_email: 'ann@example.com' },
      { entity: 'ticket', record_id: 'r2', user_email: 'ann@example.com' },
    ]));
    expect(cmp.summary()?.succeeded).toBe(2);
    expect(cmp.summary()?.failed).toEqual([{ recordId: 'r2', ok: false, error: 'Forbidden' }]);
    expect(el.querySelector('[data-testid="record-assign-summary"]')?.textContent).toContain('"succeeded":2');
    cmp.close();
    expect(closed).toEqual([true]);
  });

  it('lists the record shares, grants one and revokes one', () => {
    sharing.listRecordShares.mockReturnValue(of([{
      id: 's1', record_id: 'r1', entity: 'ticket', principal_type: 'user', principal_id: 'u1',
      capability: 'view', granted_by: null, granted_at: null,
    }]));
    const { cmp } = render('share', ['r1']);
    expect(sharing.listRecordShares).toHaveBeenCalledWith('ticket', 'r1');
    expect(cmp.shares().map(r => r.label)).toEqual(['ann@example.com']);

    cmp.pick({ kind: 'team', id: 't1', label: 'Support' });
    cmp.setCapability('deny');
    cmp.grant();
    expect(sharing.createRecordShare).toHaveBeenCalledWith({
      entity: 'ticket', record_id: 'r1', capability: 'deny', team_name: 'Support',
    });

    cmp.revoke(cmp.shares()[0]);
    expect(sharing.deleteRecordShare).toHaveBeenCalledWith('s1');
  });
});
