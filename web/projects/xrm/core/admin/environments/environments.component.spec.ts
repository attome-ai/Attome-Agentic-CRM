import { ComponentFixture, TestBed } from '@angular/core/testing';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { EnvironmentsComponent, EnvironmentsService, planCounts } from './environments.component';
import type { ChangesetPlan, LedgerRow } from './environments.component';

function row(id: string, status: string, approval: string | null): LedgerRow {
  return {
    id, changeset_id: id, ref: `sales/${id}`, layer: 'product', scope: 'sales', seq: 1,
    phase: 'expand', status, source: 'api', approval_ref: approval, applied_count: 3,
    error_message: null, created_at: '2026-11-02T08:00:00Z', finished_at: null,
  };
}

const PLAN: ChangesetPlan = {
  applicable: false,
  changesets: [{
    changeset_id: 'c1', ref: 'sales/0034', layer: 'product', scope: 'sales', status: 'blocked',
    blocked: ['missing_dependency'],
    phases: [{
      phase: 'expand', status: 'planned', applicable: true,
      operations: [
        { seq: 1, op: 'add_field', phase: 'expand', target: {}, action: 'create', risky: false },
        { seq: 2, op: 'update_entity', phase: 'expand', target: {}, action: 'update', risky: false },
        { seq: 3, op: 'set_label', phase: 'expand', target: {}, action: 'noop', risky: false },
      ],
    }],
  }],
};

describe('EnvironmentsComponent', () => {
  let fixture: ComponentFixture<EnvironmentsComponent>;
  let svc: { ledger: ReturnType<typeof vi.fn>; plan: ReturnType<typeof vi.fn> };

  beforeEach(async () => {
    svc = {
      ledger: vi.fn((_page: number, _size: number, status?: string) => of({
        items: status === 'queued'
          ? [row('q1', 'queued', 'a1'), row('q2', 'queued', null)]
          : [row('h1', 'succeeded', null)],
        total: status === 'queued' ? 2 : 1, page: 1, page_size: 25,
      })),
      plan: vi.fn(() => of(PLAN)),
    };
    await TestBed.configureTestingModule({
      imports: [EnvironmentsComponent],
      providers: [
        { provide: EnvironmentsService, useValue: svc },
        {
          provide: LangService,
          useValue: {
            translate: (key: string) => key,
            errorText: () => 'errors.unknown',
            intlLocale: () => 'en-US',
          },
        },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(EnvironmentsComponent);
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
  });

  it('lists the ledger history', () => {
    const rows = fixture.nativeElement.querySelectorAll('[data-testid="ledger-row"]');
    expect(rows.length).toBe(1);
    expect(svc.ledger).toHaveBeenCalledWith(1, 25, undefined);
  });

  it('shows only queued rows that wait for an approval', () => {
    fixture.nativeElement.querySelector('[data-testid="tab-waiting"]').click();
    fixture.detectChanges();
    expect(svc.ledger).toHaveBeenLastCalledWith(1, 25, 'queued');
    const rows = fixture.nativeElement.querySelectorAll('[data-testid="ledger-row"]');
    expect(rows.length).toBe(1);
  });

  it('counts what a plan would do', () => {
    expect(planCounts(PLAN)).toEqual({ create: 1, update: 1, noop: 1 });
  });
});
