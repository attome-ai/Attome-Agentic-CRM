import { ComponentFixture, TestBed } from '@angular/core/testing';
import { NEVER, of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { ReleaseReportService, type ReportItemView } from '@attome/xrm/core/admin/data';
import { ReportItemComponent } from './report-item.component';

function view(over: Partial<ReportItemView> = {}): ReportItemView {
  return {
    id: 'i1', report_ref: 'r1', kind: 'conflict', actionable: true, status: 'open',
    entity_logicalname: 'contact', field_logicalname: 'rating', record_id: 'rec1',
    object_kind: null, object_ref: null, detail: {}, has_values: true,
    changeset_id: null, op_seq: null, decided_by: null, decided_at: null, superseded_by: null,
    created_at: '2026-10-01T10:00:00Z', row_version: 2,
    values: { theirs: 'Gold', ours: 'Silver', key: null }, values_hidden: false,
    ...over,
  };
}

describe('ReportItemComponent', () => {
  let fixture: ComponentFixture<ReportItemComponent>;
  let svc: Record<string, ReturnType<typeof vi.fn>>;

  async function render(item: ReportItemView) {
    await TestBed.configureTestingModule({
      imports: [ReportItemComponent],
      providers: [
        { provide: ReleaseReportService, useValue: svc },
        {
          provide: LangService,
          useValue: {
            translate: (key: string) => (key.startsWith('structureErrors.') ? `T:${key}` : key),
            errorText: () => 'errors.unknown',
            intlLocale: () => 'en-US',
          },
        },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(ReportItemComponent);
    fixture.componentRef.setInput('item', item);
    fixture.detectChanges();
  }

  const el = () => fixture.nativeElement as HTMLElement;
  const btn = (id: string) => el().querySelector(`[data-testid="${id}"]`) as HTMLButtonElement | null;

  beforeEach(() => {
    TestBed.resetTestingModule();
    svc = {
      accept: vi.fn().mockReturnValue(of({ ...view(), status: 'accepted', row_version: 3 })),
      dismiss: vi.fn().mockReturnValue(of({ ...view(), status: 'dismissed', row_version: 3 })),
      useMine: vi.fn().mockReturnValue(of({ ...view(), status: 'used_mine', row_version: 3 })),
      recordRowVersion: vi.fn().mockReturnValue(of(9)),
      restore: vi.fn(),
    };
  });

  it('shows both values of a conflict and the conflict actions', async () => {
    await render(view());
    expect(el().querySelector('[data-testid="conflict-values"]')?.textContent).toContain('Gold');
    expect(el().textContent).toContain('Silver');
    expect(btn('accept')).not.toBeNull();
    expect(btn('use-mine')).not.toBeNull();
    expect(btn('dismiss')).not.toBeNull();
    expect(btn('restore')).toBeNull();
  });

  it('shows the hidden-values note and no Use mine when values are hidden', async () => {
    await render(view({ values: null, values_hidden: true }));
    expect(el().querySelector('[data-testid="values-hidden"]')).not.toBeNull();
    expect(btn('use-mine')).toBeNull();
    expect(btn('accept')).not.toBeNull();
  });

  it('accepts with the item and emits the decided item', async () => {
    await render(view());
    const changed = vi.fn();
    fixture.componentInstance.changed.subscribe(changed);
    btn('accept')!.click();
    expect(svc['accept']).toHaveBeenCalledWith(expect.objectContaining({ id: 'i1', row_version: 2 }));
    expect(changed).toHaveBeenCalledWith(expect.objectContaining({ status: 'accepted', values: view().values }));
  });

  it('sends the record row_version read when the item was shown, not at click time', async () => {
    await render(view());
    expect(svc['recordRowVersion']).toHaveBeenCalledWith('contact', 'rec1');
    expect(svc['recordRowVersion']).toHaveBeenCalledTimes(1);
    btn('use-mine')!.click();
    expect(svc['recordRowVersion']).toHaveBeenCalledTimes(1);
    expect(svc['useMine']).toHaveBeenCalledWith(expect.objectContaining({ id: 'i1' }), 9);
  });

  it('keeps Use mine disabled until the record version is known', async () => {
    svc['recordRowVersion'] = vi.fn().mockReturnValue(NEVER);
    await render(view());
    expect(btn('use-mine')!.disabled).toBe(true);
  });

  it('asks the page to reload on a version conflict', async () => {
    svc['dismiss'] = vi.fn().mockReturnValue(throwError(() => ({ kind: 'version_conflict', status: 409, message: '' })));
    await render(view());
    const stale = vi.fn();
    fixture.componentInstance.stale.subscribe(stale);
    btn('dismiss')!.click();
    fixture.detectChanges();
    expect(stale).toHaveBeenCalled();
    expect(el().querySelector('[data-testid="item-error"]')?.textContent).toContain('structureErrors.version_conflict');
  });

  it('offers Restore on an open archive-backed item', async () => {
    svc['restore'] = vi.fn().mockReturnValue(of({
      restore: { restored: 2, skipped_filled: 1, skipped_not_convertible: 0, missing_records: 0, remaining: 0 },
      remaining: 0,
      item: { ...view({ kind: 'field_deleted' }), status: 'restored' },
    }));
    await render(view({ kind: 'field_deleted', record_id: null, has_values: false, values: null }));
    expect(btn('accept')).toBeNull();
    btn('restore')!.click();
    fixture.detectChanges();
    expect(svc['restore']).toHaveBeenCalledWith('i1');
    expect(el().textContent).toContain('releaseReport.results.restored');
  });

  it('shows no actions on a decided item', async () => {
    await render(view({ status: 'accepted' }));
    expect(btn('accept')).toBeNull();
    expect(btn('dismiss')).toBeNull();
  });
});
