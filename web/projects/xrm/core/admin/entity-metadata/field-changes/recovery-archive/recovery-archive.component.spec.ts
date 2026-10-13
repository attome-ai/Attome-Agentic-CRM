import { ComponentFixture, TestBed } from '@angular/core/testing';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { FieldChangeService } from '@attome/xrm/core/admin/data';
import { RecoveryArchiveComponent } from './recovery-archive.component';

describe('RecoveryArchiveComponent', () => {
  let fixture: ComponentFixture<RecoveryArchiveComponent>;
  let svc: Record<string, ReturnType<typeof vi.fn>>;

  const row = (id: string, restored = false) => ({
    id, reason: 'field_deleted', entity_logicalname: 'contact', field_logicalname: 'rating',
    attribute_id: 'a1', record_id: 'rec-' + id, field_type: 'text', changeset_id: null, op_seq: null,
    run_ref: null, report_item_ref: null, archived_at: '2026-10-01T10:00:00Z',
    expires_at: '2026-10-31T10:00:00Z', restored_at: restored ? '2026-10-02T10:00:00Z' : null, restored_by: null,
  });
  const counts = { restored: 1, skipped_filled: 0, skipped_not_convertible: 0, missing_records: 0, remaining: 0 };

  async function render(initialField = '') {
    await TestBed.configureTestingModule({
      imports: [RecoveryArchiveComponent],
      providers: [
        { provide: FieldChangeService, useValue: svc },
        {
          provide: LangService,
          useValue: { translate: (key: string) => (key.startsWith('structureErrors.') ? `T:${key}` : key), errorText: () => 'errors.unknown', intlLocale: () => 'en-US' },
        },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(RecoveryArchiveComponent);
    fixture.componentRef.setInput('entity', 'contact');
    fixture.componentRef.setInput('initialField', initialField);
    fixture.detectChanges();
  }

  const el = () => fixture.nativeElement as HTMLElement;

  beforeEach(() => {
    TestBed.resetTestingModule();
    svc = {
      listArchive: vi.fn().mockReturnValue(of({ items: [row('1'), row('2', true)], total: 2, page: 1, page_size: 25 })),
      restoreArchived: vi.fn().mockReturnValue(of(counts)),
      restoreField: vi.fn().mockReturnValue(of({ ...counts, remaining: 5 })),
    };
  });

  it('lists the entity archive one-based, without values', async () => {
    await render();
    expect(svc['listArchive']).toHaveBeenCalledWith(
      { entity: 'contact', field: undefined, reason: undefined, include_restored: false }, 1, 25);
    expect(el().querySelectorAll('tbody tr').length).toBe(2);
    expect(el().textContent).toContain('fieldChange.archive.restored');
  });

  it('restores one value and reloads', async () => {
    await render();
    fixture.componentInstance.restoreOne(fixture.componentInstance.rows()[0]);
    fixture.detectChanges();
    expect(svc['restoreArchived']).toHaveBeenCalledWith('1');
    expect(svc['listArchive']).toHaveBeenCalledTimes(2);
    expect(el().querySelector('[data-testid="archive-notice"]')?.textContent).toContain('fieldChange.archive.result');
  });

  it('restores all values of the filtered field and says what is left', async () => {
    await render('rating');
    expect(svc['listArchive']).toHaveBeenCalledWith(
      expect.objectContaining({ field: 'rating' }), 1, 25);
    fixture.componentInstance.restoreAll();
    fixture.detectChanges();
    expect(svc['restoreField']).toHaveBeenCalledWith('contact', 'rating');
    expect(el().querySelector('[data-testid="archive-notice"]')?.textContent).toContain('fieldChange.archive.remaining');
  });

  it('disables Restore all without a field', async () => {
    await render();
    const btn = el().querySelector('[data-testid="restore-all"]') as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
  });

  it('explains restore_target_missing', async () => {
    svc['restoreArchived'] = vi.fn().mockReturnValue(throwError(() => ({
      kind: 'conflict', status: 409, message: 'conflict: restore_target_missing: the field no longer exists; re-add it first',
    })));
    await render();
    fixture.componentInstance.restoreOne(fixture.componentInstance.rows()[0]);
    fixture.detectChanges();
    expect(el().querySelector('[data-testid="archive-error"]')?.textContent).toContain('structureErrors.restore_target_missing');
  });
});
