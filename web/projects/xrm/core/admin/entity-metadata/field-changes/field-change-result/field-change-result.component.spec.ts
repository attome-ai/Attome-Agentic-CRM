import { ComponentFixture, TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { LangService } from '@attome/base';
import type { FieldChangeResult } from '@attome/xrm/core/admin/data';
import { FieldChangeResultComponent } from './field-change-result.component';

function result(over: Partial<FieldChangeResult> = {}): FieldChangeResult {
  return {
    op: 'delete_field', entity: 'contact', field: 'rating', dry_run: true, applied: false,
    error: null, references: [], blockers: [], values_to_archive: 5, not_convertible: null,
    sample_record_ids: [], archived: 0, nulled: 0, records_with_value: null, run_id: null,
    report: [], labels: [], ...over,
  };
}

describe('FieldChangeResultComponent', () => {
  let fixture: ComponentFixture<FieldChangeResultComponent>;

  async function render(r: FieldChangeResult) {
    await TestBed.configureTestingModule({
      imports: [FieldChangeResultComponent],
      providers: [
        { provide: LangService, useValue: { translate: (key: string) => (key.startsWith('structureErrors.') ? `T:${key}` : key), intlLocale: () => 'en-US' } },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(FieldChangeResultComponent);
    fixture.componentRef.setInput('result', r);
    fixture.detectChanges();
  }

  const el = () => fixture.nativeElement as HTMLElement;

  beforeEach(() => TestBed.resetTestingModule());

  it('shows the archive count of a delete dry run', async () => {
    await render(result());
    expect(el().textContent).toContain('fieldChange.result.dryRun');
    expect(el().querySelector('[data-testid="values-to-archive"]')).not.toBeNull();
    expect(el().textContent).toContain('fieldChange.result.noReferences');
  });

  it('shows a blocked change with its blockers', async () => {
    await render(result({
      error: 'field_referenced',
      blockers: [{ hook: 'views', object_kind: 'view', object_ref: null, name: 'Active contacts', reason: 'filters on it' }],
    }));
    expect(el().querySelector('[data-testid="blocked-text"]')?.textContent).toContain('structureErrors.field_referenced');
    expect(el().querySelector('[data-testid="blockers"]')?.textContent).toContain('Active contacts');
  });

  it('marks customer references', async () => {
    await render(result({
      references: [{ hook: 'views', object_kind: 'view', object_ref: null, name: 'My view', owner: 'customer' }],
    }));
    expect(el().querySelector('[data-testid="references"]')?.textContent).toContain('fieldChange.result.customer');
  });

  it('shows the not-convertible count of a type change dry run', async () => {
    await render(result({ op: 'change_field_type', values_to_archive: null, not_convertible: 3, sample_record_ids: ['a', 'b'] }));
    expect(el().querySelector('[data-testid="not-convertible"]')).not.toBeNull();
    expect(el().querySelectorAll('.fcr-ids li').length).toBe(2);
  });

  it('says the count is unknown for a large table', async () => {
    await render(result({ op: 'change_field_type', values_to_archive: null, not_convertible: null }));
    expect(el().textContent).toContain('fieldChange.result.notConvertibleUnknown');
  });
});
