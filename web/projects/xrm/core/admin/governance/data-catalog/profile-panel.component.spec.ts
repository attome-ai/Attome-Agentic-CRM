import { TestBed } from '@angular/core/testing';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { DataProfileService, fillRate, fillRates } from '@attome/xrm/core/admin/data';
import type { DataProfileRow, FieldProfile } from '@attome/xrm/core/admin/data';
import { ProfilePanelComponent, histogramBars } from './profile-panel.component';

const field = (overrides: Partial<FieldProfile>): FieldProfile => ({
  field: 'f', rows: 10, null_pct: 0, nulls: 0, blanks: 0, distinct_count: 1,
  distinct_is_lower_bound: false, top_values: [], masked: false, ...overrides,
});

const profile = (fields: FieldProfile[], overrides: Partial<DataProfileRow> = {}): DataProfileRow => ({
  id: 'p1', entity_logicalname: 'contact', status: 'completed', row_count: 200000, fields,
  sample_size: 100000, full_scan: false, error: null, created_by: 'u1',
  created_at: '2026-10-01T00:00:00Z', completed_at: '2026-10-01T00:05:00Z', import_job_ref: null,
  ...overrides,
} as DataProfileRow);

describe('profile helpers (L6-T7)', () => {
  it('fill rate counts nulls and blanks as empty', () => {
    expect(fillRate(field({ rows: 10, nulls: 2, blanks: 3 }))).toBe(50);
    expect(fillRate(field({ rows: 0 }))).toBe(0);
    expect(fillRates(profile([field({ field: 'email', rows: 4, nulls: 1 })])).get('email')).toBe(75);
    expect(fillRates(null).size).toBe(0);
  });

  it('histogram bars scale to the tallest bucket', () => {
    const bars = histogramBars(field({
      number: {
        min: 0, max: 30, mean: 10, median: 10, outliers: 0,
        percentiles: { p5: 0, p25: 5, p75: 20, p95: 28 },
        histogram: { from: 0, bucket_width: 10, counts: [2, 4, 1] },
      },
    }));
    expect(bars.map(b => b.height)).toEqual([50, 100, 25]);
    expect(bars[1]).toMatchObject({ from: 10, to: 20, count: 4 });
  });
});

describe('ProfilePanelComponent (L6-T7)', () => {
  let latest: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    TestBed.resetTestingModule();
    latest = vi.fn();
    TestBed.configureTestingModule({
      imports: [ProfilePanelComponent],
      providers: [
        { provide: DataProfileService, useValue: { latest } },
        { provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' } },
      ],
    });
  });

  function render(row: DataProfileRow | null) {
    latest.mockReturnValue(of(row));
    const fixture = TestBed.createComponent(ProfilePanelComponent);
    fixture.componentRef.setInput('entity', 'contact');
    fixture.detectChanges();
    TestBed.flushEffects();
    fixture.detectChanges();
    return fixture;
  }

  it('masked examples render as shapes', () => {
    const root: HTMLElement = render(profile([
      field({ field: 'mobile', masked: true, top_values: [{ value: '9999999999', count: 7 }] }),
      field({ field: 'city', top_values: [{ value: 'Riyadh', count: 5 }] }),
    ])).nativeElement;
    expect(latest).toHaveBeenCalledWith('contact');
    const values = root.querySelectorAll('[data-profile-value]');
    expect(values[0].textContent?.trim()).toBe('9999999999');
    expect(values[0].classList).toContain('dp-shape');
    expect(values[0].getAttribute('dir')).toBe('ltr');
    expect(values[1].classList).not.toContain('dp-shape');
    expect(root.querySelectorAll('[data-profile-masked]').length).toBe(1);
  });

  it('says when the profile was sampled', () => {
    const root: HTMLElement = render(profile([field({})])).nativeElement;
    expect(root.querySelector('[data-profile-note]')?.textContent).toContain('governance.catalog.profile.sampled');
  });

  it('opens a field with its histogram and Arabic measures', () => {
    const fixture = render(profile([field({
      field: 'amount',
      number: {
        min: 0, max: 30, mean: 10, median: 10, outliers: 1,
        percentiles: { p5: 0, p25: 5, p75: 20, p95: 28 },
        histogram: { from: 0, bucket_width: 10, counts: [2, 4, 1] },
      },
      patterns: {
        values: 10, top_shapes: [{ shape: '99.99', count: 6, share_pct: 60 }], format_match_pct: null,
        arabic: {
          script: { arabic: 0, latin: 0, mixed: 0 }, digits: { eastern: 3, western: 7 },
          with_diacritics: 0, dates: { hijri: 0, gregorian: 0 },
        },
      },
    })]));
    const root: HTMLElement = fixture.nativeElement;
    expect(root.querySelector('[data-profile-detail]')).toBeNull();
    (root.querySelector('[data-profile-field]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(root.querySelectorAll('[data-profile-histogram] .dp-bar').length).toBe(3);
    expect(root.querySelector('[data-profile-arabic]')).not.toBeNull();
  });

  it('says when there is no profile yet', () => {
    const root: HTMLElement = render(null).nativeElement;
    expect(root.querySelector('[data-profile-none]')).not.toBeNull();
  });
});
