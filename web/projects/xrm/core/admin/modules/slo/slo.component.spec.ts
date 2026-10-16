import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { SloClass, SloComponent, budgetPercent, effectiveTargets } from './slo.component';

const CLASSES: SloClass[] = [
  {
    id: 'S1', name_en: 'Authenticated read', name_ar: 'قراءة', kind: 'http', status: 'ok',
    target: { p50_ms: 10, p95_ms: 30, p99_ms: 60 }, override: null,
    budget_remaining: 0.8, error_ratio_30d: 0.0002,
  },
  {
    id: 'S2', name_en: 'Sign-in', name_ar: 'تسجيل الدخول', kind: 'http', status: 'exhausted',
    target: { p50_ms: 150, p95_ms: 300, p99_ms: 500 },
    override: { p95_ms: 400, p99_ms: 700, row_version: 3, updated_by: 'u', updated_at: '2026-10-16T08:00:00Z' },
    budget_remaining: -1.5, error_ratio_30d: 0.0025,
  },
];

describe('SloComponent (AA13-T11)', () => {
  function create() {
    const get = vi.fn((_: string) => of({ profile: 'solo', classes: CLASSES }));
    const put = vi.fn(() => of({}));
    TestBed.configureTestingModule({
      imports: [SloComponent],
      providers: [
        { provide: ApiService, useValue: { get, put, delete: vi.fn(() => of(undefined)) } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en') } },
      ],
    });
    const fixture = TestBed.createComponent(SloComponent);
    fixture.detectChanges();
    return { fixture, get, put };
  }

  it('shows each class with its status and budget, an exhausted one at zero', () => {
    const { fixture, get } = create();
    expect(get).toHaveBeenCalledWith('/api/v1/admin/slo');
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-class="S2"]')?.getAttribute('data-status')).toBe('exhausted');
    expect(budgetPercent(CLASSES[0])).toBe(80);
    expect(budgetPercent(CLASSES[1])).toBe(0);
  });

  it("uses the deployment's own targets when set and sends the row version", () => {
    const { fixture, put } = create();
    expect(effectiveTargets(CLASSES[1])).toEqual({ p95: 400, p99: 700 });
    expect(effectiveTargets(CLASSES[0])).toEqual({ p95: 30, p99: 60 });
    const component = fixture.componentInstance;
    component.edit(CLASSES[1]);
    component.p95 = 350;
    component.save(CLASSES[1]);
    expect(put).toHaveBeenCalledWith('/api/v1/admin/slo/targets/S2', {
      p95_ms: 350, p99_ms: 700, row_version: 3,
    });
  });
});
