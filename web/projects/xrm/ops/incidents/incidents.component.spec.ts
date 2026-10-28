import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { IncidentsComponent, canPublish, visibleIncidents } from './incidents.component';
import type { Incident } from './incidents.component';

const INCIDENT: Incident = {
  id: 'i1', title_en: 'Search is slow', title_ar: 'البحث بطيء', audience: 'internal', state: 'investigating',
  components: ['search'], impact: 'partial', started_at: '2026-10-28T08:00:00Z', resolved_at: null,
  published_at: '2026-10-28T08:01:00Z', auto_created: false, row_version: 2,
};
const UPDATE = {
  id: 'u1', incident_id: 'i1', stage: 'investigating', body_en: 'Looking into it', body_ar: 'نتحقق',
  corrects_update_id: null, published_at: '2026-10-28T08:01:00Z',
};

describe('incident helpers (AB11-T9)', () => {
  it('editor blocks publish without Arabic', () => {
    expect(canPublish({ stage: 'note', body_en: 'Fixed', body_ar: '', corrects_update_id: null })).toBe(false);
    expect(canPublish({ stage: 'note', body_en: 'Fixed', body_ar: 'أُصلح', corrects_update_id: null })).toBe(true);
  });

  it('hides resolved incidents unless asked', () => {
    const resolved = { ...INCIDENT, id: 'i2', resolved_at: '2026-10-28T09:00:00Z' };
    expect(visibleIncidents([INCIDENT, resolved], false).map(i => i.id)).toEqual(['i1']);
    expect(visibleIncidents([INCIDENT, resolved], true).length).toBe(2);
  });
});

describe('IncidentsComponent (AB11-T9)', () => {
  function setUp() {
    const post = vi.fn(() => of(UPDATE));
    const get = vi.fn((url: string) => {
      if (url === '/api/v1/ops/status') return of({ components: [{ key: 'search', name_en: 'Search', name_ar: 'البحث' }] });
      if (url === '/api/v1/ops/incidents') return of({ items: [INCIDENT], total: 1, page: 1, page_size: 100 });
      return of({ ...INCIDENT, updates: [UPDATE] });
    });
    TestBed.configureTestingModule({
      imports: [IncidentsComponent],
      providers: [
        { provide: ApiService, useValue: { get, post } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: signal('en-US'), errorText: () => 'error' } },
      ],
    });
    const fixture = TestBed.createComponent(IncidentsComponent);
    fixture.detectChanges();
    return { fixture, post, root: fixture.nativeElement as HTMLElement };
  }

  it('disables publish until both languages are written', () => {
    const { fixture, root } = setUp();
    fixture.componentInstance.open('i1');
    fixture.detectChanges();
    fixture.componentInstance.patchDraft({ body_en: 'Fixed' });
    fixture.detectChanges();
    expect((root.querySelector('[data-testid="oi-publish"]') as HTMLButtonElement).disabled).toBe(true);
    expect(root.querySelector('[data-testid="oi-both"]')).not.toBeNull();
  });

  it('correction posts corrects_update_id', () => {
    const { fixture, post } = setUp();
    fixture.componentInstance.open('i1');
    fixture.detectChanges();
    fixture.componentInstance.correct(UPDATE);
    fixture.componentInstance.patchDraft({ body_en: 'Corrected: search only', body_ar: 'تصحيح: البحث فقط' });
    fixture.componentInstance.publish('i1');
    expect(post).toHaveBeenCalledWith('/api/v1/ops/incidents/i1/updates', {
      stage: 'note', body_en: 'Corrected: search only', body_ar: 'تصحيح: البحث فقط', corrects_update_id: 'u1',
    });
  });
});
