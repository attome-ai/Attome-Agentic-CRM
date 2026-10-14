import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { BrandingComponent, ThemeRow } from './branding.component';

const published: ThemeRow = {
  id: '0190a0a0-0000-7000-8000-000000000001', scope_kind: 'deployment', scope_ref: '', version: 1,
  status: 'published', tokens: { primary: '#123456' }, created_at: '2026-10-14T00:00:00Z',
  published_at: '2026-10-14T00:00:00Z', row_version: 2,
};
const retired: ThemeRow = { ...published, id: '0190a0a0-0000-7000-8000-000000000002', version: 0, status: 'retired' };

describe('BrandingComponent (B13-T9)', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  function create(post = vi.fn().mockReturnValue(of({ passed: true, failures: [] }))) {
    const get = vi.fn((path: string) => path.endsWith('/diff')
      ? of([{ field: 'primary', before: '#000000', after: '#123456' }])
      : of({ items: [published, retired], total: 2, page: 1, page_size: 100 }));
    TestBed.configureTestingModule({
      imports: [BrandingComponent],
      providers: [
        { provide: ApiService, useValue: { get, post } },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
    const fixture = TestBed.createComponent(BrandingComponent);
    fixture.detectChanges();
    return { fixture, get, post };
  }

  it('loads the published colours and lists the versions', () => {
    const { fixture } = create();
    const el: HTMLElement = fixture.nativeElement;
    expect(fixture.componentInstance.tokens().primary).toBe('#123456');
    expect(el.querySelectorAll('tbody tr').length).toBe(2);
    expect(el.querySelector('[data-version="0"]')?.textContent).toContain('brandingPage.rollback');
  });

  it('checks contrast as colours change and shows failures', () => {
    const post = vi.fn().mockReturnValue(of({
      passed: false, failures: [{ pair: 'text/surface', mode: 'light', ratio: 1.5, required: 4.5 }],
    }));
    const { fixture } = create(post);
    fixture.componentInstance.setColour('text', '#eeeeee');
    fixture.componentInstance.setColour('surface', 'not a colour');
    vi.advanceTimersByTime(300);
    fixture.detectChanges();
    expect(post).toHaveBeenCalledWith('/api/v1/admin/themes/preview-check', { tokens: { primary: '#123456', text: '#eeeeee' } });
    expect(fixture.nativeElement.querySelector('[data-contrast="fail"]')?.textContent).toContain('text/surface');
  });

  it('publishes with the row version as If-Match and shows a version diff', () => {
    const { fixture, post, get } = create();
    const draft: ThemeRow = { ...published, status: 'draft', row_version: 1 };
    fixture.componentInstance.publish(draft);
    expect(post).toHaveBeenCalledWith(`/api/v1/admin/themes/${draft.id}/publish`, {}, { ifMatch: 1 });
    fixture.componentInstance.showChanges(published);
    fixture.detectChanges();
    expect(get).toHaveBeenCalledWith(`/api/v1/admin/themes/${published.id}/diff`);
    expect(fixture.nativeElement.querySelector('[data-changes]')?.textContent).toContain('primary');
  });
});
