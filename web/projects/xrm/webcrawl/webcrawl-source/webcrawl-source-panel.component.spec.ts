import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { TargetListItem, WebcrawlAdminService } from '../services/webcrawl-admin.service';
import { WebcrawlSourcePanelComponent, draftOf, settingsOf } from './webcrawl-source-panel.component';

const TARGET: TargetListItem = {
  id: 't1', url: 'https://docs.example.com/', status: 'completed', max_depth: 6, pages_found: 12,
  pages_imported: 4, last_error: null, last_crawled_at: null, created_at: '2026-11-01T00:00:00Z',
  include_patterns: '/docs/*', exclude_patterns: '', languages: ['ar'], audience: 'internal',
  import_mode: 'review', schedule: 'manual', sitemap_url: null, watch_only: false, allow_host: '',
  credential_ref: null, row_version: 3,
};

function setup() {
  const svc = {
    updateTarget: vi.fn().mockReturnValue(of({ ...TARGET, schedule: 'weekly', row_version: 4 })),
    listRuns: vi.fn().mockReturnValue(of([{ id: 'r1', started_at: '2026-11-01T00:00:00Z', finished_at: null,
      status: 'completed', pages_found: 12, items_imported: 2, items_updated: 1, items_flagged: 1, error: null }])),
    listChanges: vi.fn().mockReturnValue(of([{ page_id: 'p1', url_path: '/ar/about', item_id: 'i1',
      title: 'من نحن', version: 2, changed_at: '2026-11-01T00:00:00Z' }])),
    importPages: vi.fn().mockReturnValue(of({ data_source_ref: 'd', imported_count: 1 })),
    keepItem: vi.fn().mockReturnValue(of({})),
  };
  TestBed.configureTestingModule({
    imports: [WebcrawlSourcePanelComponent],
    providers: [
      { provide: WebcrawlAdminService, useValue: svc },
      { provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' } },
    ],
  });
  const fixture = TestBed.createComponent(WebcrawlSourcePanelComponent);
  fixture.componentRef.setInput('target', TARGET);
  fixture.detectChanges();
  TestBed.flushEffects();
  fixture.detectChanges();
  return { svc, fixture, root: fixture.nativeElement as HTMLElement };
}

describe('WebcrawlSourcePanelComponent (K6-T11)', () => {
  it('reads a source into the form and back', () => {
    const d = draftOf(TARGET);
    expect(d.ar).toBe(true);
    expect(d.en).toBe(false);
    expect(settingsOf({ ...d, en: true, watch_only: true }).languages).toEqual(['ar', 'en']);
  });

  it('saves the settings with the row version', () => {
    const { svc, fixture, root } = setup();
    const emitted = vi.fn();
    fixture.componentInstance.targetSaved.subscribe(emitted);
    (fixture.componentInstance.draft() as { schedule: string }).schedule = 'weekly';
    expect(root.querySelector('[data-testid="wsp-save"]')).not.toBeNull();
    fixture.componentInstance.save();
    fixture.detectChanges();
    expect(svc.updateTarget).toHaveBeenCalledWith('t1', 3, expect.objectContaining({ schedule: 'weekly', languages: ['ar'] }));
    expect(emitted).toHaveBeenCalledWith(expect.objectContaining({ row_version: 4 }));
  });

  it('lists runs and changes to review', () => {
    const { svc, fixture, root } = setup();
    (root.querySelector('[data-testid="wsp-tab-runs"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(root.querySelector('[data-testid="wsp-runs"]')?.textContent).toContain('12');
    (root.querySelector('[data-testid="wsp-tab-changes"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    const changes = root.querySelector('[data-testid="wsp-changes"]') as HTMLElement;
    expect(changes.textContent).toContain('من نحن');
    (changes.querySelector('[data-testid="wsp-keep"]') as HTMLButtonElement).click();
    expect(svc.keepItem).toHaveBeenCalledWith('i1');
    (changes.querySelector('[data-testid="wsp-take"]') as HTMLButtonElement).click();
    expect(svc.importPages).toHaveBeenCalledWith('t1', ['p1']);
  });
});
