import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { of } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { PageListItem, TargetListItem, WebcrawlAdminService } from './services/webcrawl-admin.service';
import { WebcrawlPageListComponent } from './webcrawl-page/list/webcrawl-page-list/webcrawl-page-list.component';
import { WebcrawlTargetListComponent } from './webcrawl-target/list/webcrawl-target-list/webcrawl-target-list.component';

// The crawl job writes each page row the moment it fetches it and only flips
// the target out of `crawling` at the end, so "reactive" here means exactly
// two things, and both are what these tests pin: the views keep re-reading
// while the target is still running, and they stop the instant it isn't.

const TARGET_ID = 'target-1';

function target(status: string, overrides: Partial<TargetListItem> = {}): TargetListItem {
  return {
    id:              TARGET_ID,
    url:             'https://example.com/',
    status,
    max_depth:       6,
    pages_found:     0,
    pages_imported:  0,
    last_error:      null,
    last_crawled_at: null,
    created_at:      '2026-08-17T00:00:00Z',
    ...overrides,
  };
}

function page(path: string, overrides: Partial<PageListItem> = {}): PageListItem {
  return {
    id:                     `page${path}`,
    url_path:               path,
    parent_path:            path === '/' ? null : '/',
    depth:                  path === '/' ? 0 : 1,
    size_bytes:             1024,
    status:                 'crawled',
    is_selected:            false,
    imported_data_item_ref: null,
    ...overrides,
  };
}

describe('webcrawl live crawl views', () => {
  const svc = {
    listTargets:     vi.fn(),
    listPages:       vi.fn(),
    createTarget:    vi.fn(),
    recrawlTarget:   vi.fn(),
    deleteTarget:    vi.fn(),
    updateSelection: vi.fn(),
    importPages:     vi.fn(),
  };
  const navigate = vi.fn();

  beforeEach(() => {
    vi.useFakeTimers();
    for (const fn of Object.values(svc)) fn.mockReset();
    navigate.mockReset();
    TestBed.configureTestingModule({
      providers: [
        { provide: WebcrawlAdminService, useValue: svc },
        { provide: Router, useValue: { navigate } },
      ],
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('WebcrawlPageListComponent', () => {
    beforeEach(() => {
      TestBed.overrideComponent(WebcrawlPageListComponent, { set: { template: '' } });
    });

    function mount(state: { status: string; pages: PageListItem[] }) {
      svc.listTargets.mockImplementation(() => of([target(state.status)]));
      svc.listPages.mockImplementation(() => of([...state.pages]));
      const fixture = TestBed.createComponent(WebcrawlPageListComponent);
      fixture.componentRef.setInput('id', TARGET_ID);
      fixture.detectChanges();
      return fixture;
    }

    it('adds pages as the crawler discovers them, then stops polling when the crawl ends', () => {
      const state = { status: 'crawling', pages: [page('/')] };
      const fixture = mount(state);
      const c = fixture.componentInstance;

      expect(c.isRunning()).toBe(true);
      expect(c.pages()).toHaveLength(1);

      state.pages = [page('/'), page('/about')];
      vi.advanceTimersByTime(2_000);
      expect(c.pages()).toHaveLength(2);

      state.pages = [page('/'), page('/about'), page('/gone', { status: 'failed' })];
      vi.advanceTimersByTime(2_000);
      expect(c.pages()).toHaveLength(3);
      expect(c.crawledCount()).toBe(2);
      expect(c.failedCount()).toBe(1);

      state.status = 'completed';
      vi.advanceTimersByTime(2_000);
      expect(c.isRunning()).toBe(false);

      const settled = svc.listPages.mock.calls.length;
      vi.advanceTimersByTime(30_000);
      expect(svc.listPages.mock.calls.length).toBe(settled);
    });

    it('never polls a target that was already finished when the page opened', () => {
      const fixture = mount({ status: 'completed', pages: [page('/')] });

      const initial = svc.listPages.mock.calls.length;
      vi.advanceTimersByTime(30_000);

      expect(svc.listPages.mock.calls.length).toBe(initial);
      expect(fixture.componentInstance.isRunning()).toBe(false);
    });

    it('does not blank the table or raise a fatal error while polling', () => {
      const state = { status: 'crawling', pages: [page('/')] };
      const fixture = mount(state);
      const c = fixture.componentInstance;

      vi.advanceTimersByTime(2_000);

      expect(c.loading()).toBe(false);
      expect(c.error()).toBeNull();
      expect(c.pages()).toHaveLength(1);
    });

    it('drops a selected page once a poll shows it imported', () => {
      const state = { status: 'crawling', pages: [page('/'), page('/about')] };
      const fixture = mount(state);
      const c = fixture.componentInstance;

      c.toggle(page('/about'));
      expect(c.selected().has('page/about')).toBe(true);

      state.pages = [page('/'), page('/about', { imported_data_item_ref: 'item-1' })];
      vi.advanceTimersByTime(2_000);

      expect(c.selected().has('page/about')).toBe(false);
    });

    it('stops polling when the view is destroyed mid-crawl', () => {
      const state = { status: 'crawling', pages: [page('/')] };
      const fixture = mount(state);

      fixture.destroy();
      const settled = svc.listPages.mock.calls.length;
      vi.advanceTimersByTime(30_000);

      expect(svc.listPages.mock.calls.length).toBe(settled);
    });
  });

  describe('WebcrawlTargetListComponent', () => {
    beforeEach(() => {
      TestBed.overrideComponent(WebcrawlTargetListComponent, { set: { template: '' } });
    });

    it('opens the detail page as soon as a crawl is started', () => {
      svc.listTargets.mockReturnValue(of([]));
      svc.createTarget.mockReturnValue(of(target('pending')));
      const fixture = TestBed.createComponent(WebcrawlTargetListComponent);
      fixture.detectChanges();

      fixture.componentInstance.urlInput.set('example.com');
      fixture.componentInstance.startCrawling();

      expect(svc.createTarget).toHaveBeenCalledWith('example.com', 6);
      expect(navigate).toHaveBeenCalledWith(['/xrm/admin/webcrawl/targets', TARGET_ID]);
    });

    it('refreshes the list while a target is running and stops once none are', () => {
      const state = { status: 'crawling' };
      svc.listTargets.mockImplementation(() => of([target(state.status)]));
      const fixture = TestBed.createComponent(WebcrawlTargetListComponent);
      fixture.detectChanges();
      const c = fixture.componentInstance;

      expect(c.anyRunning()).toBe(true);
      const afterInit = svc.listTargets.mock.calls.length;

      vi.advanceTimersByTime(2_000);
      expect(svc.listTargets.mock.calls.length).toBe(afterInit + 1);

      state.status = 'completed';
      vi.advanceTimersByTime(2_000);
      expect(c.anyRunning()).toBe(false);

      const settled = svc.listTargets.mock.calls.length;
      vi.advanceTimersByTime(30_000);
      expect(svc.listTargets.mock.calls.length).toBe(settled);
    });
  });
});
