import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { MY_JOBS_REFRESH_MS, MyJob, MyJobsComponent } from './my-jobs.component';

const RUNNING: MyJob = {
  id: 'j1', name: 'Import contacts', status: 'running', done: 400, total: 1000,
  cancel_requested: false, created_at: '2026-10-19T09:00:00Z', finished_at: null,
};
const FINISHED: MyJob = {
  id: 'j2', name: 'Bulk edit', status: 'finished', done: 50, total: 50,
  cancel_requested: false, created_at: '2026-10-18T09:00:00Z', finished_at: '2026-10-18T09:01:00Z',
};

describe('MyJobsComponent (M12-T4)', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  function setUp(items: MyJob[]) {
    const api = {
      get: vi.fn(() => of({ items, total: items.length, page: 1, page_size: 50 })),
      post: vi.fn(() => of({ ...RUNNING, cancel_requested: true })),
    };
    TestBed.configureTestingModule({
      imports: [MyJobsComponent],
      providers: [
        { provide: ApiService, useValue: api },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: signal('en-US'), errorText: () => 'error' } },
      ],
    });
    const fixture = TestBed.createComponent(MyJobsComponent);
    fixture.detectChanges();
    return { fixture, root: fixture.nativeElement as HTMLElement, api };
  }

  it('lists the caller\'s jobs with a cancel only for the running one', () => {
    const { root, api } = setUp([RUNNING, FINISHED]);
    expect(api.get).toHaveBeenCalledWith('/api/v1/jobs', { page_size: '50' });
    expect(root.querySelectorAll('[data-my-job]').length).toBe(2);
    expect(root.querySelector('[data-my-job-cancel="j1"]')).not.toBeNull();
    expect(root.querySelector('[data-my-job-cancel="j2"]')).toBeNull();
  });

  it('cancels a running job and shows it stopping', () => {
    const { fixture, root, api } = setUp([RUNNING]);
    (root.querySelector('[data-my-job-cancel="j1"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(api.post).toHaveBeenCalledWith('/api/v1/jobs/j1/cancel', {});
    expect(fixture.componentInstance.statusKey(fixture.componentInstance.jobs()[0])).toBe('stopping');
    expect(root.querySelector('[data-my-job-cancel="j1"]')).toBeNull();
  });

  it('refreshes while a job runs, and not otherwise', () => {
    const running = setUp([RUNNING]);
    vi.advanceTimersByTime(MY_JOBS_REFRESH_MS);
    expect(running.api.get).toHaveBeenCalledTimes(2);
    TestBed.resetTestingModule();
    const idle = setUp([FINISHED]);
    vi.advanceTimersByTime(MY_JOBS_REFRESH_MS * 2);
    expect(idle.api.get).toHaveBeenCalledTimes(1);
  });

  it('says so when there is nothing', () => {
    const { root } = setUp([]);
    expect(root.querySelector('[data-my-jobs-empty]')).not.toBeNull();
  });
});
