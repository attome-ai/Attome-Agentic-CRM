import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Observable, of } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { POLL_INTERVAL_MS, ProfilerComponent } from './profiler.component';
import { ApiGroup, ProfilerAdminService, StatRow, TraceSample } from '../services/profiler-admin.service';

function stat(name: string, total_ms: number, count = 1): StatRow {
  return { name, count, total_ms, avg_ms: total_ms / count, min_ms: total_ms, max_ms: total_ms };
}

function group(name: string, total_ms: number, parts: StatRow[] = []): ApiGroup {
  return { api: stat(name, total_ms), parts };
}

/** Serves a fixed stats payload; `statsCalls` still counts polls. */
class StubProfiler {
  statsCalls = 0;
  constructor(private readonly groups: ApiGroup[] = []) {}
  stats(): Observable<ApiGroup[]> {
    this.statsCalls += 1;
    return of(this.groups);
  }
  trace(): Observable<TraceSample[]> {
    return of([]);
  }
}

// `document.visibilityState` is a read-only accessor on `Document.prototype`;
// an own configurable property on the instance shadows it and is deleted in
// `afterEach` so the prototype's getter is back for every other spec.
let visibility: DocumentVisibilityState = 'visible';

function setVisibility(state: DocumentVisibilityState): void {
  visibility = state;
  document.dispatchEvent(new Event('visibilitychange'));
}

function mount(groups: ApiGroup[] = []): { fixture: ComponentFixture<ProfilerComponent>; component: ProfilerComponent; svc: StubProfiler } {
  const svc = new StubProfiler(groups);
  TestBed.configureTestingModule({
    imports: [ProfilerComponent],
    providers: [{ provide: ProfilerAdminService, useValue: svc }],
  });
  const fixture = TestBed.createComponent(ProfilerComponent);
  fixture.detectChanges();
  return { fixture, component: fixture.componentInstance, svc };
}

function resetDom(): void {
  // Vitest fake timers rather than `fakeAsync`: the workspace is zoneless.
  // rxjs's `timer` runs on `setTimeout`, which vi controls.
  vi.useFakeTimers();
  visibility = 'visible';
  Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => visibility });
  TestBed.resetTestingModule();
}

function restoreDom(): void {
  Reflect.deleteProperty(document, 'visibilityState');
  vi.useRealTimers();
}

describe('ProfilerComponent polling (T7-4)', () => {
  beforeEach(resetDom);
  afterEach(restoreDom);

  it('refreshes immediately and then every interval while visible', () => {
    const { svc } = mount();
    expect(svc.statsCalls).toBe(1);

    vi.advanceTimersByTime(POLL_INTERVAL_MS - 1);
    expect(svc.statsCalls).toBe(1);
    vi.advanceTimersByTime(1);
    expect(svc.statsCalls).toBe(2);
    vi.advanceTimersByTime(POLL_INTERVAL_MS * 2);
    expect(svc.statsCalls).toBe(4);
  });

  it('issues no request while the document is hidden', () => {
    visibility = 'hidden';
    const { svc } = mount();
    expect(svc.statsCalls).toBe(0);

    vi.advanceTimersByTime(POLL_INTERVAL_MS * 5);
    expect(svc.statsCalls).toBe(0);
  });

  it('stops polling when the document goes hidden', () => {
    const { svc } = mount();
    vi.advanceTimersByTime(POLL_INTERVAL_MS);
    expect(svc.statsCalls).toBe(2);

    setVisibility('hidden');
    vi.advanceTimersByTime(POLL_INTERVAL_MS * 5);
    expect(svc.statsCalls).toBe(2);
  });

  it('refreshes immediately when the document becomes visible again', () => {
    visibility = 'hidden';
    const { svc } = mount();
    vi.advanceTimersByTime(POLL_INTERVAL_MS);
    expect(svc.statsCalls).toBe(0);

    // No timer advance: the refresh must be immediate, not at the next tick.
    setVisibility('visible');
    expect(svc.statsCalls).toBe(1);

    vi.advanceTimersByTime(POLL_INTERVAL_MS);
    expect(svc.statsCalls).toBe(2);
  });

  it('stops polling once the component is destroyed', () => {
    const { fixture, svc } = mount();
    expect(svc.statsCalls).toBe(1);

    fixture.destroy();
    vi.advanceTimersByTime(POLL_INTERVAL_MS * 5);
    expect(svc.statsCalls).toBe(1);
  });
});

describe('ProfilerComponent loading and top consumers', () => {
  beforeEach(resetDom);
  afterEach(restoreDom);

  it('sorts the main table by total time, biggest first', () => {
    const { component } = mount([group('GET /api/v1/a', 10), group('boot', 500)]);
    expect(component.sortedGroups().map(g => g.api.name)).toEqual(['boot', 'GET /api/v1/a']);
  });

  it('separates loading, request and job time in the summary', () => {
    const { component } = mount([
      group('boot', 500),
      group('GET /api/v1/a', 30),
      group('job.bulk', 70),
    ]);
    expect(component.summary()).toEqual({ loading_ms: 500, request_ms: 30, job_ms: 70, total_ms: 600 });
  });

  it('ranks top-level probes by total time with their share', () => {
    const { component } = mount([
      group('boot', 500),
      group('GET /api/v1/a', 300),
      group('job.bulk', 200),
    ]);
    const slowest = component.slowest();
    expect(slowest.map(r => r.name)).toEqual(['boot', 'GET /api/v1/a', 'job.bulk']);
    expect(slowest[0].category).toBe('loading');
    expect(slowest[0].share).toBe(50);
  });

  it('breaks the boot timeline down by phase, slowest first', () => {
    const { component } = mount([
      group('boot', 400, [stat('boot.migrations', 300), stat('boot.license', 100)]),
    ]);
    expect(component.bootPhases().map(p => p.name)).toEqual(['migrations', 'license']);
    expect(component.bootPhases()[0].pct).toBe(75);
    expect(component.bootTotalMs()).toBe(400);
  });
});
