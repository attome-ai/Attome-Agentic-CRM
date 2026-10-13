import { signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { Observable, of } from 'rxjs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AppSwitcherComponent, AvailableApp } from './app-switcher.component';

const APPS: AvailableApp[] = [
  { id: 'app-1', name: 'Sales', icon: 'las la-chart-line', sidebar_root_ref: null, default_dashboard_ref: null, entities: ['account'] },
  { id: 'app-2', name: 'Support', icon: 'las la-life-ring', sidebar_root_ref: null, default_dashboard_ref: null, entities: ['support_case'] },
];

class StubApi {
  response: AvailableApp[] = APPS;
  get(url: string): Observable<unknown> {
    return url === '/api/v1/apps' ? of(this.response) : of([]);
  }
}

function mount(api = new StubApi()): { fixture: ComponentFixture<AppSwitcherComponent>; component: AppSwitcherComponent } {
  TestBed.configureTestingModule({
    imports: [AppSwitcherComponent],
    providers: [
      { provide: ApiService, useValue: api },
      { provide: LangService, useValue: { current: signal('en'), set: vi.fn(), translate: (key: string) => key } },
    ],
  });
  const fixture = TestBed.createComponent(AppSwitcherComponent);
  fixture.detectChanges();
  return { fixture, component: fixture.componentInstance };
}

// M65 Phase 1 (D-467) — "apps only filter, never authorize": these tests
// cover the switcher's own selection/emission behavior, not authorization —
// there is none here to test.
describe('AppSwitcherComponent', () => {
  afterEach(() => localStorage.clear());

  it('loads the caller-visible apps on init', () => {
    const { component } = mount();
    expect(component.apps()).toEqual(APPS);
  });

  it('emits the selected app\'s entities and clears back to null', () => {
    const { component } = mount();
    const emitted: (string[] | null)[] = [];
    component.appChanged.subscribe(v => emitted.push(v));

    component.select(APPS[0]);
    expect(component.selectedApp()?.id).toBe('app-1');
    expect(emitted).toEqual([['account']]);

    component.clear();
    expect(component.selectedApp()).toBeNull();
    expect(emitted).toEqual([['account'], null]);
  });

  it('persists the selection and restores it on the next mount', () => {
    const { component } = mount();
    component.select(APPS[1]);

    TestBed.resetTestingModule();
    const { component: reloaded } = mount();
    expect(reloaded.selectedApp()?.id).toBe('app-2');
  });

  it('degrades to an empty, hidden switcher when the fetch fails', () => {
    class FailingApi {
      get(): Observable<never> {
        return new Observable(subscriber => subscriber.error(new Error('network')));
      }
    }
    const { component } = mount(new FailingApi() as unknown as StubApi);
    expect(component.apps()).toEqual([]);
  });
});
