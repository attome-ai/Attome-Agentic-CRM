import { TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { describe, expect, it } from 'vitest';
import { ATTOME_CONFIG, provideAttomeI18n } from '@attome/base';
import { provideXrmI18n } from '@attome/xrm/core/i18n';
import { AppContextService } from '../services/app-context.service';
import { DashboardComponent } from './dashboard.component';

/**
 * R-10 (M26-dashboard-remediation): `embedInputs` used to be a static
 * `{ tags: ['general'], embedded: false }` object regardless of the caller's
 * selected app — this spec's old assertion (`expect(comp.embedInputs).toEqual(...)`
 * against a freshly-`new`ed component with no DI) was tautological, since
 * that was the literal initializer with nothing else able to change it. Now
 * `embedInputs` is a computed signal sourced from `AppContextService`, so
 * this drives it through the real DI'd service instead.
 */
describe('DashboardComponent', () => {
  it('embeds the selected app\'s default_dashboard_ref when one is set', () => {
    const appContext = {
      selectedApp: signal({
        id: 'app-1', name: 'Sales', icon: 'las la-chart-line',
        sidebar_root_ref: null, default_dashboard_ref: 'x', entities: [],
      }),
    };
    TestBed.configureTestingModule({
      providers: [{ provide: AppContextService, useValue: appContext }],
    });
    const component = TestBed.createComponent(DashboardComponent).componentInstance;

    expect(component.embedInputs()).toEqual({ dashboardId: 'x', embedded: false });
  });

  it('falls back to the general tag when no app is selected', () => {
    const appContext = { selectedApp: signal(null) };
    TestBed.configureTestingModule({
      providers: [{ provide: AppContextService, useValue: appContext }],
    });
    const component = TestBed.createComponent(DashboardComponent).componentInstance;

    expect(component.embedInputs()).toEqual({ tags: ['general'], embedded: false });
  });

  it('falls back to the general tag when the selected app has no default configured', () => {
    const appContext = {
      selectedApp: signal({
        id: 'app-1', name: 'Sales', icon: 'las la-chart-line',
        sidebar_root_ref: null, default_dashboard_ref: null, entities: [],
      }),
    };
    TestBed.configureTestingModule({
      providers: [{ provide: AppContextService, useValue: appContext }],
    });
    const component = TestBed.createComponent(DashboardComponent).componentInstance;

    expect(component.embedInputs()).toEqual({ tags: ['general'], embedded: false });
  });

  it('renders an error card, not a permanent spinner, when the lazy dashboard import fails', () => {
    const appContext = { selectedApp: signal(null) };
    TestBed.configureTestingModule({
      providers: [
        { provide: AppContextService, useValue: appContext },
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
        provideAttomeI18n(), provideXrmI18n(),
      ],
    });
    const fixture = TestBed.createComponent(DashboardComponent);
    // Set synchronously, before change detection — the lazy `import()`'s own microtask cannot have
    // run yet, so `embedComponent` is still null and the template must take the error branch.
    fixture.componentInstance.loadError.set('dashboard.shell.loadFailed');
    fixture.detectChanges();

    expect(fixture.nativeElement.querySelector('.xf-error-banner')).not.toBeNull();
    expect(fixture.nativeElement.querySelector('.xf-loading')).toBeNull();
  });
});
