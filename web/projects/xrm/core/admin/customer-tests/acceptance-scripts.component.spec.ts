import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, SdkService, LangService, UserPreferencesService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { AcceptanceScript, AcceptanceScriptsComponent } from './acceptance-scripts.component';
import { sdkFromApi } from '../../../testing/sdk-from-api';

const SCRIPTS: AcceptanceScript[] = [
  { id: 's1', name: 'Convert a lead', description: null, steps: ['Open a lead', 'Convert it'], last_passed: null, last_run_at: null },
];

describe('AcceptanceScriptsComponent (T7-T4)', () => {
  it('marks each step and records the run', () => {
    const getAllPages = vi.fn((_: string) => of(SCRIPTS));
    const post = vi.fn((_: string, _body: unknown) =>
      of({ run_id: 'r1', passed: false, failures: ['step 2: Convert it: no button'] }));
    TestBed.configureTestingModule({
      imports: [AcceptanceScriptsComponent],
      providers: [
        { provide: ApiService, useValue: { getAllPages, post } },
      { provide: SdkService, deps: [ApiService], useFactory: sdkFromApi },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: () => 'en-US' } },
        { provide: UserPreferencesService, useValue: { timezone: () => 'UTC', calendar: () => null, digits: () => null } },
      ],
    });
    const fixture = TestBed.createComponent(AcceptanceScriptsComponent);
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(getAllPages).toHaveBeenCalledWith('/api/v1/acceptance-scripts');

    (el.querySelector('[data-testid="as-list"] button') as HTMLButtonElement).click();
    fixture.detectChanges();
    const record = el.querySelector('[data-testid="as-record"]') as HTMLButtonElement;
    expect(record.disabled).toBe(true);

    const component = fixture.componentInstance;
    component.mark(0, true);
    component.mark(1, false);
    component.note(1, 'no button');
    fixture.detectChanges();
    expect(record.disabled).toBe(false);
    record.click();
    fixture.detectChanges();

    expect(post).toHaveBeenCalledWith('/api/v1/acceptance-scripts/s1/runs', {
      steps: [{ passed: true, note: null }, { passed: false, note: 'no button' }],
    });
    expect((el.querySelector('[data-testid="as-result"]') as HTMLElement).textContent).toContain('acceptanceScripts.failed');
    expect(el.textContent).toContain('step 2: Convert it: no button');
  });
});
