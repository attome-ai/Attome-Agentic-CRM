import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { ApiService, LangService } from '@attome/base';
import { Observable, of, throwError } from 'rxjs';
import { describe, expect, it } from 'vitest';

import { FirstRunPromptComponent } from './first-run-prompt.component';

describe('FirstRunPromptComponent (X12-T3)', () => {
  function render(answer: Observable<unknown>) {
    TestBed.configureTestingModule({
      imports: [FirstRunPromptComponent],
      providers: [
        provideRouter([]),
        { provide: ApiService, useValue: { get: () => answer } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('ar') } },
      ],
    });
    const fixture = TestBed.createComponent(FirstRunPromptComponent);
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  it('leads an administrator to the wizard while no country is set', () => {
    const root = render(of({ country: null, pack_available: true, countries: [] }));
    expect(root.querySelector('[data-first-run-prompt] a')!.getAttribute('href')).toBe('/xrm/admin/first-run');
  });

  it('shows nothing once a country is set, without the pack, or for a non-administrator', () => {
    expect(render(of({ country: 'SA', pack_available: true })).querySelector('[data-first-run-prompt]')).toBeNull();
    TestBed.resetTestingModule();
    expect(render(of({ country: null, pack_available: false })).querySelector('[data-first-run-prompt]')).toBeNull();
    TestBed.resetTestingModule();
    expect(render(throwError(() => new Error('forbidden'))).querySelector('[data-first-run-prompt]')).toBeNull();
  });
});
