import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { SecretsAdminService } from '../data/services/secrets-admin.service';
import { ConfigStartsComponent } from './config-starts.component';

describe('ConfigStartsComponent (Z1-T14)', () => {
  function setUp() {
    const starts = [
      { id: 'b', node_name: 'host:7865', started_at: '2026-10-19T10:00:00Z', app_version: 'v2', fingerprint: 'ffff0000aaaa1111' },
      { id: 'a', node_name: 'host:7865', started_at: '2026-10-18T10:00:00Z', app_version: 'v1', fingerprint: 'eeee0000aaaa1111' },
    ];
    const diff = vi.fn(() => of({
      items: [{ path: 'app.port', before: 7865, after: 7866 }], total: 1, page: 1, page_size: 1,
    }));
    TestBed.configureTestingModule({
      imports: [ConfigStartsComponent],
      providers: [
        { provide: SecretsAdminService, useValue: { starts: () => of({ items: starts, total: 2, page: 1, page_size: 25 }), diff } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: signal('en-US'), errorText: () => 'error' } },
      ],
    });
    const fixture = TestBed.createComponent(ConfigStartsComponent);
    fixture.detectChanges();
    return { fixture, root: fixture.nativeElement as HTMLElement, diff };
  }

  it('lists the starts newest first', () => {
    const { root } = setUp();
    const rows = Array.from(root.querySelectorAll('[data-start-row]')).map(r => r.getAttribute('data-start-row'));
    expect(rows).toEqual(['b', 'a']);
  });

  it('compares two picked starts, the earlier first, and renders the changed keys', () => {
    const { fixture, root, diff } = setUp();
    (root.querySelector('[data-start-pick="b"]') as HTMLInputElement).click();
    (root.querySelector('[data-start-pick="a"]') as HTMLInputElement).click();
    fixture.detectChanges();
    (root.querySelector('[data-starts-compare]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(diff).toHaveBeenCalledWith('a', 'b');
    const row = root.querySelector('[data-diff-row="app.port"]') as HTMLElement;
    expect(row.textContent).toContain('7865');
    expect(row.textContent).toContain('7866');
  });
});
