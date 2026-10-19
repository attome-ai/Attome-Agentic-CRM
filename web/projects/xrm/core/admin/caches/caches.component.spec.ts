import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { CacheAdminService } from '../data/services/cache-admin.service';
import { CachesComponent } from './caches.component';

describe('CachesComponent (Z3-T10)', () => {
  function setUp() {
    const rows = [
      { name: 'attome-model:cooked', node: 'node-a', entries: 40, hits: 3, misses: 1, evictions: 2, hit_rate: 0.75 },
      { name: 'attome-auth:session', node: 'node-a', entries: 0, hits: 0, misses: 0, evictions: 0, hit_rate: null },
    ];
    const svc = {
      list: vi.fn(() => of({ items: rows, total: 2, page: 1, page_size: 200 })),
      purge: vi.fn(() => of(undefined)),
    };
    TestBed.configureTestingModule({
      imports: [CachesComponent],
      providers: [
        { provide: CacheAdminService, useValue: svc },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: signal('en-US'), errorText: () => 'error' },
        },
      ],
    });
    const fixture = TestBed.createComponent(CachesComponent);
    fixture.detectChanges();
    return { fixture, root: fixture.nativeElement as HTMLElement, svc };
  }

  it('renders the hit rate as hits over reads, and a dash before the first read', () => {
    const { root } = setUp();
    const rate = (name: string) =>
      root.querySelector(`[data-cache-row="${name}"] [data-hit-rate]`)?.textContent?.trim();
    expect(rate('attome-model:cooked')).toBe('75%');
    expect(rate('attome-auth:session')).toBe('—');
  });

  it('purges one key after confirming, and the whole cache without one', () => {
    const { fixture, root, svc } = setUp();
    (root.querySelector('[data-purge="attome-model:cooked"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    const input = root.querySelector('[data-purge-key]') as HTMLInputElement;
    input.value = 'account';
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    (root.querySelector('[data-purge-go]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(svc.purge).toHaveBeenCalledWith('attome-model:cooked', 'account');
    expect(root.querySelector('[data-purge-confirm]')).toBeNull();

    (root.querySelector('[data-purge="attome-auth:session"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    (root.querySelector('[data-purge-go]') as HTMLButtonElement).click();
    expect(svc.purge).toHaveBeenLastCalledWith('attome-auth:session', null);
  });

  it('does not purge until confirmed', () => {
    const { fixture, root, svc } = setUp();
    (root.querySelector('[data-purge="attome-model:cooked"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(root.querySelector('[data-purge-confirm]')).not.toBeNull();
    expect(svc.purge).not.toHaveBeenCalled();
  });
});
