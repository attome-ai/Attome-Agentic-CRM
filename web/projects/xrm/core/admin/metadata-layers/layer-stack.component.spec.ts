import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { LayerStackComponent } from './layer-stack.component';
import type { PropertyStack, ResetResult } from './metadata-layers.model';

const STACK: PropertyStack[] = [
  {
    property: 'name', winner: 'customer',
    values: [
      { layer: 'platform', app: '', value: 'Account' },
      { layer: 'app', app: 'sales', value: 'Customer' },
      { layer: 'customer', app: '', value: 'Client' },
    ],
  },
  { property: 'is_auditable', winner: 'platform', values: [{ layer: 'platform', app: '', value: true }] },
];

const PREVIEW: ResetResult = { reset_id: null, changes: [{ property: 'name', current: 'Client', after: 'Customer' }] };

describe('LayerStackComponent (Y11-T15)', () => {
  function create() {
    const get = vi.fn((_: string) => of({ items: STACK }));
    const post = vi.fn((path: string, _body: unknown) =>
      of(path.endsWith('/undo') ? undefined : path.includes('preview=true') ? PREVIEW : { ...PREVIEW, reset_id: 'r1' }));
    TestBed.configureTestingModule({
      imports: [LayerStackComponent],
      providers: [
        { provide: ApiService, useValue: { get, post } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: () => 'en-US' } },
      ],
    });
    const fixture = TestBed.createComponent(LayerStackComponent);
    fixture.componentInstance.key.set('account');
    fixture.componentInstance.load();
    fixture.detectChanges();
    return { fixture, get, post };
  }

  it('layer-stack shows winner', () => {
    const { fixture, get } = create();
    expect(get).toHaveBeenCalledWith('/api/v1/admin/metadata/entity/account/layers');
    const row = fixture.nativeElement.querySelector('tr[data-property="name"]') as HTMLElement;
    expect(row.querySelectorAll('li').length).toBe(3);
    expect(row.querySelector('li.ls-wins')?.getAttribute('data-layer')).toBe('customer');
    expect(row.querySelector('.ls-winner')?.textContent).toContain('metadataLayers.layers.customer');
    expect(row.textContent).toContain('sales');
    // Only a customised property offers a reset.
    expect(row.querySelector('td:last-child button')).not.toBeNull();
    const plain = fixture.nativeElement.querySelector('tr[data-property="is_auditable"]') as HTMLElement;
    expect(plain.querySelector('td:last-child button')).toBeNull();
  });

  it('previews a reset before applying it, then offers an undo', () => {
    const { fixture, post } = create();
    const c = fixture.componentInstance;
    c.previewReset('name');
    fixture.detectChanges();
    expect(post).toHaveBeenCalledWith('/api/v1/admin/metadata/entity/account/reset?preview=true', { properties: ['name'] });
    expect(post).toHaveBeenCalledTimes(1);
    expect(fixture.nativeElement.querySelector('tr[data-change="name"]').textContent).toContain('Customer');

    c.confirmReset();
    expect(post).toHaveBeenLastCalledWith('/api/v1/admin/metadata/entity/account/reset', { properties: ['name'] });
    expect(c.undoId()).toBe('r1');

    c.undo('r1');
    expect(post).toHaveBeenLastCalledWith('/api/v1/admin/metadata/resets/r1/undo', null);
    expect(c.undoId()).toBeNull();
  });
});
