import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { BulkTagComponent } from './bulk-tag.component';

describe('BulkTagComponent (B4-T4)', () => {
  function create() {
    const post = vi.fn().mockReturnValue(of({ changed: 2, failed: [{ id: 'c', code: 'forbidden' }] }));
    const get = vi.fn().mockReturnValue(of({ items: [{ id: 't1', name: 'VIP', colour: null, personal: false, uses: 4 }] }));
    TestBed.configureTestingModule({
      imports: [BulkTagComponent],
      providers: [
        { provide: ApiService, useValue: { get, post } },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
    const fixture = TestBed.createComponent(BulkTagComponent);
    fixture.componentRef.setInput('entity', 'account');
    fixture.componentRef.setInput('recordIds', ['a', 'b', 'c']);
    fixture.detectChanges();
    return { fixture, post, get };
  }

  it('adds a tag by name to every selected record and reports the result', () => {
    const { fixture, post } = create();
    const changed = vi.fn();
    fixture.componentInstance.changed.subscribe(changed);
    fixture.componentInstance.add('  VIP ');
    expect(post).toHaveBeenCalledWith('/api/v1/account/tags/bulk', { ids: ['a', 'b', 'c'], add: { name: 'VIP' } });
    expect(fixture.componentInstance.result()).toEqual({ changed: 2, failed: [{ id: 'c', code: 'forbidden' }] });
    expect(changed).toHaveBeenCalled();
  });

  it('removes a suggested tag by id', () => {
    const { fixture, post, get } = create();
    fixture.componentInstance.open.set(true);
    fixture.componentInstance.suggest('vi');
    expect(get).toHaveBeenCalledWith('/api/v1/tags/suggest', { q: 'vi' });
    fixture.detectChanges();
    (fixture.nativeElement.querySelector('[data-remove="t1"]') as HTMLButtonElement).click();
    expect(post).toHaveBeenCalledWith('/api/v1/account/tags/bulk', { ids: ['a', 'b', 'c'], remove_tag_id: 't1' });
  });

  it('sends nothing for an empty name', () => {
    const { fixture, post } = create();
    fixture.componentInstance.add('   ');
    expect(post).not.toHaveBeenCalled();
  });
});
