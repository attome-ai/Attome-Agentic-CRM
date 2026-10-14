import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { TagPageComponent } from './tag-page.component';

describe('TagPageComponent (B4-T4)', () => {
  it('lists tagged records grouped by entity', () => {
    const get = vi.fn().mockReturnValue(of({ items: [
      { entity: 'account', record_id: 'r1', label: 'Acme' },
      { entity: 'contact', record_id: 'r2', label: null },
      { entity: 'account', record_id: 'r3', label: 'Beta' },
    ] }));
    TestBed.configureTestingModule({
      imports: [TagPageComponent],
      providers: [
        provideRouter([]),
        { provide: ApiService, useValue: { get } },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
    const fixture = TestBed.createComponent(TagPageComponent);
    fixture.componentRef.setInput('tagId', 'tag-1');
    fixture.detectChanges();
    TestBed.flushEffects();
    fixture.detectChanges();
    expect(get).toHaveBeenCalledWith('/api/v1/tags/tag-1/records');
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelectorAll('[data-entity]').length).toBe(2);
    expect(el.querySelector('[data-entity="account"]')?.querySelectorAll('li').length).toBe(2);
    expect(el.querySelector('[data-entity="contact"]')?.textContent).toContain('r2');
  });
});
