import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { ApiService, LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { RecordAncestorsComponent, recordLabel } from './record-ancestors.component';

describe('RecordAncestorsComponent (A17-T5)', () => {
  function create(get: ReturnType<typeof vi.fn>) {
    TestBed.configureTestingModule({
      imports: [RecordAncestorsComponent],
      providers: [
        provideRouter([]),
        { provide: ApiService, useValue: { get } },
        { provide: LangService, useValue: { translate: (k: string) => k } },
      ],
    });
    const fixture = TestBed.createComponent(RecordAncestorsComponent);
    fixture.componentRef.setInput('entity', 'account');
    fixture.componentRef.setInput('recordId', 'r3');
    fixture.detectChanges();
    TestBed.flushEffects();
    fixture.detectChanges();
    return fixture;
  }

  it('shows the path from the root', () => {
    const get = vi.fn().mockReturnValue(of({ items: [
      { id: 'r2', data: { name: 'Region West' } },
      { id: 'r1', data: { title: 'Head office' } },
    ] }));
    const fixture = create(get);
    expect(get).toHaveBeenCalledWith('/api/v1/account/r3/ancestors');
    const links = [...fixture.nativeElement.querySelectorAll('a')].map((a: HTMLElement) => a.textContent?.trim());
    expect(links).toEqual(['Head office', 'Region West']);
  });

  it('shows nothing for an entity without a tree', () => {
    const fixture = create(vi.fn().mockReturnValue(throwError(() => new Error('422'))));
    expect(fixture.nativeElement.querySelector('[data-ancestors]')).toBeNull();
  });

  it('names a record by its first name-like field, else its id', () => {
    expect(recordLabel({ id: 'abcdef123456', data: {} })).toBe('abcdef12');
    expect(recordLabel({ id: 'x', data: { name: '  ', subject: 'Case 7' } })).toBe('Case 7');
  });
});
