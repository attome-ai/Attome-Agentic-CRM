import { TestBed } from '@angular/core/testing';
import { LangService, SdkService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { RefactorDialogComponent, splitTargets } from './refactor-dialog.component';

describe('splitTargets (A1-T14)', () => {
  it('reads one field = expression a line', () => {
    expect(splitTargets('first_name = word(full_name, 1)\n\nnope\nlast_name=word(full_name, 2)')).toEqual([
      { field: 'first_name', expression: 'word(full_name, 1)' },
      { field: 'last_name', expression: 'word(full_name, 2)' },
    ]);
  });
});

describe('RefactorDialogComponent', () => {
  function setup() {
    const post = vi.fn((path: string, _opts?: unknown) =>
      path.endsWith('/preview')
        ? of({ rows_read: 10, rows_changed: 8, rows_unconvertible: 2, more_rows: false, examples: [] })
        : of({ run_id: 'run-1', to_review: [{ kind: 'view', id: 'v1', label: 'All contacts', attribute: 'account_ref' }] }));
    TestBed.configureTestingModule({
      imports: [RefactorDialogComponent],
      providers: [
        { provide: SdkService, useValue: { post } },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
    const fixture = TestBed.createComponent(RefactorDialogComponent);
    fixture.componentRef.setInput('entityId', 'e1');
    fixture.componentRef.setInput('entityName', 'contact');
    fixture.componentRef.setInput('attributes', ['full_name', 'account_ref']);
    fixture.detectChanges();
    return { fixture, post };
  }

  it('previews a split before it can run', () => {
    const { fixture, post } = setup();
    const c = fixture.componentInstance;
    c.source.set('full_name');
    c.targets.set('first_name = word(full_name, 1)');
    expect(c.preview()).toBeNull();
    c.previewSplit();
    fixture.detectChanges();
    expect(post.mock.calls[0][0]).toBe('/api/v1/admin/entities/e1/refactor/preview');
    expect(post.mock.calls[0][1]).toEqual({
      body: { source: 'full_name', targets: [{ field: 'first_name', expression: 'word(full_name, 1)' }] },
    });
    expect((fixture.nativeElement as HTMLElement).querySelector('[data-testid="rf-preview-result"]')).not.toBeNull();
  });

  it('turns a lookup into a many-to-many and lists what to move by hand', () => {
    const { fixture, post } = setup();
    const c = fixture.componentInstance;
    c.kind.set('to_many_to_many');
    c.source.set('account_ref');
    c.childName.set('contact_account');
    c.run();
    fixture.detectChanges();
    expect(post.mock.calls[0][0]).toBe('/api/v1/admin/entities/e1/refactor/to-many-to-many');
    expect(post.mock.calls[0][1]).toEqual({
      body: { lookup: 'account_ref', name: 'contact_account', role_a: 'contact', role_b: 'account_ref' },
    });
    expect(c.queued()).toBe('run-1');
    expect((fixture.nativeElement as HTMLElement).querySelectorAll('[data-testid="rf-review"] li')).toHaveLength(1);
  });
});
