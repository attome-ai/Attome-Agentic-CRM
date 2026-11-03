import { TestBed } from '@angular/core/testing';
import { LangService, SdkService, WorkspaceState } from '@attome/base';
import { of } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { DevelopStartComponent, recentWorkspaces } from './develop-start.component';

const ws = (id: string, status: string, used: string) => ({ id, name: id, status, last_used_at: used });

describe('recentWorkspaces (T1-T1)', () => {
  it('keeps open workspaces, most recently used first', () => {
    const rows = [
      ws('a', 'open', '2026-11-01T10:00:00Z'),
      ws('b', 'published', '2026-11-03T10:00:00Z'),
      ws('c', 'open', '2026-11-02T10:00:00Z'),
    ];
    expect(recentWorkspaces(rows).map(w => w.id)).toEqual(['c', 'a']);
    expect(recentWorkspaces(rows, 1)).toHaveLength(1);
  });
});

describe('DevelopStartComponent', () => {
  beforeEach(() => sessionStorage.clear());
  afterEach(() => sessionStorage.clear());

  function setup() {
    const get = vi.fn((path: string) => {
      if (path.endsWith('/workspaces')) return of({ items: [ws('w1', 'open', '2026-11-03T10:00:00Z')] });
      if (path.endsWith('/apps')) return of({ items: [{ id: 'app1', name: 'Sales' }] });
      return of({ items: [{ id: 't1', name: 'Welcome series' }] });
    });
    const post = vi.fn((path: string, _opts?: unknown) =>
      path.includes('model.app.plan')
        ? of({ result: { written_plan: ['Create the entity visit.'], steps: [{}, {}, {}] } })
        : of({ id: 'w9', name: 'New app', status: 'open', last_used_at: '2026-11-03T11:00:00Z' }));
    TestBed.configureTestingModule({
      imports: [DevelopStartComponent],
      providers: [
        { provide: SdkService, useValue: { get, post } },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
    const fixture = TestBed.createComponent(DevelopStartComponent);
    fixture.detectChanges();
    return { fixture, get, post };
  }

  it('offers the three ways to start and the recent work', () => {
    const { fixture } = setup();
    const root = fixture.nativeElement as HTMLElement;
    for (const id of ['ds-blank', 'ds-describe', 'ds-templates', 'ds-recent']) {
      expect(root.querySelector(`[data-testid="${id}"]`)).not.toBeNull();
    }
    expect(root.querySelector('[data-testid="ds-templates"]')?.textContent).toContain('Sales');
    expect(root.querySelectorAll('[data-testid="ds-enter"]')).toHaveLength(1);
  });

  it('starts a blank app in a new workspace and enters it', () => {
    const { fixture, post } = setup();
    fixture.componentInstance.name.set('New app');
    fixture.componentInstance.startBlank();
    expect(post.mock.calls[0][1]).toEqual({ body: { name: 'New app', data: { mode: 'none' } } });
    expect(TestBed.inject(WorkspaceState).active()?.id).toBe('w9');
  });

  it('shows the written plan before the steps', () => {
    const { fixture } = setup();
    const c = fixture.componentInstance;
    c.description.set('A clinic');
    c.plan(false);
    expect(c.written()).toEqual(['Create the entity visit.']);
    expect(c.steps()).toBeNull();
    c.plan(true);
    expect(c.steps()).toBe(3);
  });
});
