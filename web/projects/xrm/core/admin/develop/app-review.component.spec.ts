import { TestBed } from '@angular/core/testing';
import { LangService, SdkService, WORKSPACE_HEADER } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { AppReviewComponent, type ReviewPreview, draftEntities, groupOps, opKind } from './app-review.component';

const op = (name: string, target: Record<string, unknown>, risky = false) =>
  ({ op: name, action: 'create', target, risky });

const preview: ReviewPreview = {
  workspace: 'w1',
  operations: 5,
  conflicts: [],
  publishable: true,
  plan: {
    applicable: true,
    changesets: [{
      phases: [{
        operations: [
          op('create_entity', { entity: 'visit' }),
          op('add_field', { entity: 'visit', field: 'notes' }),
          op('upsert_view', { entity: 'visit', view: 'all' }),
          op('grant_role_privilege', { role: 'nurse', privilege: 'visit.read' }),
          op('set_label', { entity: 'clinic', locale: 'ar' }),
        ],
      }],
    }],
  },
};

describe('grouping the draft (AD4-T2)', () => {
  it('sorts operations into kinds', () => {
    expect(opKind('create_entity')).toBe('entities');
    expect(opKind('change_field_type')).toBe('fields');
    expect(opKind('upsert_query')).toBe('screens');
    expect(opKind('ensure_privilege')).toBe('access');
    expect(opKind('upsert_state_transition')).toBe('processes');
    expect(opKind('set_label')).toBe('labels');
    expect(opKind('upsert_record')).toBe('other');
    expect(groupOps(preview).map(g => g.kind)).toEqual(['entities', 'fields', 'screens', 'access', 'labels']);
  });

  it('lists the entities the draft touches once each', () => {
    expect(draftEntities(preview)).toEqual(['visit', 'clinic']);
    expect(draftEntities({ ...preview, plan: null })).toEqual([]);
  });
});

describe('AppReviewComponent', () => {
  function setup(publishAnswer: unknown) {
    const checklist = [{
      entity: 'visit', ready: false,
      items: [{ area: 'tests', done: false, required: true, detail: '0 test(s)', fix: '/xrm/admin/customer-tests' }],
    }];
    const get = vi.fn((path: string, _opts?: unknown) =>
      path.endsWith('/publish') ? of(preview) : of(checklist));
    const post = vi.fn((_path: string, _opts?: unknown) => of(publishAnswer));
    TestBed.configureTestingModule({
      imports: [AppReviewComponent],
      providers: [
        { provide: SdkService, useValue: { get, post } },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
    const fixture = TestBed.createComponent(AppReviewComponent);
    fixture.componentRef.setInput('id', 'w1');
    fixture.detectChanges();
    fixture.detectChanges();
    return { fixture, get, post };
  }

  it('shows the grouped changes and reads the checklist inside the workspace', () => {
    const { fixture, get } = setup({ status: 'published' });
    const root = fixture.nativeElement as HTMLElement;
    expect(get.mock.calls[0][0]).toBe('/api/v1/admin/workspaces/w1/publish');
    expect(get.mock.calls[1][0]).toBe('/api/v1/admin/checklist');
    expect(get.mock.calls[1][1]).toEqual({
      query: { entities: 'visit,clinic' },
      headers: { [WORKSPACE_HEADER]: 'w1' },
    });
    expect(root.querySelectorAll('[data-testid="ar-changes"] ul[data-kind]')).toHaveLength(5);
    expect(root.querySelector('[data-testid="ar-checklist"] li[data-done="false"] a')).not.toBeNull();
    expect(fixture.componentInstance.open()).toBe(1);
  });

  it('publishes, and says when the owner must review first', () => {
    const { fixture, post } = setup({ status: 'in_review', review_request_id: 'r1' });
    fixture.componentInstance.publish();
    fixture.detectChanges();
    expect(post.mock.calls[0][0]).toBe('/api/v1/admin/workspaces/w1/publish');
    expect(fixture.componentInstance.outcome()).toBe('in_review');
    expect((fixture.nativeElement as HTMLElement).querySelector('[data-testid="ar-outcome"]')?.textContent)
      .toContain('dataModel.reviewWaiting');
  });
});
