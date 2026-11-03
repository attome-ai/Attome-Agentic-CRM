import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService, SdkService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import {
  DraftResult, DraftReviewComponent, acceptedCalls, attributeKey, entityKey, layoutDraft,
} from './draft-review.component';

const RESULT: DraftResult = {
  findings: [],
  plan: [
    { entity: 'visit', decision: 'create', add_attributes: ['visited_on', 'notes'], ask_attributes: [] },
    { entity: 'tenant', decision: 'extend', base: 'party', add_attributes: ['lease_start'], ask_attributes: [] },
    { entity: 'invoice', decision: 'reuse', existing: 'invoice', add_attributes: ['memo'], ask_attributes: [] },
    { entity: 'properties', decision: 'ask', question: 'close to property', add_attributes: [], ask_attributes: [] },
  ],
  calls: [
    { action: 'model.entity.create', args: { logicalname: 'visit', name: 'Visit' } },
    { action: 'model.entity.create', args: { logicalname: 'tenant', name: 'Tenant', extends_entity_id: 'p' } },
    { action: 'model.attribute.create', args: { entity: 'visit', logicalname: 'visited_on', field_type: 'date' } },
    { action: 'model.attribute.create', args: { entity: 'visit', logicalname: 'notes', field_type: 'text' } },
    { action: 'model.attribute.create', args: { entity: 'tenant', logicalname: 'lease_start', field_type: 'date' } },
    { action: 'model.attribute.create', args: { entity: 'invoice', logicalname: 'memo', field_type: 'text' } },
  ],
};

describe('acceptedCalls (AD1-T2)', () => {
  it('keeps every call until something is rejected', () => {
    expect(acceptedCalls(RESULT, new Set())).toHaveLength(6);
  });

  it('drops a rejected entity with its attributes, and a rejected attribute alone', () => {
    const left = acceptedCalls(RESULT, new Set([entityKey('visit'), attributeKey('invoice', 'memo')]));
    expect(left.map(c => `${c.action}:${String(c.args['logicalname'])}`)).toEqual([
      'model.entity.create:tenant',
      'model.attribute.create:lease_start',
    ]);
  });
});

describe('layoutDraft', () => {
  it('puts the drafted entities above what they extend or reuse', () => {
    const d = layoutDraft(RESULT, false);
    const proposed = d.nodes.filter(n => n.role === 'proposed').map(n => n.logicalname);
    expect(proposed).toEqual(['visit', 'tenant', 'invoice', 'properties']);
    expect(d.nodes.filter(n => n.role === 'base').map(n => n.logicalname)).toEqual(['party', 'invoice']);
    expect(d.edges).toEqual([
      { from: 'tenant', to: 'party', kind: 'extends' },
      { from: 'invoice', to: 'invoice', kind: 'reuses' },
    ]);
  });

  it('mirrors in a right-to-left language', () => {
    const ltr = layoutDraft(RESULT, false).nodes[0].x;
    const rtl = layoutDraft(RESULT, true).nodes[0].x;
    expect(ltr + rtl).toBe(900);
  });
});

describe('DraftReviewComponent', () => {
  function setup() {
    const post = vi.fn((path: string) =>
      path.includes('model.draft') ? of({ status: 'completed', result: RESULT }) : of({ status: 'completed' }));
    TestBed.configureTestingModule({
      imports: [DraftReviewComponent],
      providers: [
        { provide: SdkService, useValue: { post } },
        { provide: LangService, useValue: { translate: (key: string) => key, isRtl: signal(false) } },
      ],
    });
    const fixture = TestBed.createComponent(DraftReviewComponent);
    fixture.detectChanges();
    return { fixture, post };
  }

  it('drafts, shows each step, and makes only the accepted calls', () => {
    const { fixture, post } = setup();
    const component = fixture.componentInstance;
    component.description.set('A property company with tenants and visits');
    component.draft();
    fixture.detectChanges();
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelectorAll('[data-testid="draft-step"]')).toHaveLength(4);
    expect(root.querySelectorAll('[data-testid="draft-node"][data-role="base"]')).toHaveLength(2);

    component.toggle(entityKey('visit'));
    fixture.detectChanges();
    expect(component.accepted()).toHaveLength(3);

    component.apply();
    const invoked = post.mock.calls.map(c => c[0]).filter(p => !p.includes('model.draft'));
    expect(invoked).toEqual([
      '/api/v1/actions/model.entity.create/invoke',
      '/api/v1/actions/model.attribute.create/invoke',
      '/api/v1/actions/model.attribute.create/invoke',
    ]);
    expect(component.applied()).toBe(3);
  });
});
