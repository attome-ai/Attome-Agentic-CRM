import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { GraphEdge, RelationshipExplorerComponent, pathSteps, ringLayout } from './relationship-explorer.component';

const edge = (from: [string, string], to: [string, string], type: string): GraphEdge => ({
  from_entity: from[0], from_id: from[1], to_entity: to[0], to_id: to[1], edge_type: type,
});

describe('relationship explorer (A7-T5)', () => {
  it('lays the ring out evenly from the top and reads a path step by step', () => {
    const points = ringLayout(4, 100, 180, 180);
    expect(points[0]).toEqual({ x: 180, y: 80 });
    expect(points[2]).toEqual({ x: 180, y: 280 });
    const steps = pathSteps([
      edge(['contact', 'c1'], ['account', 'a1'], 'lookup:account_ref'),
      edge(['opportunity', 'o1'], ['account', 'a1'], 'lookup:account_ref'),
    ], { entity: 'contact', id: 'c1' });
    expect(steps).toEqual([
      { entity: 'contact', via: 'account_ref' },
      { entity: 'account', via: 'account_ref' },
      { entity: 'opportunity', via: null },
    ]);
  });

  function setUp() {
    const post = vi.fn((url: string) => url.endsWith('/traverse')
      ? of({
        nodes: { items: [], total: 2, page: 1, page_size: 100 },
        edges: [
          edge(['contact', 'c1'], ['account', 'a1'], 'lookup:account_ref'),
          edge(['case', 'k1'], ['contact', 'c1'], 'lookup:contact_ref'),
        ],
        truncated: false,
      })
      : of({ paths: [[edge(['contact', 'c1'], ['account', 'a1'], 'lookup:account_ref')]], truncated: false }));
    TestBed.configureTestingModule({
      imports: [RelationshipExplorerComponent],
      providers: [
        { provide: ApiService, useValue: { post } },
        { provide: Router, useValue: { navigate: vi.fn() } },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, errorText: () => 'e', isRtl: signal(false) },
        },
      ],
    });
    const fixture = TestBed.createComponent(RelationshipExplorerComponent);
    fixture.componentRef.setInput('entityName', 'contact');
    fixture.componentRef.setInput('recordId', 'c1');
    fixture.detectChanges();
    return { fixture, cmp: fixture.componentInstance, el: fixture.nativeElement as HTMLElement, post };
  }

  it('draws the record and what it links to directly', () => {
    const { cmp, fixture, el } = setUp();
    fixture.detectChanges();
    expect(cmp.ring().map(n => n.node.entity)).toEqual(['account', 'case']);
    expect(el.querySelectorAll('[data-testid="rx-diagram"] .rx-node-link').length).toBe(2);
  });

  it('finds how the record connects to another one', () => {
    const { cmp, fixture, el, post } = setUp();
    cmp.targetEntity.set('account');
    cmp.targetId.set('a1');
    cmp.findPaths();
    expect(post).toHaveBeenLastCalledWith('/api/v1/graph/paths', {
      from: { entity: 'contact', id: 'c1' },
      to: { entity: 'account', id: 'a1' },
    });
    fixture.detectChanges();
    expect(el.querySelectorAll('[data-testid="rx-path"]').length).toBe(1);
    expect(el.querySelector('.rx-path-via')?.textContent).toContain('account_ref');
  });
});
