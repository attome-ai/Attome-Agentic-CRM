import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { LineageService } from '@attome/xrm/core/admin/data';
import type { ImpactReport, LineageCleanup, LineageGraph } from '@attome/xrm/core/admin/data';

import { CleanupListComponent } from './cleanup-list.component';
import { ImpactPanelComponent } from './impact-panel.component';
import { LineageGraphComponent } from './lineage-graph.component';
import { LineageComponent } from './lineage.component';
import { NODE_W, layoutLineage, walkTarget } from './lineage-layout';

const ID = '0192f0a0-0000-7000-8000-000000000001';
const ID2 = '0192f0a0-0000-7000-8000-000000000002';

/** contact.email, used by a query, itself used by a dashboard that reads personal data. */
const graph = (): LineageGraph => ({
  nodes: [
    { key: 'entity:contact.email', node: { Data: { entity: 'contact', attribute: 'email' } }, label: 'contact.email', depth: 0, reads_personal: false },
    { key: `query:${ID}`, node: { Definition: { kind: 'query', id: ID } }, label: 'Active contacts', depth: 1, reads_personal: false },
    { key: `dashboard:${ID2}`, node: { Definition: { kind: 'dashboard', id: ID2 } }, label: 'Outreach', depth: 2, reads_personal: true },
  ],
  edges: [
    { from: `query:${ID}`, to: 'entity:contact.email', edge_kind: 'reads', confidence: 'parsed' },
    { from: `dashboard:${ID2}`, to: `query:${ID}`, edge_kind: 'reads', confidence: 'parsed' },
  ],
  hidden: 1,
  truncated: false,
});

const lang = (rtl: boolean) => ({
  translate: (k: string) => k, intlLocale: () => 'en-US', isRtl: () => rtl, current: signal(rtl ? 'ar' : 'en'),
});

describe('lineage layout (L5-T7)', () => {
  it('lays columns by depth with data flowing toward the end', () => {
    const l = layoutLineage(graph(), 'down', false);
    const x = (key: string) => l.nodes.find(n => n.node.key === key)!.x;
    expect(x('entity:contact.email')).toBeLessThan(x(`query:${ID}`));
    expect(x(`query:${ID}`)).toBeLessThan(x(`dashboard:${ID2}`));
    expect(l.edges.length).toBe(2);
    // The edge runs from the source's end side to the user's start side.
    expect(l.edges[0].path.startsWith(`M${NODE_W},`)).toBe(true);
  });

  it('graph renders right to left in Arabic', () => {
    const ltr = layoutLineage(graph(), 'down', false);
    const rtl = layoutLineage(graph(), 'down', true);
    const x = (l: typeof ltr, key: string) => l.nodes.find(n => n.node.key === key)!.x;
    expect(x(rtl, 'entity:contact.email')).toBeGreaterThan(x(rtl, `dashboard:${ID2}`));
    expect(x(rtl, 'entity:contact.email')).toBe(ltr.width - x(ltr, 'entity:contact.email') - NODE_W);
  });

  it('an upstream walk puts what the start uses first', () => {
    const up = layoutLineage(graph(), 'up', false);
    const x = (key: string) => up.nodes.find(n => n.node.key === key)!.x;
    expect(x(`dashboard:${ID2}`)).toBeLessThan(x('entity:contact.email'));
  });

  it('marks paths into personal-data readers and edges added in compare mode', () => {
    const g = graph();
    const l = layoutLineage(g, 'down', false, { from: 1, to: 2, added: [g.edges[0]], removed: [], truncated: false });
    const intoDashboard = l.edges.find(e => e.edge.from === `dashboard:${ID2}`)!;
    const intoQuery = l.edges.find(e => e.edge.from === `query:${ID}`)!;
    expect(intoDashboard.sensitive).toBe(true);
    expect(intoQuery.sensitive).toBe(false);
    expect(intoQuery.added).toBe(true);
    expect(intoDashboard.added).toBe(false);
  });

  it('reads a node key as a walk target', () => {
    expect(walkTarget('entity:contact.email')).toEqual({ kind: 'entity', ref: 'contact.email' });
    expect(walkTarget(`metric:${ID}`)).toEqual({ kind: 'metric', ref: ID });
    expect(walkTarget('nonsense')).toBeNull();
  });
});

describe('LineageGraphComponent (L5-T7)', () => {
  beforeEach(() => {
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      imports: [LineageGraphComponent],
      providers: [{ provide: LangService, useValue: lang(false) }],
    });
  });

  it('draws nodes, red paths and a list in reading order', () => {
    const fixture = TestBed.createComponent(LineageGraphComponent);
    fixture.componentRef.setInput('graph', graph());
    fixture.detectChanges();
    const root: HTMLElement = fixture.nativeElement;
    expect(root.querySelectorAll('[data-lineage-node]').length).toBe(3);
    expect(root.querySelectorAll('.lg-edge--sensitive').length).toBe(1);
    expect(root.querySelector('.lg-node--sensitive')?.getAttribute('data-key')).toBe(`dashboard:${ID2}`);
    const opened: string[] = [];
    fixture.componentInstance.open.subscribe(k => opened.push(k));
    (root.querySelector(`[data-lineage-open][data-key="query:${ID}"]`) as HTMLButtonElement).click();
    expect(opened).toEqual([`query:${ID}`]);
  });
});

describe('LineageComponent (L5-T7)', () => {
  let svc: { walk: ReturnType<typeof vi.fn>; compare: ReturnType<typeof vi.fn>; cleanup: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    TestBed.resetTestingModule();
    svc = {
      walk: vi.fn(() => of(graph())),
      compare: vi.fn(() => of({ from: 1, to: 2, added: [], removed: [], truncated: false })),
      cleanup: vi.fn(() => of({ dangling: [], cycles: [], unused_attributes: [] } satisfies LineageCleanup)),
    };
    TestBed.configureTestingModule({
      imports: [LineageComponent],
      providers: [provideRouter([]), { provide: LineageService, useValue: svc }, { provide: LangService, useValue: lang(true) }],
    });
  });

  it('walks from the deep-linked node with the chosen filters and compares versions', () => {
    const fixture = TestBed.createComponent(LineageComponent);
    fixture.componentRef.setInput('node', 'entity:contact.email');
    fixture.detectChanges();
    expect(svc.walk).toHaveBeenCalledWith('entity', 'contact.email', { direction: 'down', depth: 3, kinds: [], version: null });
    expect(svc.compare).not.toHaveBeenCalled();

    const c = fixture.componentInstance;
    c.direction.set('up');
    c.depth.set(40);
    c.toggleKind('metric');
    c.version.set(2);
    c.compareFrom.set(1);
    c.walk();
    expect(svc.walk).toHaveBeenLastCalledWith('entity', 'contact.email', { direction: 'up', depth: 10, kinds: ['metric'], version: 2 });
    expect(svc.compare).toHaveBeenCalledWith(1, 2);
    fixture.detectChanges();
    const root: HTMLElement = fixture.nativeElement;
    expect(root.querySelector('[data-lineage-comparison]')).not.toBeNull();
    expect(root.querySelectorAll('[data-lineage-node]').length).toBe(3);
  });
});

describe('CleanupListComponent (L5-T7)', () => {
  function render(cleanup: LineageCleanup) {
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      imports: [CleanupListComponent],
      providers: [
        { provide: LineageService, useValue: { cleanup: () => of(cleanup) } },
        { provide: LangService, useValue: lang(false) },
      ],
    });
    const fixture = TestBed.createComponent(CleanupListComponent);
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  it('lists dangling links, cycles and unused fields', () => {
    const root = render({
      dangling: [{ from: `query:${ID}`, to: 'entity:gone.field', edge_kind: 'reads', confidence: 'parsed' }],
      cycles: [[`metric:${ID}`, `metric:${ID2}`]],
      unused_attributes: ['contact.fax'],
    });
    expect(root.querySelector('[data-cleanup-dangling]')?.textContent).toContain('entity:gone.field');
    expect(root.querySelector('[data-cleanup-cycles]')?.textContent).toContain(`metric:${ID2}`);
    expect(root.querySelector('[data-cleanup-unused]')?.textContent).toContain('contact.fax');
    expect(root.querySelector('[data-cleanup-clean]')).toBeNull();
  });

  it('says when there is nothing to tidy', () => {
    expect(render({ dangling: [], cycles: [], unused_attributes: [] }).querySelector('[data-cleanup-clean]')).not.toBeNull();
  });
});

describe('ImpactPanelComponent (L5-T7)', () => {
  let impact: ReturnType<typeof vi.fn>;

  function render(report: ImpactReport) {
    TestBed.resetTestingModule();
    impact = vi.fn(() => of(report));
    TestBed.configureTestingModule({
      imports: [ImpactPanelComponent],
      providers: [{ provide: LineageService, useValue: { impact } }, { provide: LangService, useValue: lang(false) }],
    });
    const fixture = TestBed.createComponent(ImpactPanelComponent);
    fixture.componentRef.setInput('entity', 'contact');
    fixture.componentRef.setInput('attribute', 'email');
    fixture.componentRef.setInput('change', 'delete');
    fixture.detectChanges();
    TestBed.flushEffects();
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  it('impact panel lists breaking items first, then what is affected by depth', () => {
    const root = render({
      affected: [
        { from_kind: 'dashboard', from_ref: ID2, from_label: 'Outreach', depth: 2, edge_kind: 'reads', confidence: 'parsed', attribute_level: false, change: 0 },
        { from_kind: 'metric', from_ref: ID, from_label: 'Reach', depth: 1, edge_kind: 'reads', confidence: 'parsed', attribute_level: true, change: 0 },
      ],
      breaking: [{ from_kind: 'metric', from_ref: ID, from_label: 'Reach', edge_kind: 'reads' }],
      hidden: 2,
    });
    expect(impact).toHaveBeenCalledWith('contact', 'email', 'delete');
    expect(root.querySelector('[data-impact-breaking]')?.textContent).toContain('Reach');
    const items = [...root.querySelectorAll('[data-impact-affected] li')].map(li => li.textContent ?? '');
    expect(items[0]).toContain('Reach');
    expect(items[1]).toContain('Outreach');
    expect(root.textContent).toContain('governance.lineage.impact.hidden');
  });

  it('says when nothing uses the field', () => {
    const root = render({ affected: [], breaking: [], hidden: 0 });
    expect(root.querySelector('[data-impact-none]')).not.toBeNull();
    expect(root.querySelector('[data-impact-breaking]')).toBeNull();
  });
});
