import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService, SdkService } from '@attome/base';
import { AdminService, LineageService } from '@attome/xrm/core/admin/data';
import type { EntityDetail, EntityMeta, ImpactReport, RelationshipDef } from '@attome/xrm/core/admin/data';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { DataModelDiagramComponent, layoutDiagram } from './data-model-diagram.component';

const entity = (id: string, logicalname: string, extendsId: string | null = null) =>
  ({ id, logicalname, name: logicalname, extends_entity_id: extendsId, is_active: true }) as unknown as EntityMeta;

const PARTY = entity('p', 'party');
const CONTACT = entity('c', 'contact', 'p');
const ACCOUNT = entity('a', 'account');
const LEAD = entity('l', 'lead', 'c');
const ALL = [ACCOUNT, CONTACT, LEAD, PARTY];

const DETAIL = {
  id: 'c', logicalname: 'contact', name: 'contact', extends_entity_id: 'p', storage_mode: 'standard',
  attributes: [
    { id: 'f1', logicalname: 'account_ref', name: 'Account', field_type: 'lookup', lookup_entity_name: 'account',
      is_active: true, sensitivity: 'internal', data_classification: 'general' },
    { id: 'f2', logicalname: 'email', name: 'Email', field_type: 'email', lookup_entity_name: null,
      is_active: true, sensitivity: 'personal', data_classification: 'personal' },
  ],
} as unknown as EntityDetail;

const RELATIONSHIPS = [
  { id: 'r1', name: 'contact_tag', entity_a: 'contact', entity_b: 'tag', is_active: true },
] as unknown as RelationshipDef[];

const IMPACT: ImpactReport = {
  affected: [{ from_kind: 'form', from_ref: 'f', from_label: 'Contact form', depth: 1, edge_kind: 'reads',
    confidence: 'exact', attribute_level: true, change: 1 }],
  breaking: [{ from_kind: 'workflow', from_ref: 'w', from_label: 'Welcome email', edge_kind: 'reads' }],
  hidden: 0,
};

function setup(rtl = false) {
  const admin = {
    listEntities: vi.fn().mockReturnValue(of(ALL)),
    listRelationships: vi.fn().mockReturnValue(of(RELATIONSHIPS)),
    getEntity: vi.fn().mockReturnValue(of(DETAIL)),
  };
  const lineage = { impact: vi.fn().mockReturnValue(of(IMPACT)) };
  TestBed.configureTestingModule({
    imports: [DataModelDiagramComponent],
    providers: [
      { provide: AdminService, useValue: admin },
      { provide: LineageService, useValue: lineage },
      // AD1-T2: the draft review the page embeds; not exercised here.
      { provide: SdkService, useValue: { post: vi.fn() } },
      { provide: LangService, useValue: { translate: (key: string) => key, isRtl: signal(rtl), intlLocale: () => 'en-US' } },
    ],
  });
  const fixture = TestBed.createComponent(DataModelDiagramComponent);
  fixture.componentInstance.centerName.set('contact');
  fixture.detectChanges();
  TestBed.flushEffects();
  fixture.detectChanges();
  return { admin, lineage, fixture };
}

const nodeX = (root: HTMLElement, name: string) =>
  Number(root.querySelector(`[data-testid="dm-node"][data-name="${name}"]`)?.getAttribute('data-x'));

describe('DataModelDiagramComponent (A1-T14)', () => {
  it('lays out lookups, links and inheritance around the entity', () => {
    const d = layoutDiagram(CONTACT, DETAIL, ALL, RELATIONSHIPS, false);
    const role = (n: string) => d.nodes.find(x => x.logicalname === n)?.role;
    expect(role('contact')).toBe('center');
    expect(role('account')).toBe('lookup');
    expect(role('party')).toBe('base');
    expect(role('lead')).toBe('derived');
    expect(role('tag')).toBe('related');
    expect(d.edges.filter(e => e.kind === 'extends').length).toBe(2);
    expect(d.edges.find(e => e.kind === 'lookup')?.label).toBe('Account');
  });

  it('diagram mirrors in RTL', () => {
    const ltr = setup(false).fixture.nativeElement as HTMLElement;
    expect(nodeX(ltr, 'account')).toBeGreaterThan(nodeX(ltr, 'contact'));
    expect(nodeX(ltr, 'tag')).toBeLessThan(nodeX(ltr, 'contact'));
    TestBed.resetTestingModule();
    const rtl = setup(true).fixture.nativeElement as HTMLElement;
    expect(nodeX(rtl, 'account')).toBeLessThan(nodeX(rtl, 'contact'));
    expect(nodeX(rtl, 'tag')).toBeGreaterThan(nodeX(rtl, 'contact'));
  });

  it('shows uses before delete', () => {
    const { lineage, fixture } = setup();
    const root = fixture.nativeElement as HTMLElement;
    const button = root.querySelector('[data-testid="dm-attribute"] [data-testid="dm-uses-delete"]') as HTMLButtonElement;
    button.click();
    fixture.detectChanges();
    expect(lineage.impact).toHaveBeenCalledWith('contact', 'account_ref', 'delete');
    const uses = root.querySelector('[data-testid="dm-uses"]') as HTMLElement;
    expect(uses.querySelector('[data-breaking]')?.textContent).toContain('Welcome email');
    expect(uses.querySelector('[data-affected]')?.textContent).toContain('Contact form');
  });
});
