import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { WorkflowAdminService } from '../services/workflow-admin.service';
import {
  TemplateDoc, WorkflowTemplateGalleryComponent, argumentOf, filterTemplates, templateCommands, templateSlug,
} from './template-gallery.component';

const DOC: TemplateDoc = {
  description_en: 'Approve large invoices',
  parameters: [
    { name: 'entity', type: 'entity' },
    { name: 'approvers', type: 'users' },
  ],
  graph: { nodes: [], edges: [] },
};

describe('WorkflowTemplateGalleryComponent (M6-T4)', () => {
  function create() {
    const get = vi.fn((url: string) => url.endsWith('/flow_template')
      ? of({ items: [{ id: 't-1', name: 'big_invoices', app: 'core', state: 'published' },
                     { id: 't-2', name: 'draft_only', app: 'core', state: 'draft' }] })
      : of({ doc: DOC }));
    const post = vi.fn((_url: string, _body: unknown) => of({ graph: { nodes: [], edges: [] }, issues: [] }));
    const workflows = {
      listDefinitions: vi.fn(() => of([])),
      createDefinition: vi.fn(() => of({ id: 'f-1' })),
      createVersion: vi.fn(() => of({ id: 'v-1', definition_id: 'f-1' })),
      getDefinition: vi.fn(), getVersion: vi.fn(),
    };
    const navigate = vi.fn(() => Promise.resolve(true));
    TestBed.configureTestingModule({
      imports: [WorkflowTemplateGalleryComponent],
      providers: [
        { provide: ApiService, useValue: { get, post } },
        { provide: WorkflowAdminService, useValue: workflows },
        { provide: Router, useValue: { navigate } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: () => 'en-US' } },
      ],
    });
    const fixture = TestBed.createComponent(WorkflowTemplateGalleryComponent);
    fixture.detectChanges();
    return { fixture, post, workflows, navigate };
  }

  it('lists only published templates with their descriptions', () => {
    const { fixture } = create();
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-template="t-1"]')?.textContent).toContain('Approve large invoices');
    expect(el.querySelector('[data-template="t-2"]')).toBeNull();
  });

  it('fills a template and opens the new draft flow', () => {
    const { fixture, post, workflows, navigate } = create();
    const c = fixture.componentInstance;
    c.select(c.items()[0]);
    c.args = { entity: 'invoice', approvers: 'u-1, u-2' };
    c.flowLogicalname = 'big_invoices';
    c.start();
    expect(post).toHaveBeenCalledWith('/api/v1/admin/model/flow_template/t-1/instantiate', {
      args: { entity: 'invoice', approvers: ['u-1', 'u-2'] },
    });
    expect(workflows.createVersion).toHaveBeenCalledWith('f-1', { graph: { nodes: [], edges: [] } });
    expect(navigate).toHaveBeenCalledWith(['/xrm/workflow/definitions', 'f-1', 'versions', 'v-1']);
  });

  it('searches names and descriptions and types arguments', () => {
    const items = [{ id: 'a', name: 'renewals', app: 'x', state: 'published' }];
    expect(filterTemplates(items, { a: { description_en: 'Hijri renewal reminders' } }, 'hijri')).toHaveLength(1);
    expect(filterTemplates(items, {}, 'zatca')).toHaveLength(0);
    expect(argumentOf({ name: 'n', type: 'number' }, '42')).toBe(42);
    expect(argumentOf({ name: 'n', type: 'text' }, '  ')).toBeUndefined();
    expect(templateSlug('Big Invoices!')).toBe('big_invoices');
    expect(templateSlug('2026 plan')).toBe('template_2026_plan');
    expect(templateCommands('d', { nodes: [] }, [])).toHaveLength(3);
  });
});
