import type { XrmFormTabDef } from '@attome/xrm/core/entity';
import { Component, input } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { EMPTY, of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiService, ATTOME_CONFIG, LangService } from '@attome/base';
import type { EntitySchema } from '@attome/xrm';
import { EntityService, RecordTabPanelsComponent, XrmBaseFormComponent } from '@attome/xrm/core/entity';
import { AiAgentFormComponent } from './ai-agent-form.component';

/**
 * D-561 §5 on the agent form: `retrieval_mode` is editable here, and the form
 * says plainly that the edit reaches new sessions only — a running session
 * keeps the mode stored when it started. The section appears only when the
 * entity carries the attribute, so a deployment whose bundle predates it shows
 * no control that would save nothing.
 */
const field = (id: string, name: string) => ({
  id, entity_id: 'e1', name, display_name: name, field_type: 'text', options: null,
  sort_order: 0, is_required: false,
});

const schema = (withMode: boolean): EntitySchema => ({
  id: 'e1',
  name: 'Agent',
  logical_name: 'ai_agent',
  fields: withMode ? [field('f1', 'name'), field('f2', 'retrieval_mode')] : [field('f1', 'name')],
  relationships: [],
} as unknown as EntitySchema);

const INERT = [
  'bulkStatus', 'bulkUpdate', 'delete', 'exportRecords', 'exportStatus', 'hardDelete',
  'invalidateSchema', 'linkRelated', 'list', 'listRelated', 'listTransitions',
  'lookupSearch', 'restore', 'transition', 'unlinkRelated', 'update', 'create',
] as const;

// D-773: the record tabs render inside <xrm-base-form>; each panel has its own
// spec and fetches on init, so a stub with the same selector and inputs
// stands in for them here.
@Component({ selector: 'xrm-record-tab-panels', standalone: true, template: '' })
class RecordTabPanelsStubComponent {
  readonly entityName = input.required<string>();
  readonly recordId   = input<string | null>(null);
  readonly tabs       = input.required<XrmFormTabDef[]>();
  readonly activeTab  = input.required<string>();
  readonly idPrefix   = input('entity');
}

function stubRecordTabs(): void {
  TestBed.overrideComponent(XrmBaseFormComponent, {
    remove: { imports: [RecordTabPanelsComponent] },
    add: { imports: [RecordTabPanelsStubComponent] },
  });
}

describe('AiAgentFormComponent — knowledge retrieval mode', () => {
  let getSchema: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    getSchema = vi.fn();
    const inert: Record<string, unknown> = {};
    for (const m of INERT) inert[m] = vi.fn().mockReturnValue(EMPTY);
    TestBed.configureTestingModule({
      imports: [AiAgentFormComponent],
      providers: [
        {
          provide: EntityService,
          useValue: {
            ...inert,
            getSchema,
            get: vi.fn().mockReturnValue(of({ id: 'a-1', data: { name: 'Agent', retrieval_mode: 'pre_retrieved' }, row_version: 1 })),
          },
        },
        { provide: ApiService, useValue: { get: vi.fn().mockReturnValue(EMPTY), post: vi.fn().mockReturnValue(EMPTY), put: vi.fn().mockReturnValue(EMPTY), patch: vi.fn().mockReturnValue(EMPTY), delete: vi.fn().mockReturnValue(EMPTY) } },
        { provide: Router, useValue: { navigate: vi.fn(), parseUrl: () => ({ queryParamMap: { get: () => null } }), url: '/' } },
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
    stubRecordTabs();
  });

  function render(withMode: boolean) {
    getSchema.mockReturnValue(of(schema(withMode)));
    const fixture = TestBed.createComponent(AiAgentFormComponent);
    fixture.componentRef.setInput('name', 'ai_agent');
    fixture.componentRef.setInput('id', 'a-1');
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  it('offers the retrieval mode and says an edit reaches new sessions only', () => {
    const html = render(true);
    expect(html.textContent).toContain('aiAgentForm.knowledgeSection');
    const note = html.querySelector('.ai-agent-form__snapshot');
    expect(note?.getAttribute('role')).toBe('note');
    expect(note?.textContent).toContain('aiAgentForm.retrievalModeSnapshot');
    expect(html.querySelectorAll('attome-field-input').length).toBe(2);
  });

  it('shows no knowledge section when the entity has no retrieval_mode attribute', () => {
    const html = render(false);
    expect(html.textContent).not.toContain('aiAgentForm.knowledgeSection');
    expect(html.querySelector('.ai-agent-form__snapshot')).toBeNull();
  });
});
