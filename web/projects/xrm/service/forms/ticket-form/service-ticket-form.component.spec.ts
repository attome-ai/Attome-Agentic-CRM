import { Component, input, signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { ATTOME_CONFIG, LangService, UserPreferencesService } from '@attome/base';
import { EntityService, RecordTabPanelsComponent, XrmBaseFormComponent } from '@attome/xrm/core/entity';
import type { XrmFormTabDef } from '@attome/xrm/core/entity';
import type { EntitySchema } from '@attome/xrm';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { SlaService } from '../../sla/sla.service';
import { ServiceTicketFormComponent } from './service-ticket-form.component';

// The real panels have their own specs and each fetches on init; a stub with
// the same selector and inputs proves the wiring without their HTTP.
@Component({ selector: 'xrm-record-tab-panels', standalone: true, template: '' })
class RecordTabPanelsStubComponent {
  readonly entityName = input.required<string>();
  readonly recordId   = input<string | null>(null);
  readonly tabs       = input.required<XrmFormTabDef[]>();
  readonly activeTab  = input.required<string>();
  readonly idPrefix   = input('entity');
}

const TICKET_SCHEMA = {
  id: 'e1', name: 'Ticket', logical_name: 'service_ticket',
  fields: [
    { id: 'f1', entity_id: 'e1', name: 'title', display_name: 'Title', field_type: 'text', options: null, sort_order: 0, is_required: false },
  ],
} as unknown as EntitySchema;

const ID = 'ticket-1';

describe('ServiceTicketFormComponent', () => {
  let svc: { getSchema: ReturnType<typeof vi.fn>; get: ReturnType<typeof vi.fn> };
  let sla: { resumeClock: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    svc = { getSchema: vi.fn(() => of(TICKET_SCHEMA)), get: vi.fn() };
    sla = { resumeClock: vi.fn() };
    TestBed.configureTestingModule({
      imports: [ServiceTicketFormComponent],
      providers: [
        { provide: EntityService, useValue: svc },
        { provide: SlaService, useValue: sla },
        { provide: Router, useValue: { navigate: vi.fn(), parseUrl: () => ({ queryParamMap: { get: () => null } }), url: '/' } },
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
        { provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' } },
        { provide: UserPreferencesService, useValue: { timezone: signal<string | null>(null), calendar: () => null, digits: () => null } },
      ],
    });
    // D-773: the record tabs are rendered by <xrm-base-form>, so the stub goes there.
    TestBed.overrideComponent(XrmBaseFormComponent, {
      remove: { imports: [RecordTabPanelsComponent] },
      add: { imports: [RecordTabPanelsStubComponent] },
    });
  });

  function render(id: string | null) {
    const fixture = TestBed.createComponent(ServiceTicketFormComponent);
    fixture.componentRef.setInput('name', 'service_ticket');
    fixture.componentRef.setInput('id', id);
    fixture.detectChanges();
    return fixture;
  }

  it('carries Details plus the shared Documents, Communications, Notes, Activities, Relationships, Timeline and History tabs', () => {
    svc.get.mockReturnValue(of({ id: ID, row_version: 1, data: { title: 'x' } }));
    const fixture = render(ID);
    expect(fixture.componentInstance.tabs().map(t => t.id))
      .toEqual(['details', 'documents', 'communications', 'notes', 'activities', 'relationships', 'timeline', 'history']);
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('#service-ticket-tab-notes')?.getAttribute('aria-controls')).toBe('service-ticket-panel-notes');
    const panels = fixture.debugElement.query(d => d.componentInstance instanceof RecordTabPanelsStubComponent)
      .componentInstance as RecordTabPanelsStubComponent;
    expect(panels.idPrefix()).toBe('service-ticket');
    expect(panels.recordId()).toBe(ID);
    expect(panels.tabs().map(t => t.id)).toContain('relationships');
    expect(panels.tabs().map(t => t.id)).toContain('timeline');
  });

  it('shows the SLA badge from the loaded record and refreshes it after an SLA action', () => {
    svc.get
      .mockReturnValueOnce(of({ id: ID, row_version: 1, data: { sla_policy_id: 'p', resolution_due_at: '2020-01-01T00:00:00Z', sla_breached: true } }))
      .mockReturnValueOnce(of({ id: ID, row_version: 2, data: { sla_policy_id: 'p', resolved_at: '2020-01-02T00:00:00Z' } }));
    sla.resumeClock.mockReturnValue(of({ state: 'running' }));
    const fixture = render(ID);
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector<HTMLElement>('.xf-header [data-testid="sla-badge"]')?.dataset['kind']).toBe('breached');

    el.querySelector<HTMLButtonElement>('[data-testid="sla-resume"]')!.click();
    fixture.detectChanges();
    expect(sla.resumeClock).toHaveBeenCalledWith(ID);
    expect(svc.get).toHaveBeenCalledTimes(2);
    expect(el.querySelector<HTMLElement>('[data-testid="sla-badge"]')?.dataset['kind']).toBe('resolved');
  });

  it('has no SLA actions and no badge on a new ticket', () => {
    const fixture = render(null);
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-testid="ticket-sla-actions"]')).toBeNull();
    expect(el.querySelector('[data-testid="sla-badge"]')).toBeNull();
    expect(svc.get).not.toHaveBeenCalled();
  });
});
