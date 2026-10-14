import { Component, signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService, UserPreferencesService } from '@attome/base';
import { RecordTimelineService } from '@attome/xrm/core/entity/record-activity';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';
import { RecordTabPanelsComponent } from './record-tab-panels.component';
import { recordTabDefs, RECORD_TAB_IDS } from './record-tabs';
import type { XrmFormTabDef } from '../base/xrm-form.base';

const echo = (key: string) => key;

describe('recordTabDefs', () => {
  it('returns every record tab, in the generic form order, for an ordinary entity', () => {
    expect(recordTabDefs('contact', echo).map(t => t.id)).toEqual([...RECORD_TAB_IDS]);
  });

  it('resolves labels through the translate function', () => {
    const tabs = recordTabDefs('contact', key => `T(${key})`, ['notes']);
    expect(tabs).toEqual([{ id: 'notes', label: 'T(xrmForm.tabs.notes)', icon: 'las la-sticky-note' }]);
  });

  it('hides each tab on its own entity', () => {
    expect(recordTabDefs('attome_document', echo).map(t => t.id)).not.toContain('documents');
    expect(recordTabDefs('note', echo).map(t => t.id)).not.toContain('notes');
    expect(recordTabDefs('activity', echo).map(t => t.id)).not.toContain('activities');
    expect(recordTabDefs('tag_category', echo).map(t => t.id)).not.toContain('tags');
    expect(recordTabDefs('tag_item', echo).map(t => t.id)).not.toContain('tags');
    expect(recordTabDefs('audit_consent', echo).map(t => t.id)).not.toContain('consent');
    expect(recordTabDefs('audit_consent_purpose', echo).map(t => t.id)).not.toContain('consent');
  });

  it('restricts to `include` but keeps the canonical order', () => {
    const ids = recordTabDefs('service_ticket', echo, ['relationships', 'notes', 'documents']).map(t => t.id);
    expect(ids).toEqual(['documents', 'notes', 'relationships']);
  });
});

// Mounted without a record id, so no panel's heavy child component is
// instantiated: this spec is about which panels render and how they are
// wired to the tab strip, not about each panel's own behaviour (they have
// their own specs).
@Component({
  standalone: true,
  imports: [RecordTabPanelsComponent],
  template: `<xrm-record-tab-panels [entityName]="'contact'" [recordId]="recordId()"
               [tabs]="tabs()" [activeTab]="active()" idPrefix="demo" />`,
})
class HostComponent {
  readonly recordId = signal<string | null>(null);
  readonly tabs = signal<XrmFormTabDef[]>([
    { id: 'details', label: 'Details', icon: '' },
    ...recordTabDefs('contact', echo, ['documents', 'notes', 'relationships']),
  ]);
  readonly active = signal('notes');
}

function mount() {
  TestBed.configureTestingModule({
    imports: [HostComponent],
    providers: [{ provide: LangService, useValue: { translate: (key: string) => key } }],
  });
  const fixture = TestBed.createComponent(HostComponent);
  fixture.detectChanges();
  return fixture;
}

describe('RecordTabPanelsComponent', () => {
  it('renders a panel only for the record tabs present in `tabs`, wired to the prefixed tab ids', () => {
    const fixture = mount();
    const el: HTMLElement = fixture.nativeElement;
    const panels = Array.from(el.querySelectorAll<HTMLElement>('[role="tabpanel"]'));
    expect(panels.map(p => p.id)).toEqual(['demo-panel-documents', 'demo-panel-notes', 'demo-panel-relationships']);
    expect(panels[1].getAttribute('aria-labelledby')).toBe('demo-tab-notes');
    expect(el.querySelector('[data-testid="communications-tab"]')).toBeNull();
    expect(el.querySelector('[data-testid="tags-tab"]')).toBeNull();
  });

  it('shows only the active panel', () => {
    const fixture = mount();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector<HTMLElement>('#demo-panel-notes')!.hidden).toBe(false);
    expect(el.querySelector<HTMLElement>('#demo-panel-documents')!.hidden).toBe(true);
    fixture.componentInstance.active.set('documents');
    fixture.detectChanges();
    expect(el.querySelector<HTMLElement>('#demo-panel-documents')!.hidden).toBe(false);
    expect(el.querySelector<HTMLElement>('#demo-panel-notes')!.hidden).toBe(true);
  });

  it('asks for a save first while there is no record id', () => {
    const fixture = mount();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('#demo-panel-notes .xf-hint')?.textContent).toContain('xrmForm.saveBeforeNotes');
    expect(el.querySelector('#demo-panel-documents .xf-hint')?.textContent).toContain('xrmForm.saveBeforeDocuments');
    expect(el.querySelector('#demo-panel-relationships .xf-hint')?.textContent)
      .toContain('xrmForm.saveBeforeRelationships');
  });
});

// U3 (D-601): the Timeline panel comes from the record-activity entry point,
// loaded lazily the first time the tab is opened on a saved record.
@Component({
  selector: 'xrm-saved-record-tabs-host',
  standalone: true,
  imports: [RecordTabPanelsComponent],
  template: `<xrm-record-tab-panels [entityName]="'contact'" [recordId]="'rec-1'"
               [tabs]="tabs" [activeTab]="active()" idPrefix="demo" />`,
})
class SavedHostComponent {
  // Only the two lazily loaded tabs: any other panel would mount its own
  // data component against this saved record id.
  readonly tabs = recordTabDefs('contact', echo, ['timeline', 'history']);
  readonly active = signal('details');
}

describe('RecordTabPanelsComponent record activity', () => {
  it('loads the timeline panel only when its tab is opened', async () => {
    const timeline = vi.fn().mockReturnValue(of({ items: [] }));
    TestBed.configureTestingModule({
      imports: [SavedHostComponent],
      providers: [
        { provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' } },
        { provide: UserPreferencesService, useValue: { timezone: () => null, calendar: () => null, digits: () => null } },
        { provide: RecordTimelineService, useValue: { timeline, history: vi.fn() } },
      ],
    });
    const fixture = TestBed.createComponent(SavedHostComponent);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-testid="record-timeline"]')).toBeNull();
    expect(timeline).not.toHaveBeenCalled();

    fixture.componentInstance.active.set('timeline');
    fixture.detectChanges();
    await vi.waitFor(() => {
      fixture.detectChanges();
      expect(el.querySelector('#demo-panel-timeline [data-testid="record-timeline"]')).not.toBeNull();
    });
    expect(timeline).toHaveBeenCalledWith('contact', 'rec-1', expect.objectContaining({ cursor: null }));
  });
});
