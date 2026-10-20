import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { ApiService, ATTOME_CONFIG, LangService, provideAttomeI18n } from '@attome/base';
import { provideXrmI18n } from '@attome/xrm/core/i18n';
import { xrmEn } from '@attome/xrm/core/i18n-en';
import { DialogService } from '@attome/base/dialog';
import { EntityRecord } from '@attome/xrm';
import { EntityRecordResponse, EntityService } from '@attome/xrm/core/entity';
import { Observable, of, throwError } from 'rxjs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { PageEditorComponent, pageDraftStorageKey } from './page-editor.component';

/**
 * Page Editor save paths against a real `DashboardService` over mocked
 * `EntityService`/`ApiService`:
 *
 * - R-02 regression: an inspector edit to `view_id` reaches the PATCH.
 * - Dashboard 10/10 Phase 1.4 — the editor never loses work: structural
 *   operations merge into the draft instead of reloading, a delete is a draft
 *   edit, a 409/412 mid-save keeps everything unsaved dirty, and the draft is
 *   mirrored for recovery.
 *
 * Most tests never call `fixture.detectChanges()` — the logic under test is
 * pure component state, and every mocked call resolves synchronously, so
 * `ngOnInit()` completes the whole load in one call.
 */

const PAGE_ID = 'page-1';
const DASHBOARD_ID = 'dashboard-1';
const SECTION_ID = 'section-1';
const WIDGET_A = 'widget-a';
const WIDGET_B = 'widget-b';

function mockPage(data: Record<string, unknown> = { name: 'Test Page', dashboard_id: DASHBOARD_ID }): EntityRecordResponse {
  return { id: PAGE_ID, entity_id: 'dashboard_page', data, row_version: 0, created_at: null, updated_at: null };
}

function widget(id: string, name: string, rowVersion = 0): EntityRecord {
  return {
    id,
    entity_id: 'dashboard_widget',
    data: { section_id: SECTION_ID, widget_type: 'table', name, query_id: null, view_id: null, sequence: 0 },
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    row_version: rowVersion,
  };
}

function draftTree(widgets: EntityRecord[]) {
  return {
    dashboard: { id: DASHBOARD_ID, row_version: 0, data: {} },
    pages: [{ id: PAGE_ID, row_version: 0, data: { dashboard_id: DASHBOARD_ID } }],
    sections: [{ id: SECTION_ID, row_version: 0, data: { page_id: PAGE_ID, parent_section_id: null } }],
    widgets: widgets.map(w => ({ id: w.id, row_version: w.row_version, data: w.data })),
    pages_needing_root_section: [],
  };
}

interface SetupOptions {
  widgets?: EntityRecord[];
  page?: EntityRecordResponse;
  updateImpl?: (entityName: string, id: string, patch: Record<string, unknown>, rowVersion?: number) => Observable<EntityRecordResponse>;
  serverWidget?: (id: string) => EntityRecordResponse;
  render?: boolean;
}

function setup(options: SetupOptions = {}) {
  const widgets = options.widgets ?? [widget(WIDGET_A, 'Widget A')];

  const defaultUpdate = (entityName: string, id: string, patch: Record<string, unknown>, rowVersion?: number) => {
    const base = widgets.find(w => w.id === id);
    return of({
      id,
      entity_id: entityName,
      data: { ...(base?.data ?? {}), ...patch },
      row_version: (rowVersion ?? 0) + 1,
      created_at: null,
      updated_at: null,
    } as EntityRecordResponse);
  };
  const updateSpy = vi.fn(options.updateImpl ?? defaultUpdate);
  const createSpy = vi.fn((entityName: string, data: Record<string, unknown>) => of({
    id: WIDGET_B, entity_id: entityName, data, row_version: 0, created_at: null, updated_at: null,
  } as EntityRecordResponse));
  const deleteSpy = vi.fn(() => of(undefined));
  const getSpy = vi.fn((entityName: string, id: string) => {
    if (entityName === 'dashboard_page') return of(options.page ?? mockPage());
    return of(options.serverWidget?.(id) ?? ({
      id, entity_id: entityName, data: { section_id: SECTION_ID, widget_type: 'table', name: 'Copy' },
      row_version: 0, created_at: null, updated_at: null,
    } as EntityRecordResponse));
  });

  const entityService = {
    get: getSpy,
    list: vi.fn(() => of({ data: [], meta: { total: 0, limit: 100, offset: 0 } })),
    create: createSpy,
    delete: deleteSpy,
    update: updateSpy,
    getSchema: vi.fn(() => of({ fields: [] })),
  };

  const apiGetSpy = vi.fn((path: string) => {
    if (path.endsWith('/tree')) return of(draftTree(widgets));
    return of([]); // /api/v1/attome-dashboard/widget-types
  });
  const apiService = {
    get: apiGetSpy,
    getAllPages: vi.fn(() => of([])),
    post: vi.fn((path: string) => of(path.endsWith('/widget/duplicate') ? { id: WIDGET_B } : {})),
    patch: vi.fn(() => of({})),
    delete: vi.fn(() => of(undefined)),
  };

  const dialogService = { confirm: vi.fn(() => Promise.resolve(true)) };

  TestBed.configureTestingModule({
    imports: [PageEditorComponent],
    providers: [
      provideRouter([]),
      { provide: EntityService, useValue: entityService },
      { provide: ApiService, useValue: apiService },
      { provide: DialogService, useValue: dialogService },
      ...(options.render
        ? [{ provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } }, provideAttomeI18n(), provideXrmI18n(xrmEn)]
        : [{ provide: LangService, useValue: { translate: (key: string) => key } }]),
    ],
  });

  const fixture: ComponentFixture<PageEditorComponent> = TestBed.createComponent(PageEditorComponent);
  fixture.componentRef.setInput('pageId', PAGE_ID);
  const component = fixture.componentInstance;
  if (options.render) fixture.detectChanges();
  else component.ngOnInit();

  const treeCalls = () => apiGetSpy.mock.calls.filter(([path]) => String(path).endsWith('/tree')).length;
  return { fixture, component, updateSpy, createSpy, deleteSpy, getSpy, treeCalls };
}

afterEach(() => sessionStorage.clear());

describe('PageEditorComponent — view_id save path (R-02)', () => {
  it('saveChanges() PATCHes a widget field edited through onWidgetField, including view_id', () => {
    const { component, updateSpy } = setup();

    component.selectWidget(WIDGET_A);
    component.onWidgetField('view_id', 'view-abc');
    component.saveChanges();

    expect(updateSpy).toHaveBeenCalledWith(
      'dashboard_widget',
      WIDGET_A,
      expect.objectContaining({ view_id: 'view-abc' }),
      0,
    );
  });

  it('does not PATCH anything when no field actually changed', () => {
    const { component, updateSpy } = setup();

    component.selectWidget(WIDGET_A);
    component.saveChanges();

    expect(updateSpy).not.toHaveBeenCalled();
  });
});

describe('PageEditorComponent — loading (D-520/D-527)', () => {
  it('loads the page through its dashboard tree with one call', () => {
    const { component, treeCalls } = setup();

    expect(treeCalls()).toBe(1);
    expect(component.rootSectionId()).toBe(SECTION_ID);
    expect(component.widgets().map(w => w.id)).toEqual([WIDGET_A]);
  });

  it('refuses to edit a page no dashboard owns', () => {
    const { component, treeCalls } = setup({ page: mockPage({ name: 'Orphan' }) });

    expect(component.loadError()).toBe('pageEditor.noDashboard');
    expect(treeCalls()).toBe(0);
  });
});

describe('PageEditorComponent — the editor never loses work (Phase 1.4)', () => {
  it("move A then add B keeps A's move saveable, without reloading", () => {
    const { component, updateSpy, createSpy, deleteSpy, treeCalls } = setup();

    component.selectWidget(WIDGET_A);
    component.onWidgetField('grid_col', 3);
    component.onAddWidget('table');

    expect(createSpy).toHaveBeenCalledOnce();
    expect(component.widgets().map(w => w.id)).toEqual([WIDGET_A, WIDGET_B]);
    expect(component.dirty()).toBe(true);
    expect(treeCalls()).toBe(1);

    component.saveChanges();
    expect(updateSpy).toHaveBeenCalledWith('dashboard_widget', WIDGET_A, expect.objectContaining({ grid_col: 3 }), 0);
    expect(deleteSpy).not.toHaveBeenCalled();
  });

  it('duplicate merges the new widget instead of reloading', () => {
    const { component, getSpy, treeCalls } = setup();

    component.selectWidget(WIDGET_A);
    component.onWidgetField('name', 'Edited');
    component.onDuplicateWidgetId(WIDGET_A);

    expect(getSpy).toHaveBeenCalledWith('dashboard_widget', WIDGET_B);
    expect(component.widgets().map(w => w.id)).toEqual([WIDGET_A, WIDGET_B]);
    expect(component.widgets()[0].data['name']).toBe('Edited');
    expect(treeCalls()).toBe(1);
  });

  it('delete with a dirty sibling keeps the sibling dirty, and Save deletes', async () => {
    const { component, updateSpy, deleteSpy } = setup({
      widgets: [widget(WIDGET_A, 'Widget A'), widget(WIDGET_B, 'Widget B')],
    });

    component.selectWidget(WIDGET_A);
    component.onWidgetField('name', 'Edited');
    await component.onDeleteWidgetId(WIDGET_B);

    expect(deleteSpy).not.toHaveBeenCalled();
    expect(component.dirty()).toBe(true);
    expect(component.widgets().map(w => w.id)).toEqual([WIDGET_A]);
    expect(component.widgets()[0].data['name']).toBe('Edited');

    component.saveChanges();
    expect(updateSpy).toHaveBeenCalledWith('dashboard_widget', WIDGET_A, expect.objectContaining({ name: 'Edited' }), 0);
    expect(deleteSpy).toHaveBeenCalledWith('dashboard_widget', WIDGET_B);
    expect(component.dirty()).toBe(false);
  });

  it('undoing a delete brings the widget back without any server call', async () => {
    const { component, deleteSpy } = setup({
      widgets: [widget(WIDGET_A, 'Widget A'), widget(WIDGET_B, 'Widget B')],
    });

    await component.onDeleteWidgetId(WIDGET_B);
    component.undo();

    expect(component.widgets().map(w => w.id)).toEqual([WIDGET_A, WIDGET_B]);
    component.saveChanges();
    expect(deleteSpy).not.toHaveBeenCalled();
  });

  it('a 412 mid-save stops the queue, marks the widget, and keeps the rest dirty', () => {
    let failB = true;
    const { component, updateSpy } = setup({
      widgets: [widget(WIDGET_A, 'Widget A'), widget(WIDGET_B, 'Widget B')],
      updateImpl: (entityName, id, patch, rowVersion) => {
        if (id === WIDGET_B && failB) return throwError(() => ({ kind: 'conflict', status: 412, message: 'stale' }));
        return of({
          id, entity_id: entityName, data: patch, row_version: (rowVersion ?? 0) + 1, created_at: null, updated_at: null,
        } as EntityRecordResponse);
      },
    });

    component.selectWidget(WIDGET_A);
    component.onWidgetField('name', 'A edited');
    component.selectWidget(WIDGET_B);
    component.onWidgetField('name', 'B edited');
    component.saveChanges();

    expect(component.conflictedWidgetIds().has(WIDGET_B)).toBe(true);
    expect(component.dirty()).toBe(true);
    expect(component.error()).toBe('pageEditor.conflict');
    expect(component.widgets().find(w => w.id === WIDGET_B)!.data['name']).toBe('B edited');

    // A was saved; retrying sends only B.
    updateSpy.mockClear();
    failB = false;
    component.saveChanges();
    expect(updateSpy).toHaveBeenCalledOnce();
    expect(updateSpy).toHaveBeenCalledWith('dashboard_widget', WIDGET_B, expect.objectContaining({ name: 'B edited' }), 0);
    expect(component.dirty()).toBe(false);
  });

  it('"Take theirs" replaces the conflicted widget with the server version', () => {
    const { component } = setup({
      updateImpl: () => throwError(() => ({ kind: 'conflict', status: 409, message: 'stale' })),
      serverWidget: id => ({
        id, entity_id: 'dashboard_widget', data: { section_id: SECTION_ID, widget_type: 'table', name: 'Theirs' },
        row_version: 5, created_at: null, updated_at: null,
      }),
    });

    component.selectWidget(WIDGET_A);
    component.onWidgetField('name', 'Mine');
    component.saveChanges();
    component.takeTheirs(WIDGET_A);

    const a = component.widgets().find(w => w.id === WIDGET_A)!;
    expect(a.data['name']).toBe('Theirs');
    expect(a.row_version).toBe(5);
    expect(component.conflictedWidgetIds().size).toBe(0);
  });

  it('"Keep mine" re-applies the local edit on the server version and saves again', () => {
    let conflict = true;
    const { component, updateSpy } = setup({
      updateImpl: (entityName, id, patch, rowVersion) => {
        if (conflict) { conflict = false; return throwError(() => ({ kind: 'conflict', status: 412, message: 'stale' })); }
        return of({ id, entity_id: entityName, data: patch, row_version: (rowVersion ?? 0) + 1, created_at: null, updated_at: null } as EntityRecordResponse);
      },
      serverWidget: id => ({
        id, entity_id: 'dashboard_widget', data: { section_id: SECTION_ID, widget_type: 'table', name: 'Theirs', grid_col: 2 },
        row_version: 5, created_at: null, updated_at: null,
      }),
    });

    component.selectWidget(WIDGET_A);
    component.onWidgetField('name', 'Mine');
    component.saveChanges();
    component.keepMine(WIDGET_A);

    expect(updateSpy).toHaveBeenLastCalledWith('dashboard_widget', WIDGET_A, expect.objectContaining({ name: 'Mine' }), 5);
    const a = component.widgets().find(w => w.id === WIDGET_A)!;
    expect(a.data['grid_col']).toBe(2);
    expect(component.dirty()).toBe(false);
  });

  it('mirrors the draft to sessionStorage and clears it on cancel', () => {
    const { component } = setup();

    component.selectWidget(WIDGET_A);
    component.onWidgetField('name', 'Edited');
    const stored = JSON.parse(sessionStorage.getItem(pageDraftStorageKey(PAGE_ID))!);
    expect(stored.widgets[WIDGET_A]).toEqual({ name: 'Edited' });

    component.cancelChanges();
    expect(sessionStorage.getItem(pageDraftStorageKey(PAGE_ID))).toBeNull();
    expect(component.widgets()[0].data['name']).toBe('Widget A');
  });

  it('recovery restores a stored draft after reload', () => {
    sessionStorage.setItem(pageDraftStorageKey(PAGE_ID), JSON.stringify({
      version: 1, page: { name: 'Recovered Page' }, widgets: { [WIDGET_A]: { name: 'Recovered' } }, deleted: [], views: {},
    }));
    const { component, updateSpy } = setup();

    expect(component.recoverableDraft()).not.toBeNull();
    component.restoreRecoveredDraft();

    expect(component.widgets()[0].data['name']).toBe('Recovered');
    expect(component.page()!.data['name']).toBe('Recovered Page');
    expect(component.dirty()).toBe(true);
    component.saveChanges();
    expect(updateSpy).toHaveBeenCalledWith('dashboard_widget', WIDGET_A, expect.objectContaining({ name: 'Recovered' }), 0);
  });

  it('reports unsaved changes to the leave guard while dirty', () => {
    const { component } = setup();

    expect(component.hasUnsavedChanges()).toBe(false);
    component.selectWidget(WIDGET_A);
    component.onWidgetField('name', 'Edited');
    expect(component.hasUnsavedChanges()).toBe(true);
  });

  it('an error banner keeps the canvas on screen', () => {
    const { fixture, component } = setup({ render: true });

    component.error.set('Something failed');
    fixture.detectChanges();

    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('.xpe-canvas-grid')).not.toBeNull();
    expect(el.textContent).toContain('Something failed');
  });
});

describe('PageEditorComponent — Dashboard 10/10 Phase 5 (keyboard, multi-select, copy/paste)', () => {
  it('a plain selectWidget call replaces the selection with just that widget', () => {
    const { component } = setup({ widgets: [widget(WIDGET_A, 'A'), widget(WIDGET_B, 'B')] });

    component.selectWidget(WIDGET_A);
    component.selectWidget(WIDGET_B);

    expect(component.selectedWidgetIds()).toEqual(new Set([WIDGET_B]));
  });

  it('Ctrl/Cmd+Click toggles a widget in the selection without clearing it', () => {
    const { component } = setup({ widgets: [widget(WIDGET_A, 'A'), widget(WIDGET_B, 'B')] });

    component.selectWidget(WIDGET_A);
    component.selectWidget(WIDGET_B, new MouseEvent('click', { ctrlKey: true }));
    expect(component.selectedWidgetIds()).toEqual(new Set([WIDGET_A, WIDGET_B]));

    component.selectWidget(WIDGET_A, new MouseEvent('click', { ctrlKey: true }));
    expect(component.selectedWidgetIds()).toEqual(new Set([WIDGET_B]));
  });

  it('Shift+Click selects the contiguous range in canvas order', () => {
    const widgetC = widget('widget-c', 'C');
    const { component } = setup({ widgets: [widget(WIDGET_A, 'A'), widget(WIDGET_B, 'B'), widgetC] });

    component.selectWidget(WIDGET_A);
    component.selectWidget('widget-c', new MouseEvent('click', { shiftKey: true }));

    expect(component.selectedWidgetIds()).toEqual(new Set([WIDGET_A, WIDGET_B, 'widget-c']));
  });

  it('toggleWidgetSelected adds/removes a widget independent of click modifiers (the tile checkbox)', () => {
    const { component } = setup({ widgets: [widget(WIDGET_A, 'A'), widget(WIDGET_B, 'B')] });

    component.toggleWidgetSelected(WIDGET_A, true);
    component.toggleWidgetSelected(WIDGET_B, true);
    expect(component.selectedWidgetIds()).toEqual(new Set([WIDGET_A, WIDGET_B]));

    component.toggleWidgetSelected(WIDGET_A, false);
    expect(component.selectedWidgetIds()).toEqual(new Set([WIDGET_B]));
  });

  it('onDeleteSelectedWidget deletes every selected widget in one undoable step, one confirm dialog', async () => {
    const { component, deleteSpy } = setup({ widgets: [widget(WIDGET_A, 'A'), widget(WIDGET_B, 'B')] });
    component.selectWidget(WIDGET_A);
    component.selectWidget(WIDGET_B, new MouseEvent('click', { ctrlKey: true }));

    await component.onDeleteSelectedWidget();

    expect(component.widgets()).toEqual([]);
    expect(component.selectedWidgetIds().size).toBe(0);
    expect(component.canUndo()).toBe(true);

    component.saveChanges();
    expect(deleteSpy).toHaveBeenCalledWith('dashboard_widget', WIDGET_A);
    expect(deleteSpy).toHaveBeenCalledWith('dashboard_widget', WIDGET_B);
  });

  it('ArrowRight moves the focused widget one grid unit; Shift+ArrowRight grows its width instead', () => {
    const { component } = setup({ widgets: [widget(WIDGET_A, 'A')] });

    component.onTileKeydown(new KeyboardEvent('keydown', { key: 'ArrowRight' }), component.widgets()[0]);
    expect(component.widgets()[0].data['grid_col']).toBe(1);

    component.onTileKeydown(
      new KeyboardEvent('keydown', { key: 'ArrowRight', shiftKey: true }),
      component.widgets()[0],
    );
    expect(component.widgets()[0].data['grid_col_span']).toBe(2);
  });

  it('ArrowLeft/ArrowUp never move a widget past the grid origin', () => {
    const { component } = setup({ widgets: [widget(WIDGET_A, 'A')] });

    component.onTileKeydown(new KeyboardEvent('keydown', { key: 'ArrowLeft' }), component.widgets()[0]);
    component.onTileKeydown(new KeyboardEvent('keydown', { key: 'ArrowUp' }), component.widgets()[0]);

    expect(component.widgets()[0].data['grid_col'] ?? 0).toBe(0);
    expect(component.widgets()[0].data['grid_row'] ?? 0).toBe(0);
  });

  it('keyboard move/resize is a no-op in preview mode', () => {
    const { component } = setup({ widgets: [widget(WIDGET_A, 'A')] });
    component.togglePreview();

    component.onTileKeydown(new KeyboardEvent('keydown', { key: 'ArrowRight' }), component.widgets()[0]);

    expect(component.widgets()[0].data['grid_col']).toBeUndefined();
  });

  it('copies the selection and pastes new widgets through duplicateWidget, selecting the pasted set', () => {
    const { component, getSpy } = setup({ widgets: [widget(WIDGET_A, 'A')] });
    component.selectWidget(WIDGET_A);

    component.onCopySelectedWidgets();
    component.onPasteClipboardWidgets();

    expect(getSpy).toHaveBeenCalledWith('dashboard_widget', WIDGET_B);
    expect(component.widgets().map(w => w.id)).toEqual([WIDGET_A, WIDGET_B]);
    expect(component.selectedWidgetIds()).toEqual(new Set([WIDGET_B]));
  });

  it('pasting with nothing copied is a no-op', () => {
    const { component } = setup({ widgets: [widget(WIDGET_A, 'A')] });

    component.onPasteClipboardWidgets();

    expect(component.widgets().map(w => w.id)).toEqual([WIDGET_A]);
  });

  it('Ctrl/Cmd+C then Ctrl/Cmd+V on a tile copy/pastes the current selection', () => {
    const { component, getSpy } = setup({ widgets: [widget(WIDGET_A, 'A')] });
    component.selectWidget(WIDGET_A);
    const w = component.widgets()[0];

    component.onTileKeydown(new KeyboardEvent('keydown', { key: 'c', ctrlKey: true }), w);
    component.onTileKeydown(new KeyboardEvent('keydown', { key: 'v', ctrlKey: true }), w);

    expect(getSpy).toHaveBeenCalledWith('dashboard_widget', WIDGET_B);
    expect(component.widgets().map(x => x.id)).toEqual([WIDGET_A, WIDGET_B]);
  });
});
