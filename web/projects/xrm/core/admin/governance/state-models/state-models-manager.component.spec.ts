import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiService, LangService } from '@attome/base';
import { ConfirmService } from '@attome/base/dialog';
import { signal } from '@angular/core';
import { AdminService, ChangesetContextService, StateModelsService } from '@attome/xrm/core/admin/data';
import type { StateModelDetail, StateTransition } from '@attome/xrm/core/admin/data';
import { StateModelsManagerComponent, splitActions } from './state-models-manager.component';

describe('StateModelsManagerComponent', () => {
  let fixture: ComponentFixture<StateModelsManagerComponent>;
  let svc: Record<string, ReturnType<typeof vi.fn>>;
  let admin: Record<string, ReturnType<typeof vi.fn>>;
  let confirm: { confirm: ReturnType<typeof vi.fn> };

  const transition = (over: Partial<StateTransition> = {}): StateTransition => ({
    id: 't1', model_ref: 'm1', from_state: 'new', to_state: 'open', name: 'Open',
    required_privilege: null, guard_expression: null, entry_actions: [], exit_actions: [],
    display_order: 0, row_version: 1, owner_layer: 'project',
    ...over,
  });

  const detail = (over: Partial<StateModelDetail> = {}): StateModelDetail => ({
    id: 'm1', entity_logicalname: 'ticket', name: 'Ticket lifecycle', state_field: 'status',
    initial_state: 'new', is_active: true, row_version: 3, owner_layer: 'project',
    created_at: '2026-09-01T00:00:00Z', updated_at: '2026-09-01T00:00:00Z',
    transitions: [transition()],
    ...over,
  });

  async function render() {
    await TestBed.configureTestingModule({
      imports: [StateModelsManagerComponent],
      providers: [
        provideRouter([]),
        { provide: StateModelsService, useValue: svc },
        // Z11-T14: the expression editor loads the entity's fields and the function list.
        { provide: ApiService, useValue: { get: () => of({}), post: vi.fn() } },
        { provide: AdminService, useValue: admin },
        { provide: ConfirmService, useValue: confirm },
        // The owner-layer badge (D-785) reads the editing layer from here.
        { provide: ChangesetContextService, useValue: { editingLayer: signal(null) } },
        { provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' } },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(StateModelsManagerComponent);
    fixture.detectChanges();
  }

  const el = () => fixture.nativeElement as HTMLElement;

  beforeEach(() => {
    TestBed.resetTestingModule();
    svc = {
      listModels: vi.fn().mockReturnValue(of([{
        id: 'm1', entity_logicalname: 'ticket', name: 'Ticket lifecycle', state_field: 'status',
        initial_state: 'new', is_active: true, row_version: 3, owner_layer: 'project',
      }])),
      getModel: vi.fn().mockReturnValue(of(detail())),
      createModel: vi.fn().mockReturnValue(of(detail())),
      updateModel: vi.fn().mockReturnValue(of(detail({ row_version: 4 }))),
      deleteModel: vi.fn().mockReturnValue(of(undefined)),
      createTransition: vi.fn().mockReturnValue(of(transition({ id: 't2', from_state: 'open', to_state: 'closed', name: 'Close' }))),
      updateTransition: vi.fn().mockReturnValue(of(transition({ name: 'Start', row_version: 2 }))),
      deleteTransition: vi.fn().mockReturnValue(of(undefined)),
    };
    admin = {
      listEntities: vi.fn().mockReturnValue(of([
        { id: 'e1', logicalname: 'ticket', name: 'Ticket', attribute_count: 3, is_active: true, is_append_only: false },
      ])),
      getEntity: vi.fn().mockReturnValue(of({
        id: 'e1', logicalname: 'ticket', name: 'Ticket',
        attributes: [
          { id: 'a1', logicalname: 'status', name: 'Status', field_type: 'choice', options: { choices: ['new', 'open', 'closed'], multi: false } },
          { id: 'a2', logicalname: 'title', name: 'Title', field_type: 'text', options: null },
        ],
      })),
    };
    confirm = { confirm: vi.fn().mockResolvedValue(true) };
  });

  it('lists the models', async () => {
    await render();
    expect(el().textContent).toContain('Ticket lifecycle');
  });

  it('offers only the entity\'s Choice fields and their options as states', async () => {
    await render();
    const c = fixture.componentInstance;
    c.startCreate();
    c.chooseEntity('ticket');
    expect(admin['getEntity']).toHaveBeenCalledWith('e1');
    expect(c.choiceFields().map(f => f.logicalname)).toEqual(['status']);
    c.chooseStateField('status');
    expect(c.stateOptions()).toEqual(['new', 'open', 'closed']);
    expect(c.draft().initial_state).toBe('new');
  });

  it('creates a model and switches to editing it', async () => {
    await render();
    const c = fixture.componentInstance;
    c.startCreate();
    c.chooseEntity('ticket');
    c.chooseStateField('status');
    c.setDraft('name', ' Ticket lifecycle ');
    expect(c.canCreate()).toBe(true);
    c.create();
    expect(svc['createModel']).toHaveBeenCalledWith({
      entity_logicalname: 'ticket', name: 'Ticket lifecycle', state_field: 'status', initial_state: 'new', is_active: true,
    });
    expect(c.mode()).toBe('edit');
    expect(c.detail()?.id).toBe('m1');
  });

  it('saves the model with the row_version it read', async () => {
    await render();
    const c = fixture.componentInstance;
    c.open('m1');
    c.setDraft('name', 'Renamed');
    c.saveModel();
    expect(svc['updateModel']).toHaveBeenCalledWith('m1', expect.objectContaining({ name: 'Renamed', row_version: 3 }));
    expect(c.detail()?.row_version).toBe(4);
  });

  it('shows a conflict banner with a reload action on a stale row_version', async () => {
    svc['updateModel'].mockReturnValue(throwError(() => ({ status: 409, kind: 'version_conflict', message: 'stale' })));
    await render();
    const c = fixture.componentInstance;
    c.open('m1');
    c.saveModel();
    fixture.detectChanges();
    expect(c.conflict()).toBe(true);
    expect(el().textContent).toContain('governance.stateModels.conflict');
    c.reload();
    expect(svc['getModel']).toHaveBeenCalledTimes(2);
    expect(c.conflict()).toBe(false);
  });

  it('shows the server message for an ordinary 409 (duplicate edge)', async () => {
    svc['createTransition'].mockReturnValue(throwError(() => ({ status: 409, kind: 'conflict', message: 'edge exists' })));
    await render();
    const c = fixture.componentInstance;
    c.open('m1');
    c.setNewTransition('from_state', 'new');
    c.setNewTransition('to_state', 'open');
    c.setNewTransition('name', 'Open again');
    c.addTransition();
    expect(c.conflict()).toBe(false);
    expect(c.actionError()).toBe('edge exists');
  });

  it('adds a transition, splitting its action lists', async () => {
    await render();
    const c = fixture.componentInstance;
    c.open('m1');
    c.setNewTransition('from_state', 'open');
    c.setNewTransition('to_state', 'closed');
    c.setNewTransition('name', 'Close');
    c.setNewTransition('entry_actions', 'notify, , stamp_closed ');
    expect(c.canAddTransition()).toBe(true);
    c.addTransition();
    expect(svc['createTransition']).toHaveBeenCalledWith('m1', expect.objectContaining({
      from_state: 'open', to_state: 'closed', name: 'Close',
      entry_actions: ['notify', 'stamp_closed'], exit_actions: [], required_privilege: null,
    }));
    expect(c.detail()?.transitions.length).toBe(2);
  });

  it('refuses a self-transition', async () => {
    await render();
    const c = fixture.componentInstance;
    c.open('m1');
    c.setNewTransition('from_state', 'open');
    c.setNewTransition('to_state', 'open');
    c.setNewTransition('name', 'Loop');
    expect(c.canAddTransition()).toBe(false);
  });

  it('saves an edited transition with its row_version', async () => {
    await render();
    const c = fixture.componentInstance;
    c.open('m1');
    const t = c.detail()!.transitions[0];
    expect(c.isTransitionDirty(t)).toBe(false);
    c.setTransitionDraft('t1', 'name', 'Start');
    expect(c.isTransitionDirty(t)).toBe(true);
    c.saveTransition(t);
    expect(svc['updateTransition']).toHaveBeenCalledWith('m1', 't1', expect.objectContaining({ name: 'Start', row_version: 1 }));
    expect(c.detail()?.transitions[0].name).toBe('Start');
  });

  it('moves a transition edge in place, sending from and to', async () => {
    svc['updateTransition'].mockReturnValue(of(transition({ to_state: 'closed', row_version: 2 })));
    await render();
    const c = fixture.componentInstance;
    c.open('m1');
    fixture.detectChanges();
    const t = c.detail()!.transitions[0];
    const selects = el().querySelectorAll('[data-testid="sm-transition-to"]');
    expect(selects.length).toBe(1);
    c.setTransitionDraft('t1', 'to_state', 'closed');
    expect(c.isTransitionDirty(t)).toBe(true);
    expect(c.canSaveTransition(t)).toBe(true);
    c.saveTransition(t);
    expect(svc['updateTransition']).toHaveBeenCalledWith('m1', 't1', expect.objectContaining({
      from_state: 'new', to_state: 'closed', row_version: 1,
    }));
    expect(c.detail()?.transitions[0].to_state).toBe('closed');
  });

  it('will not save an edge moved onto itself', async () => {
    await render();
    const c = fixture.componentInstance;
    c.open('m1');
    const t = c.detail()!.transitions[0];
    c.setTransitionDraft('t1', 'to_state', 'new');
    expect(c.canSaveTransition(t)).toBe(false);
  });

  it('keeps a state the field no longer offers selectable on an old edge', async () => {
    await render();
    const c = fixture.componentInstance;
    c.open('m1');
    expect(c.optionsFor('retired')).toEqual(['retired', 'new', 'open', 'closed']);
    expect(c.optionsFor('open')).toEqual(['new', 'open', 'closed']);
  });

  it('deletes a transition only after confirmation', async () => {
    await render();
    const c = fixture.componentInstance;
    c.open('m1');
    confirm.confirm.mockResolvedValueOnce(false);
    await c.deleteTransition(c.detail()!.transitions[0]);
    expect(svc['deleteTransition']).not.toHaveBeenCalled();
    await c.deleteTransition(c.detail()!.transitions[0]);
    expect(svc['deleteTransition']).toHaveBeenCalledWith('m1', 't1');
    expect(c.detail()?.transitions.length).toBe(0);
  });

  it('deletes the model after confirmation and closes the editor', async () => {
    await render();
    const c = fixture.componentInstance;
    c.open('m1');
    await c.deleteModel();
    expect(svc['deleteModel']).toHaveBeenCalledWith('m1');
    expect(c.mode()).toBe('none');
    expect(c.detail()).toBeNull();
  });

  it('splits comma-separated actions', () => {
    expect(splitActions(' a, b ,,c ')).toEqual(['a', 'b', 'c']);
    expect(splitActions('')).toEqual([]);
  });
});
