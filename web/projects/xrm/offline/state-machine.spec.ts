import { TestBed } from '@angular/core/testing';
import { describe, expect, it } from 'vitest';
import { MemoryBackend, OfflineStore } from './offline-store';
import { OFFLINE_STORE, OfflineQueueService } from './offline-queue.service';
import {
  OfflineStateModel, PROFILE_KEY, availableTransitions, currentState, queueTransition, storedStateModel,
} from './state-machine';

const model: OfflineStateModel = {
  name: 'Visit',
  state_field: 'status',
  initial_state: 'planned',
  transitions: [
    { from_state: 'planned', to_state: 'on_site', name: 'Arrive', guard_expression: null, language: 'v1',
      required_privilege: null, requires_approval: false },
    { from_state: 'on_site', to_state: 'done', name: 'Finish', guard_expression: 'notes != ""', language: 'v1',
      required_privilege: null, requires_approval: false },
    { from_state: 'on_site', to_state: 'escalated', name: 'Escalate', guard_expression: null, language: 'v1',
      required_privilege: null, requires_approval: true },
  ],
};

function setup() {
  TestBed.resetTestingModule();
  TestBed.configureTestingModule({
    providers: [{ provide: OFFLINE_STORE, useFactory: () => new OfflineStore(new MemoryBackend()) }],
  });
  return { queue: TestBed.inject(OfflineQueueService), store: TestBed.inject(OFFLINE_STORE) };
}

describe('offline state machine (B18-T13)', () => {
  it('offers only the moves from the current state, approvals only online', () => {
    expect(currentState(model, {})).toBe('planned');
    expect(availableTransitions(model, {}, false).map(t => t.to_state)).toEqual(['on_site']);
    const onSite = { status: 'on_site', notes: '' };
    expect(availableTransitions(model, onSite, false).map(t => t.to_state)).toEqual(['done']);
    expect(availableTransitions(model, onSite, true).map(t => t.to_state)).toEqual(['done', 'escalated']);
  });

  it('runs guards on the device when it can, and leaves them to the server when it cannot', () => {
    const onSite = { status: 'on_site', notes: '' };
    const evaluate = (expr: string, _lang: string, record: Record<string, unknown>) =>
      expr === 'notes != ""' ? record['notes'] !== '' : null;
    expect(availableTransitions(model, onSite, false, evaluate)).toEqual([]);
    expect(availableTransitions(model, { ...onSite, notes: 'Fixed' }, false, evaluate).map(t => t.to_state))
      .toEqual(['done']);
    expect(availableTransitions(model, onSite, false, () => null).map(t => t.to_state)).toEqual(['done']);
  });

  it('queues a move as an update of the state field and refuses one the model does not allow', async () => {
    const { queue } = setup();
    const op = await queueTransition(queue, model,
      { entity: 'visit', id: 'v1', rowVersion: 4, record: { status: 'planned' }, to: 'on_site' }, false);
    expect(op.kind).toBe('update');
    expect(op.changed).toEqual({ status: 'on_site' });
    expect(op.base_values).toEqual({ status: 'planned' });
    expect(op.base_row_version).toBe(4);
    await expect(queueTransition(queue, model,
      { entity: 'visit', id: 'v1', record: { status: 'planned' }, to: 'done' }, false))
      .rejects.toThrow('transition_not_allowed');
    expect(await queue.size()).toBe(1);
  });

  it('reads the state model from the stored profile', async () => {
    const { store } = setup();
    expect(await storedStateModel(store, 'visit')).toBeNull();
    await store.put('meta', PROFILE_KEY, {
      bundle_version: 'abc', max_days_offline: 7,
      entities: [{ entity: 'visit', state_model: model }, { entity: 'note', state_model: null }],
    });
    expect((await storedStateModel(store, 'visit'))?.state_field).toBe('status');
    expect(await storedStateModel(store, 'note')).toBeNull();
  });
});
