import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { ApiService, LangService } from '@attome/base';
import { EntityService } from '@attome/xrm/core/entity';
import { of, throwError } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { MyQueuesComponent } from './my-queues.component';
import { MyQueuesService, groupByQueue, missingStarters, type QueueItemRow } from './my-queues.service';

const item = (id: string, queue: string, priority: string, entered: string, status = 'waiting'): QueueItemRow => ({
  id, queue_ref: queue, record_entity: 'service_ticket', record_id: `t-${id}`, priority, status,
  assigned_ref: null, entered_at: entered,
});

describe('my queues (G4-T3)', () => {
  it('groups open items by queue, by priority then age, and leaves out empty queues', () => {
    const groups = groupByQueue(
      [{ id: 'q2', name: 'Billing' }, { id: 'q1', name: 'Access' }, { id: 'q3', name: 'Empty' }],
      [
        item('a', 'q2', 'low', '2026-10-01T00:00:00Z'),
        item('b', 'q2', 'critical', '2026-10-03T00:00:00Z'),
        item('c', 'q2', 'critical', '2026-10-02T00:00:00Z'),
        item('d', 'q1', 'medium', '2026-10-01T00:00:00Z'),
      ],
    );
    expect(groups.map(g => g.queue.name)).toEqual(['Access', 'Billing']);
    expect(groups[1].items.map(i => i.id)).toEqual(['c', 'b', 'a']);
  });

  it('adds only the starter queues not there yet, by either name', () => {
    const missing = missingStarters('hr', [{ id: '1', name: 'payroll' }, { id: '2', name: 'الإجازات' }]);
    expect(missing.map(s => s.en)).toEqual(['Onboarding', 'Employee Relations']);
    expect(missingStarters('it', []).length).toBe(4);
  });

  it('counts each bulk move, a refusal as failed', async () => {
    TestBed.configureTestingModule({
      providers: [
        { provide: ApiService, useValue: {} },
        { provide: EntityService, useValue: {} },
      ],
    });
    const service = TestBed.inject(MyQueuesService);
    const act = vi.fn((id: string) => (id === 'bad' ? throwError(() => new Error('409')) : of({})));
    const outcome = await new Promise(resolve => service.bulk(['a', 'bad', 'b'], act).subscribe(resolve));
    expect(outcome).toEqual({ done: 2, failed: 1 });
    expect(act).toHaveBeenCalledTimes(3);
  });

  function create() {
    const list = vi.fn((entity: string) => of(entity === 'queue'
      ? { data: [{ id: 'q1', data: { name: 'Service Desk' } }], meta: { total: 1 } }
      : { data: [{ id: 'i1', data: { queue_ref: 'q1', record_entity: 'service_ticket', record_id: 't1',
          priority: 'high', status: 'waiting', entered_at: '2026-10-27T08:00:00Z' } }], meta: { total: 1 } }));
    const createRecord = vi.fn(() => of({}));
    const post = vi.fn(() => of({ id: 'i1', queue_id: 'q1', status: 'picked', assigned_ref: 'u1' }));
    TestBed.configureTestingModule({
      imports: [MyQueuesComponent],
      providers: [
        provideRouter([]),
        { provide: ApiService, useValue: { post } },
        { provide: EntityService, useValue: { list, create: createRecord } },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, current: signal('ar'), errorText: () => 'error', intlLocale: () => 'ar-SA' },
        },
      ],
    });
    const fixture = TestBed.createComponent(MyQueuesComponent);
    fixture.detectChanges();
    return { fixture, cmp: fixture.componentInstance, el: fixture.nativeElement as HTMLElement, list, createRecord, post };
  }

  it('lists the items, picks the selected ones and creates a starter set in the reader\'s language', () => {
    const { fixture, cmp, el, post, createRecord: created } = create();
    expect(el.querySelector('[data-queue="q1"]')).not.toBeNull();
    expect(el.querySelector('[data-item="i1"]')).not.toBeNull();
    cmp.toggleGroup(cmp.groups()[0].items);
    fixture.detectChanges();
    expect(cmp.selectedCount()).toBe(1);
    cmp.pickSelected();
    expect(post).toHaveBeenCalledWith('/api/v1/queue-items/i1/pick', {});
    expect(cmp.outcome()).toEqual({ done: 1, failed: 0 });
    cmp.addStarters('it');
    // "Service Desk" exists already: three more, named in Arabic.
    expect(created).toHaveBeenCalledTimes(3);
    expect(created).toHaveBeenCalledWith('queue', { name: 'طلبات الصلاحيات' });
  });
});
