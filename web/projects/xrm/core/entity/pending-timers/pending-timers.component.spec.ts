import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { PendingTimer, PendingTimersComponent } from './pending-timers.component';

const TIMER: PendingTimer = {
  id: 't1', kind: 'service.escalation', target_entity: 'case', target_id: 'r1',
  run_id: null, due_at: '2026-10-20T08:00:00Z', created_at: '2026-10-19T08:00:00Z',
};

describe('PendingTimersComponent (M10-T4)', () => {
  function setUp(items: PendingTimer[], inputs: { entity?: string; recordId?: string }) {
    const get = vi.fn(() => of({ items, total: items.length, page: 1, page_size: 200 }));
    const names: Record<string, string> = { 'pendingTimers.kinds.service.escalation': 'Escalation' };
    TestBed.configureTestingModule({
      imports: [PendingTimersComponent],
      providers: [
        { provide: ApiService, useValue: { get } },
        { provide: LangService, useValue: { translate: (k: string) => names[k] ?? k, current: signal('en'), intlLocale: signal('en-US') } },
      ],
    });
    const fixture = TestBed.createComponent(PendingTimersComponent);
    if (inputs.entity) fixture.componentRef.setInput('entity', inputs.entity);
    if (inputs.recordId) fixture.componentRef.setInput('recordId', inputs.recordId);
    fixture.detectChanges();
    return { root: fixture.nativeElement as HTMLElement, get, timers: fixture.componentInstance };
  }

  it('lists a record\'s pending timers by what and when', () => {
    const { root, get } = setUp([TIMER], { entity: 'case', recordId: 'r1' });
    expect(get).toHaveBeenCalledWith('/api/v1/case/r1/timers', undefined);
    const row = root.querySelector('[data-pending-timer="t1"]') as HTMLElement;
    expect(row.textContent).toContain('Escalation');
  });

  it('shows nothing on a record without timers', () => {
    const { root } = setUp([], { entity: 'case', recordId: 'r1' });
    expect(root.querySelector('[data-pending-timers]')).toBeNull();
  });

  it('lists every pending timer, with its record, for administrators', () => {
    const { root, get } = setUp([TIMER], {});
    expect(get).toHaveBeenCalledWith('/api/v1/admin/timers', { page_size: '200' });
    expect(root.querySelector('[data-pending-timer="t1"]')?.textContent).toContain('case');
  });

  it('names an unknown kind by its code', () => {
    const { timers } = setUp([], {});
    expect(timers.kindLabel('flow.wait')).toBe('flow.wait');
  });
});
