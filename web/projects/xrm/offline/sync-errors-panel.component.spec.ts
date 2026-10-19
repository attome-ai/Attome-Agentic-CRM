import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { LangService } from '@attome/base';
import { describe, expect, it } from 'vitest';
import { SyncErrorsPanelComponent, errorLink } from './sync-errors-panel.component';
import { SyncProblem } from './sync.service';

const rejected: SyncProblem = {
  op: { seq: 1, client_op_id: 'op-1', kind: 'update', entity: 'visit', id: 'v1', changed: { amount: -1 } },
  result: {
    client_op_id: 'op-1', status: 'rejected', id: 'v1', code: 'validation',
    message: 'amount: must be positive', link: '/xrm/entity/visit/form?id=v1',
  },
};
const draft: SyncProblem = {
  op: { seq: 2, client_op_id: 'op-2', kind: 'create', entity: 'visit', id: 'v2', changed: { subject: '' } },
  result: { client_op_id: 'op-2', status: 'rejected', id: 'v2', code: 'validation', message: 'subject: required' },
};
const conflict: SyncProblem = {
  op: { seq: 3, client_op_id: 'op-3', kind: 'update', entity: 'visit', id: 'v3' },
  result: { client_op_id: 'op-3', status: 'conflict', id: 'v3', server_values: {} },
};

describe('SyncErrorsPanelComponent (B18-T9)', () => {
  it('error link opens record', () => {
    expect(errorLink(rejected)).toEqual({ path: '/xrm/entity/visit/form', query: { id: 'v1' } });
    expect(errorLink(draft)).toEqual({ path: '/xrm/entity/visit/form', query: { id: 'v2', offline: 'draft' } });

    TestBed.configureTestingModule({
      imports: [SyncErrorsPanelComponent],
      providers: [provideRouter([]), { provide: LangService, useValue: { translate: (key: string) => key } }],
    });
    const fixture = TestBed.createComponent(SyncErrorsPanelComponent);
    fixture.componentRef.setInput('problems', [rejected, conflict, draft]);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    const items = el.querySelectorAll('[data-testid="offline-sync-error"]');
    expect(items.length).toBe(2);
    expect(items[0].textContent).toContain('amount: must be positive');
    const links = el.querySelectorAll<HTMLAnchorElement>('[data-testid="offline-sync-error-link"]');
    expect(links[0].getAttribute('href')).toBe('/xrm/entity/visit/form?id=v1');
    expect(links[1].getAttribute('href')).toBe('/xrm/entity/visit/form?id=v2&offline=draft');
  });
});
