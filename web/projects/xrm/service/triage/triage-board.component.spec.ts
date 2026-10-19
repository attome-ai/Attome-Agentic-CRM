import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { ServiceAdminService, TriageItem, triageColumns } from '../services/service-admin.service';
import { TriageBoardComponent } from './triage-board.component';

function item(id: string, status: string, created_at: string): TriageItem {
  return {
    id,
    title: `Request ${id}`,
    reference: `REQ-2026-0000${id}`,
    status,
    priority: 'high',
    category: null,
    created_at,
    row_version: 3,
  };
}

describe('triageColumns', () => {
  it('groups requests by status, newest first, with every column present', () => {
    const columns = triageColumns([
      item('1', 'new', '2026-10-19T08:00:00Z'),
      item('2', 'new', '2026-10-19T09:00:00Z'),
      item('3', 'rejected', '2026-10-18T09:00:00Z'),
    ]);
    expect(columns['new'].map(i => i.id)).toEqual(['2', '1']);
    expect(columns['triaged']).toEqual([]);
    expect(columns['converted']).toEqual([]);
    expect(columns['rejected'].map(i => i.id)).toEqual(['3']);
  });
});

describe('TriageBoardComponent', () => {
  const svc = {
    listWorkRequests: vi.fn(),
    listConversionMaps: vi.fn(),
    setWorkRequestStatus: vi.fn(),
    convertWorkRequest: vi.fn(),
  };

  beforeEach(() => {
    vi.resetAllMocks();
    svc.listWorkRequests.mockReturnValue(of([
      item('1', 'new', '2026-10-19T08:00:00Z'),
      item('2', 'triaged', '2026-10-19T07:00:00Z'),
    ]));
    svc.listConversionMaps.mockReturnValue(of([{ id: 'm1', name: 'To ticket', target_entity: 'service_ticket' }]));
    svc.setWorkRequestStatus.mockReturnValue(of({}));
    svc.convertWorkRequest.mockReturnValue(of({ records: [] }));
    TestBed.configureTestingModule({
      imports: [TriageBoardComponent],
      providers: [
        { provide: ServiceAdminService, useValue: svc },
        { provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' } },
      ],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(TriageBoardComponent);
    fixture.detectChanges();
    return fixture;
  }

  it('shows each request in its status column', () => {
    const el: HTMLElement = render().nativeElement;
    const column = (status: string) =>
      el.querySelector(`[data-status="${status}"]`)!.querySelectorAll('[data-testid="triage-card"]');
    expect(column('new').length).toBe(1);
    expect(column('triaged').length).toBe(1);
    expect(column('converted').length).toBe(0);
  });

  it('accepts a new request against its version and reloads', () => {
    const fixture = render();
    const el: HTMLElement = fixture.nativeElement;
    (el.querySelector('[data-id="1"] [data-testid="triage-accept"]') as HTMLButtonElement).click();
    expect(svc.setWorkRequestStatus).toHaveBeenCalledWith(
      expect.objectContaining({ id: '1', row_version: 3 }),
      'triaged',
    );
    expect(svc.listWorkRequests).toHaveBeenCalledTimes(2);
  });

  it('offers no accept on a triaged request, but converts it with the chosen map', () => {
    const el: HTMLElement = render().nativeElement;
    expect(el.querySelector('[data-id="2"] [data-testid="triage-accept"]')).toBeNull();
    (el.querySelector('[data-id="2"] [data-testid="triage-convert"]') as HTMLButtonElement).click();
    expect(svc.convertWorkRequest).toHaveBeenCalledWith('2', 'm1');
  });
});
