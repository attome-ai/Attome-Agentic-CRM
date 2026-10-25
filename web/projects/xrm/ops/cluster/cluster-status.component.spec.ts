import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService, UserPreferencesService } from '@attome/base';
import { AccessService } from '@attome/xrm/core/access/data';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { ClusterStatus, ClusterStatusComponent, reasonOk } from './cluster-status.component';

const SINGLE: ClusterStatus = {
  mode: 'single', leader: 'local', members: [], synchronous_standby: null, last_failover: null,
};

const HA: ClusterStatus = {
  mode: 'ha',
  leader: 'db1',
  members: [
    { name: 'db1', role: 'leader', state: 'running', lag_bytes: null, timeline: 3 },
    { name: 'db2', role: 'sync_standby', state: 'streaming', lag_bytes: 0, timeline: 3 },
    { name: 'db3', role: 'replica', state: 'streaming', lag_bytes: 4096, timeline: 3 },
  ],
  synchronous_standby: 'db2',
  last_failover: null,
};

const NO_HISTORY = { items: [], total: 0, page: 1, page_size: 20 };

describe('ClusterStatusComponent (AB2-T11)', () => {
  function create(status: ClusterStatus, canSwitch = true) {
    const get = vi.fn((url: string) => of(url === '/api/v1/ops/cluster' ? status : NO_HISTORY));
    const post = vi.fn((_url: string, _body: unknown) => of({ approval_id: 'a-1', status: 'pending' }));
    TestBed.configureTestingModule({
      imports: [ClusterStatusComponent],
      providers: [
        { provide: ApiService, useValue: { get, post } },
        { provide: AccessService, useValue: { ready: () => of(undefined), hasPrivilege: () => canSwitch } },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, errorText: () => 'error', current: signal('en'), intlLocale: () => 'en-US' },
        },
        { provide: UserPreferencesService, useValue: { timezone: () => 'UTC', calendar: () => null, digits: () => null } },
      ],
    });
    const fixture = TestBed.createComponent(ClusterStatusComponent);
    fixture.detectChanges();
    return { fixture, get, post };
  }

  it('shows single-server notice', () => {
    const { fixture } = create(SINGLE);
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-testid="oc-single"]')).not.toBeNull();
    expect(el.querySelector('[data-testid="oc-members"]')).toBeNull();
    expect(el.querySelector('[data-testid="oc-request"]')).toBeNull();
  });

  it('lists members in ha mode', () => {
    const { fixture } = create(HA);
    const rows = fixture.nativeElement.querySelectorAll('[data-testid="oc-member"]');
    expect(rows.length).toBe(3);
    expect(rows[1].textContent).toContain('ops.cluster.sync');
    expect(rows[2].textContent).toContain('4096');
    expect(fixture.nativeElement.querySelector('[data-testid="oc-request"]')).not.toBeNull();
  });

  it('hides the switchover request without the privilege', () => {
    const { fixture } = create(HA, false);
    expect(fixture.nativeElement.querySelector('[data-testid="oc-request"]')).toBeNull();
  });

  it('blocks submit with short reason', () => {
    const { fixture, post } = create(HA);
    const component = fixture.componentInstance;
    component.openDialog();
    component.reason = 'too short';
    component.submit();
    fixture.detectChanges();
    expect(post).not.toHaveBeenCalled();
    expect(fixture.nativeElement.querySelector('[data-testid="oc-form-error"]')).not.toBeNull();

    component.reason = 'planned kernel patching';
    component.candidate = 'db2';
    component.submit();
    fixture.detectChanges();
    expect(post).toHaveBeenCalledWith('/api/v1/ops/cluster/switchover', {
      reason: 'planned kernel patching', candidate: 'db2',
    });
    expect(fixture.nativeElement.querySelector('[data-testid="oc-approval"]')).not.toBeNull();
    expect(component.replicas().map(m => m.name)).toEqual(['db2', 'db3']);
  });

  it('checks the reason length', () => {
    expect(reasonOk('123456789')).toBe(false);
    expect(reasonOk('1234567890')).toBe(true);
    expect(reasonOk('x'.repeat(501))).toBe(false);
  });
});
