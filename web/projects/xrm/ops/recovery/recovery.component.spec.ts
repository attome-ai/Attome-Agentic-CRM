import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, ATTOME_CONFIG, LangService, UserPreferencesService } from '@attome/base';
import { AccessService } from '@attome/xrm/core/access/data';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { RecoveryComponent, RecoveryTarget, RpoSource } from './recovery.component';

const TARGETS: RecoveryTarget[] = [
  {
    id: 't-1', profile: 'solo', scenario: 'corruption', rpo_seconds: 300, rto_seconds: 3600,
    evidence_kind: 'recovery', proven: false, proven_on: null, measured_rpo_seconds: null,
    measured_rto_seconds: null, row_version: 1,
  },
];

const RPO: RpoSource[] = [
  { source: 'backup', value_seconds: 90000, target_seconds: 300, status: 'over' },
  { source: 'standby', value_seconds: null, target_seconds: 300, status: 'off' },
];

const page = <T>(items: T[]) => ({ items, total: items.length, page: 1, page_size: 20 });

describe('RecoveryComponent (AB3-T10)', () => {
  function create(privileges: string[]) {
    TestBed.resetTestingModule();
    const get = vi.fn((url: string) => {
      if (url === '/api/v1/ops/recovery-targets') return of(page(TARGETS));
      if (url === '/api/v1/ops/rpo') return of(page(RPO));
      return of(page([]));
    });
    const post = vi.fn((_url: string, _body: unknown) => of({}));
    TestBed.configureTestingModule({
      imports: [RecoveryComponent],
      providers: [
        { provide: ApiService, useValue: { get, post } },
        { provide: AccessService, useValue: { ready: () => of(undefined), hasPrivilege: (k: string) => privileges.includes(k) } },
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'https://crm.example' } },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, errorText: () => 'error', current: signal('en'), intlLocale: () => 'en-US' },
        },
        { provide: UserPreferencesService, useValue: { timezone: () => 'UTC', calendar: () => null, digits: () => null } },
      ],
    });
    const fixture = TestBed.createComponent(RecoveryComponent);
    fixture.detectChanges();
    return { fixture, post };
  }

  it('shows not proven without evidence', () => {
    const { fixture } = create(['ops.read']);
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-testid="rc-unproven"]')).not.toBeNull();
    expect(el.querySelector('[data-testid="rc-proven"]')).toBeNull();
    const tiles = Array.from(el.querySelectorAll('[data-testid="rc-rpo"]')).map(t => t.getAttribute('data-status'));
    expect(tiles).toEqual(['over', 'off']);
    expect(el.querySelector('[data-testid="rc-declare"]')).toBeNull();
    expect((el.querySelector('[data-testid="rc-runbook-ar"]') as HTMLAnchorElement).href)
      .toBe('https://crm.example/api/v1/ops/dr-runbook?lang=ar');
  });

  it('declare dialog requires summary', () => {
    const { fixture, post } = create(['ops.dr.declare']);
    const open: HTMLButtonElement = fixture.nativeElement.querySelector('[data-testid="rc-declare"]');
    open.click();
    fixture.detectChanges();
    const submit: HTMLButtonElement = fixture.nativeElement.querySelector('[data-testid="rc-declare-submit"]');
    submit.click();
    fixture.detectChanges();
    expect(post).not.toHaveBeenCalled();
    expect(fixture.nativeElement.querySelector('[data-testid="rc-form-error"]')).not.toBeNull();

    fixture.componentInstance.summary = 'The Riyadh site lost power';
    submit.click();
    fixture.detectChanges();
    expect(post).toHaveBeenCalledWith('/api/v1/ops/disasters', {
      scenario: 'site_loss', summary: 'The Riyadh site lost power',
    });
  });
});
