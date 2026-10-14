import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { UsageComponent } from './usage.component';

describe('UsageComponent (U11-T1)', () => {
  it('shows users, the contract reference and the modules on', () => {
    const get = vi.fn().mockReturnValue(of({
      modules_on: ['core', 'workflow'],
      users_active: 12,
      users_signed_in_30d: 9,
      contract_reference: null,
    }));
    TestBed.configureTestingModule({
      imports: [UsageComponent],
      providers: [
        { provide: ApiService, useValue: { get } },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
    const fixture = TestBed.createComponent(UsageComponent);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    expect(get).toHaveBeenCalledWith('/api/v1/admin/usage');
    expect(el.querySelector('[data-figure="active"]')?.textContent).toContain('12');
    expect(el.querySelector('[data-figure="recent"]')?.textContent).toContain('9');
    expect(el.textContent).toContain('usagePage.noContract');
    expect(el.querySelectorAll('.us-modules li').length).toBe(2);
  });

  it('warns when backups share the disk and are late (U6-T1)', () => {
    const usage = { modules_on: [], users_active: 1, users_signed_in_30d: 1, contract_reference: null };
    const backup = {
      enabled: true, runs_here: true, files: true, dir: '/srv/attome/backups', keep: 7, hour: 2,
      same_disk: true, archives: 3,
      latest: { name: 'attome-20200101-0200.dump', taken_at: '2020-01-01T02:00:00Z', size_bytes: 10, files: 4 },
    };
    const get = vi.fn((path: string) => of(path === '/api/v1/admin/backup' ? backup : usage));
    TestBed.configureTestingModule({
      imports: [UsageComponent],
      providers: [
        { provide: ApiService, useValue: { get } },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
    const fixture = TestBed.createComponent(UsageComponent);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-backup="same-disk"]')).not.toBeNull();
    expect(el.querySelector('[data-backup="late"]')).not.toBeNull();
    expect(el.querySelector('[data-backup="latest"]')?.textContent).toContain('attome-20200101-0200.dump');
    const fresh = { ...backup.latest, taken_at: new Date().toISOString() };
    expect(fixture.componentInstance.backupLate({ ...backup, latest: fresh })).toBe(false);
  });
});
