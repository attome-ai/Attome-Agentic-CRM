import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ActivatedRoute, convertToParamMap } from '@angular/router';
import { ApiService, LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { DeviceApprovalComponent, normaliseUserCode } from './device-approval.component';

const GRANT = {
  client_id: 'attome-cli', client_name: 'Attome CLI', user_code: 'BCDF-GHJK',
  created_at: '2026-10-30T10:00:00Z', expires_at: '2026-10-30T10:10:00Z',
};

describe('DeviceApprovalComponent (C7-T1)', () => {
  function create(query: Record<string, string> = {}, found = true) {
    const get = vi.fn(() => (found ? of(GRANT) : throwError(() => ({ status: 404, kind: 'not_found' }))));
    const post = vi.fn(() => of(null));
    TestBed.configureTestingModule({
      imports: [DeviceApprovalComponent],
      providers: [
        { provide: ApiService, useValue: { get, post } },
        { provide: ActivatedRoute, useValue: { snapshot: { queryParamMap: convertToParamMap(query) } } },
        {
          provide: LangService,
          useValue: {
            translate: (k: string, p?: Record<string, string>) => (p ? `${k}:${Object.values(p).join(',')}` : k),
            current: signal('en'), errorText: () => 'error', intlLocale: () => 'en-US',
          },
        },
      ],
    });
    const fixture = TestBed.createComponent(DeviceApprovalComponent);
    fixture.detectChanges();
    return { fixture, get, post, root: fixture.nativeElement as HTMLElement };
  }

  it('normalises a typed code', () => {
    expect(normaliseUserCode(' bcdf-ghjk ')).toBe('BCDFGHJK');
  });

  it('looks up the code from the link and approves it', () => {
    const { fixture, get, post, root } = create({ user_code: 'bcdf-ghjk' });
    expect(get).toHaveBeenCalledWith('/api/v1/oauth/device', { user_code: 'BCDFGHJK' });
    expect(root.querySelector('[data-client]')?.textContent).toContain('Attome CLI');
    (root.querySelector('[data-approve]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(post).toHaveBeenCalledWith('/api/v1/oauth/device/approve', { user_code: 'BCDFGHJK', approve: true });
    expect(root.querySelector('[data-done]')?.textContent).toContain('deviceApproval.approved');
  });

  it('denies, and says when a code is unknown', () => {
    const { fixture, post, root } = create({ user_code: 'BCDFGHJK' });
    (root.querySelector('[data-deny]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(post).toHaveBeenCalledWith('/api/v1/oauth/device/approve', { user_code: 'BCDFGHJK', approve: false });
    TestBed.resetTestingModule();
    const missing = create({ user_code: 'ZZZZZZZZ' }, false);
    missing.fixture.detectChanges();
    expect(missing.root.querySelector('[role="alert"]')?.textContent).toContain('deviceApproval.notFound');
  });
});
