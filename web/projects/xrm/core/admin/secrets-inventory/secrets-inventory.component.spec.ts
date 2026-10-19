import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it } from 'vitest';

import { SecretsAdminService } from '../data/services/secrets-admin.service';
import { SecretsInventoryComponent } from './secrets-inventory.component';

describe('SecretsInventoryComponent (Z1-T14)', () => {
  function setUp() {
    const rows = [
      { name: 'auth.jwt_secret', used_by: ['sessions'], key_ids: ['k1', 'k0'], active_key_id: 'k1',
        active_since: '2025-01-01T00:00:00Z', age_days: 400, over_age: true, rotation: 'key_ring', set: true },
      { name: 'email.smtp_password', used_by: ['email'], key_ids: [], active_key_id: null,
        active_since: null, age_days: null, over_age: false, rotation: 'replace', set: false },
    ];
    TestBed.configureTestingModule({
      imports: [SecretsInventoryComponent],
      providers: [
        { provide: SecretsAdminService, useValue: { secrets: () => of({ items: rows, total: 2, page: 1, page_size: 200 }) } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: signal('en-US'), errorText: () => 'error' } },
      ],
    });
    const fixture = TestBed.createComponent(SecretsInventoryComponent);
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  it('renders one row per secret with its users and active key', () => {
    const root = setUp();
    expect(root.querySelectorAll('[data-secret-row]').length).toBe(2);
    const jwt = root.querySelector('[data-secret-row="auth.jwt_secret"]') as HTMLElement;
    expect(jwt.textContent).toContain('sessions');
    expect(jwt.textContent).toContain('k1');
    expect(jwt.querySelector('[data-secret-over-age]')).not.toBeNull();
    expect(root.querySelector('[data-secret-row="email.smtp_password"] [data-secret-unset]')).not.toBeNull();
  });

  it('shows no value column', () => {
    const root = setUp();
    const headers = Array.from(root.querySelectorAll('thead th')).map(th => th.textContent?.trim());
    expect(headers).toEqual(['secretsAdmin.name', 'secretsAdmin.usedBy', 'secretsAdmin.activeKey', 'secretsAdmin.age']);
    expect(root.textContent).not.toContain('value');
  });
});
