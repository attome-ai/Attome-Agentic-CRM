import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, AuthService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { WhatsAppSetupComponent, systemBody } from './whatsapp-setup.component';

const NUMBER = { id: 'n1', name: 'Riyadh support', phone_number_id: '111', waba_id: '222', templates: 0, synced_at: null };
const TEMPLATE = {
  id: 't1', name: 'order_ready', language: 'ar', category: 'UTILITY', variables: ['body.1', 'body.2'],
  variable_map: { 'body.1': 'first_name' }, synced_at: '2026-11-01T00:00:00Z', row_version: 2,
};

function setup() {
  const api = {
    get: vi.fn((path: string) => of(path.endsWith('/numbers') ? { items: [NUMBER], total: 1 } : { items: [TEMPLATE], total: 1 })),
    post: vi.fn((path: string) => of(path.endsWith('/sync') ? { added: 1, updated: 0, removed: 0 } : { id: 'n2' })),
    put: vi.fn(() => of({ ...TEMPLATE, variable_map: { 'body.1': 'first_name', 'body.2': 'order_no' }, row_version: 3 })),
  };
  TestBed.configureTestingModule({
    imports: [WhatsAppSetupComponent],
    providers: [
      { provide: ApiService, useValue: api },
      { provide: AuthService, useValue: { userId: signal('u1') } },
      { provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' } },
    ],
  });
  const fixture = TestBed.createComponent(WhatsAppSetupComponent);
  fixture.detectChanges();
  return { api, fixture, root: fixture.nativeElement as HTMLElement };
}

describe('WhatsAppSetupComponent (J5-T3)', () => {
  it('connects a number as a WhatsApp system with its secrets sealed', () => {
    const body = systemBody({
      name: ' Support ', phone_number_id: '111', waba_id: '222', access_token: 'tok', app_secret: 'sec',
      verify_token: 'v', unknown_sender: 'contact',
    }, 'u1');
    expect(body['name']).toBe('Support');
    expect(body['service_principal_ref']).toBe('u1');
    const config = JSON.parse(body['config'] as string) as Record<string, string>;
    expect(config['social']).toBe('whatsapp');
    expect(config['waba_id']).toBe('222');
    expect(config['inbound_key']).toMatch(/^[0-9a-f]{32}$/);
    expect(JSON.parse(body['credential_value'] as string)).toEqual({ access_token: 'tok', app_secret: 'sec' });
    expect(config['access_token']).toBeUndefined();
  });

  it('syncs templates and saves a variable map with the row version', () => {
    const { api, fixture, root } = setup();
    expect(root.querySelector('[data-testid="wa-numbers"]')?.textContent).toContain('Riyadh support');
    (root.querySelector('[data-testid="wa-sync"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(api.post).toHaveBeenCalledWith('/api/v1/admin/integrations/whatsapp/n1/templates/sync', {});
    expect(root.querySelector('[data-testid="wa-templates"]')?.textContent).toContain('order_ready');

    const component = fixture.componentInstance;
    component.setVar(component.templates()[0], 'body.2', 'order_no');
    (root.querySelector('[data-testid="wa-save-map"]') as HTMLButtonElement).click();
    expect(api.put).toHaveBeenCalledWith(
      '/api/v1/admin/integrations/whatsapp/templates/t1/variables',
      { variable_map: { 'body.1': 'first_name', 'body.2': 'order_no' } },
      { ifMatch: 2 },
    );
  });
});
