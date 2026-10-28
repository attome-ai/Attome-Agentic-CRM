import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ActivatedRoute, convertToParamMap, provideRouter } from '@angular/router';
import { LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { OidcProviderFormComponent, applyPreset, bodyOf, draftOf, emptyDraft } from './oidc-provider-form.component';
import { OidcProvidersComponent } from './oidc-providers.component';
import { OidcPresetItem, OidcProviderItem, SecurityAdminService } from './security-admin.service';

const provider = (over: Partial<OidcProviderItem> = {}): OidcProviderItem => ({
  id: 'p1', key: 'corp', display_name: 'Corp', display_name_ar: 'الشركة', issuer: 'https://login.corp.example',
  client_id: 'client', scopes: ['openid', 'email'], claim_map: { email: 'email' }, link_mode: 'link_only',
  trusted_for_mfa: false, tenant_allowlist: [], enabled: true, read_only: false, secret_set: true,
  secret_fingerprint: 'ab12', row_version: 3, preset: null, default_role_ref: null, secret_updated_at: null,
  ...over,
} as unknown as OidcProviderItem);

const lang = { translate: (k: string) => k, current: signal('en'), errorText: () => 'error', intlLocale: () => 'en-GB' };

describe('sign-in provider screens (Q1-T14)', () => {
  it('applies a preset without overwriting what was typed', () => {
    const draft = applyPreset({ ...emptyDraft(), display_name: 'Our login' }, {
      key: 'entra', display_name: 'Microsoft Entra ID', kind: 'oidc',
      issuer_template: 'https://login.microsoftonline.com/{tenant}/v2.0', scopes: ['openid', 'email', 'profile'],
      claim_map: { email: 'preferred_username' }, mfa_claim: 'amr', supports_forced_reauth: true,
    } as unknown as OidcPresetItem);
    expect(draft.preset).toBe('entra');
    expect(draft.display_name).toBe('Our login');
    expect(draft.issuer).toBe('https://login.microsoftonline.com/{tenant}/v2.0');
    expect(draft.scopes).toBe('openid email profile');
    expect(JSON.parse(draft.claim_map)).toEqual({ email: 'preferred_username' });
  });

  it('builds the request body, keeping the stored secret when none is typed', () => {
    const edit = bodyOf(draftOf(provider()), false);
    expect('body' in edit ? edit.body['client_secret'] : 'invalid').toBeUndefined();
    expect('body' in edit && edit.body['scopes']).toEqual(['openid', 'email']);
    expect('body' in edit && 'key' in edit.body).toBe(false);
    expect(bodyOf({ ...emptyDraft(), display_name: 'X', issuer: 'https://x', client_id: 'c' }, true))
      .toEqual({ invalid: 'oidcAdmin.required' });
    expect(bodyOf({ ...draftOf(provider()), claim_map: '[1]' }, false)).toEqual({ invalid: 'oidcAdmin.invalidClaimMap' });
  });

  function mountForm(id: string, svc: Record<string, unknown>) {
    TestBed.configureTestingModule({
      imports: [OidcProviderFormComponent],
      providers: [
        provideRouter([]),
        { provide: ActivatedRoute, useValue: { snapshot: { paramMap: convertToParamMap({ id }) } } },
        { provide: SecurityAdminService, useValue: svc },
        { provide: LangService, useValue: lang },
      ],
    });
    const fixture = TestBed.createComponent(OidcProviderFormComponent);
    fixture.detectChanges();
    return { fixture, cmp: fixture.componentInstance, el: fixture.nativeElement as HTMLElement };
  }

  const baseSvc = () => ({
    listOidcPresets: vi.fn(() => of([])),
    listRoles: vi.fn(() => of([{ id: 'r1', name: 'Sales' }])),
    listOidcProviders: vi.fn(() => of([provider()])),
    listOidcDomains: vi.fn(() => of([{
      id: 'd1', domain: 'corp.example', provider_id: 'p1', provider_key: 'corp',
      verification_record_name: '_attome.corp.example', verification_record_value: 'attome-verify=abc',
      sso_only: false, created_at: '2026-10-01T00:00:00Z', row_version: 0, verified_at: null,
    }])),
    listOidcGroupMappings: vi.fn(() => of([{ id: 'm1', provider_id: 'p1', claim_value: 'sales', role_id: 'r1', team_id: null }])),
    updateOidcProvider: vi.fn(() => of(provider({ row_version: 4 }))),
    verifyOidcDomain: vi.fn(() => of({})),
  });

  it('saves an edit with its row version and shows the domain\'s TXT record and the mappings', () => {
    TestBed.resetTestingModule();
    const svc = baseSvc();
    const { fixture, cmp, el } = mountForm('p1', svc);
    cmp.draft.display_name = 'Corp SSO';
    cmp.save();
    expect(svc.updateOidcProvider).toHaveBeenCalledWith('p1', expect.objectContaining({ display_name: 'Corp SSO' }), 3);
    cmp.show('domains');
    fixture.detectChanges();
    expect(el.querySelector('[data-domain="corp.example"]')?.textContent)
      .toContain('_attome.corp.example TXT "attome-verify=abc"');
    cmp.show('groups');
    fixture.detectChanges();
    expect(el.querySelector('[data-mapping="sales"]')?.textContent).toContain('Sales');
  });

  it('shows a provider from config.json read-only', () => {
    TestBed.resetTestingModule();
    const svc = { ...baseSvc(), listOidcProviders: vi.fn(() => of([provider({ read_only: true })])) };
    const { fixture, cmp, el } = mountForm('p1', svc);
    fixture.detectChanges();
    expect(cmp.readOnly()).toBe(true);
    expect(el.querySelector('[data-read-only]')).not.toBeNull();
    expect(el.querySelector('[data-testid="oidc-test"]')).toBeNull();
  });

  it('lists providers with a config badge', () => {
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      imports: [OidcProvidersComponent],
      providers: [
        provideRouter([]),
        { provide: SecurityAdminService, useValue: { listOidcProviders: vi.fn(() => of([provider(), provider({ id: null, key: 'cfg', read_only: true })])) } },
        { provide: LangService, useValue: lang },
      ],
    });
    const fixture = TestBed.createComponent(OidcProvidersComponent);
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-provider="corp"] a')).not.toBeNull();
    expect(el.querySelector('[data-provider="cfg"] [data-config]')).not.toBeNull();
    expect(el.querySelector('[data-provider="cfg"] a')).toBeNull();
  });
});
