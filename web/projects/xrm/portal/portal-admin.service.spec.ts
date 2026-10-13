import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ATTOME_CONFIG } from '@attome/base';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { PortalAdminService } from './portal-admin.service';

/** Pins the URL, method and body each call sends to the portal admin API. */
describe('PortalAdminService', () => {
  let service: PortalAdminService;
  let http: HttpTestingController;
  const API = 'http://localhost:7865';
  const BASE = `${API}/api/v1/admin/webportals`;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG, useValue: { apiUrl: API } },
      ],
    });
    service = TestBed.inject(PortalAdminService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('lists portals on the one-based admin page', () => {
    service.listPortals().subscribe();
    const req = http.expectOne(r => r.url === BASE);
    expect(req.request.method).toBe('GET');
    expect(req.request.params.get('page')).toBe('1');
    expect(req.request.params.get('page_size')).toBe('200');
    expect(req.request.withCredentials).toBe(true);
    req.flush({ items: [], total: 0, page: 1, page_size: 200 });
  });

  it('puts a grant under the role and entity', () => {
    const grant = {
      can_read: true, can_create: true, can_update: false, can_delete: false,
      conditions: [{ field: 'portal_user_ref', operator: 'eq' as const, value_ref: '@portal_user.id' }],
      fields: [{ field: 'title', can_read: true, can_write: true, can_filter: false }],
    };
    service.putGrant('p1', 'r1', 'case', grant).subscribe();
    const req = http.expectOne(`${BASE}/p1/roles/r1/grants/case`);
    expect(req.request.method).toBe('PUT');
    expect(req.request.body).toEqual(grant);
    req.flush(null, { status: 204, statusText: 'No Content' });
  });

  it('assigns a role with a role_id body', () => {
    service.assignRole('p1', 'u1', 'r1').subscribe();
    const req = http.expectOne(`${BASE}/p1/users/u1/role`);
    expect(req.request.method).toBe('PUT');
    expect(req.request.body).toEqual({ role_id: 'r1' });
    req.flush(null, { status: 204, statusText: 'No Content' });
  });

  it('exports a user through the export route (G-14)', () => {
    let id: string | undefined;
    service.exportUser('p1', 'u1').subscribe(r => (id = r.id));
    const req = http.expectOne(`${BASE}/p1/users/u1/export`);
    expect(req.request.method).toBe('POST');
    req.flush({ id: 'dsr-1', status: 'fulfilled', scopes: [] });
    expect(id).toBe('dsr-1');
  });

  it('invites, enables and disables on their own routes', () => {
    service.inviteUser('p1', 'u1').subscribe();
    http.expectOne(r => r.method === 'POST' && r.url === `${BASE}/p1/users/u1/invite`).flush({ expires_at: '2026-10-01T00:00:00Z' });
    service.setUserEnabled('p1', 'u1', false).subscribe();
    http.expectOne(r => r.method === 'POST' && r.url === `${BASE}/p1/users/u1/disable`).flush({});
    service.setUserEnabled('p1', 'u1', true).subscribe();
    http.expectOne(r => r.method === 'POST' && r.url === `${BASE}/p1/users/u1/enable`).flush({});
  });

  it('patches settings and reads and puts the auth policy', () => {
    service.updateSettings('p1', { row_version: 3, mfa_policy: 'required', owning_team_ref: null }).subscribe();
    const patch = http.expectOne(r => r.method === 'PATCH' && r.url === `${BASE}/p1/settings`);
    expect(patch.request.body).toEqual({ row_version: 3, mfa_policy: 'required', owning_team_ref: null });
    patch.flush({});

    service.getAuthPolicy('p1').subscribe();
    http.expectOne(r => r.method === 'GET' && r.url === `${BASE}/p1/auth-policy`).flush({});
    const body = {
      signup_mode: 'invite_only' as const, signup_domains: [], signup_role_ref: null, oidc_providers: [],
      terms_version: null, privacy_version: null, editable_profile_fields: ['phone'],
      page_size_cap: 100, allowed_cidrs: [], records_rpm: 600, username_min_len: 3, username_max_len: 12, username_blocked_words: [], username_reserved: [], trusted_server_login: false, row_version: 1,
    };
    service.putAuthPolicy('p1', body).subscribe();
    const put = http.expectOne(r => r.method === 'PUT' && r.url === `${BASE}/p1/auth-policy`);
    expect(put.request.body).toEqual(body);
    put.flush(body);
  });

  it('renames and deletes a role and unassigns a user role', () => {
    service.renameRole('p1', 'r1', 'agents').subscribe();
    const rename = http.expectOne(r => r.method === 'PATCH' && r.url === `${BASE}/p1/roles/r1`);
    expect(rename.request.body).toEqual({ name: 'agents' });
    rename.flush(null, { status: 204, statusText: 'No Content' });
    service.deleteRole('p1', 'r1').subscribe();
    http.expectOne(r => r.method === 'DELETE' && r.url === `${BASE}/p1/roles/r1`)
      .flush(null, { status: 204, statusText: 'No Content' });
    service.unassignRole('p1', 'u1').subscribe();
    http.expectOne(r => r.method === 'DELETE' && r.url === `${BASE}/p1/users/u1/role`)
      .flush(null, { status: 204, statusText: 'No Content' });
  });
});
