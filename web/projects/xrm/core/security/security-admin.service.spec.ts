import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ATTOME_CONFIG } from '@attome/base';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { SecurityAdminService } from './security-admin.service';

/**
 * The client for the platform's entire authorization-administration surface:
 * grants, roles, role grants, field-security profiles, entity access, team and
 * organization membership, and record shares.
 *
 * Coverage here is deliberately about *addressing*, not about the backend's
 * decisions. Every method is a one-line path/verb/body construction, and the
 * realistic defect is a wrong one — a delete aimed at the collection instead of
 * the member, a nested id in the wrong position, a body key the backend ignores
 * so a write silently no-ops. On this particular surface those mistakes revoke
 * or grant the wrong access rather than throwing, which is exactly the class
 * that reaches production looking fine.
 */
describe('SecurityAdminService', () => {
  let service: SecurityAdminService;
  let httpMock: HttpTestingController;

  const API = 'http://localhost:7865';
  const SEC = `${API}/api/v1/admin/security`;

  const emptyPage = { items: [], total: 0, page: 1, page_size: 200 };

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG, useValue: { apiUrl: API } },
      ],
    });
    service = TestBed.inject(SecurityAdminService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  /** Asserts a paginated-walk collection endpoint and unwraps one item. */
  const expectPagedList = (url: string) => {
    const req = httpMock.expectOne(r => r.url === url);
    expect(req.request.method).toBe('GET');
    expect(req.request.params.get('page')).toBe('1');
    expect(req.request.params.get('page_size')).toBe('200');
    return req;
  };

  // ── Privileges/Roles ────────────────────────────────────────────────────────

  it('lists privileges and roles through the paginated walk', () => {
    service.listPrivileges().subscribe();
    expectPagedList(`${SEC}/privileges`).flush(emptyPage);

    service.listRoles().subscribe();
    expectPagedList(`${SEC}/roles`).flush(emptyPage);
  });

  it('creates a role', () => {
    service.createRole({ name: 'auditor' } as never).subscribe();
    const req = httpMock.expectOne(`${SEC}/roles`);
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({ name: 'auditor' });
    req.flush({});
  });

  it('lists, creates and deletes role grants', () => {
    service.listRoleGrants().subscribe();
    expectPagedList(`${SEC}/role-grants`).flush(emptyPage);

    service.createRoleGrant({ role_ref: 'r1', privilege_ref: 'p1' } as never).subscribe();
    httpMock.expectOne(req => req.url === `${SEC}/role-grants` && req.method === 'POST').flush({});

    service.deleteRoleGrant('rg1').subscribe();
    const del = httpMock.expectOne(`${SEC}/role-grants/rg1`);
    expect(del.request.method).toBe('DELETE');
    del.flush(null);
  });

  // ── Field-security profiles ─────────────────────────────────────────────────

  it('lists and creates field profiles', () => {
    service.listFieldProfiles().subscribe();
    expectPagedList(`${SEC}/field-profiles`).flush(emptyPage);

    service.createFieldProfile({ name: 'pii' } as never).subscribe();
    httpMock.expectOne(r => r.url === `${SEC}/field-profiles` && r.method === 'POST').flush({});
  });

  it('scopes profile fields under the profile', () => {
    service.listFieldProfileFields('fp1').subscribe();
    expectPagedList(`${SEC}/field-profiles/fp1/fields`).flush(emptyPage);

    service.setFieldProfileField('fp1', { entity_name: 'contact', field_name: 'ssn' } as never).subscribe();
    const set = httpMock.expectOne(`${SEC}/field-profiles/fp1/fields`);
    expect(set.request.method).toBe('POST');
    expect(set.request.body).toMatchObject({ field_name: 'ssn' });
    set.flush({});
  });

  it('assigns a field profile to a role by body and unassigns it by path', () => {
    // Asymmetric on purpose: assignment carries role_id in the body, removal
    // addresses it as a path segment. Mixing the two produces a request the
    // backend answers 404/400 for, or worse, one that targets the collection.
    service.assignFieldProfile('fp1', 'r1').subscribe();
    const assign = httpMock.expectOne(`${SEC}/field-profiles/fp1/assignments`);
    expect(assign.request.method).toBe('POST');
    expect(assign.request.body).toEqual({ role_id: 'r1' });
    assign.flush(null);

    service.unassignFieldProfile('fp1', 'r1').subscribe();
    const unassign = httpMock.expectOne(`${SEC}/field-profiles/fp1/assignments/r1`);
    expect(unassign.request.method).toBe('DELETE');
    unassign.flush(null);
  });

  // ── Entity access ───────────────────────────────────────────────────────────

  it('lists, upserts and deletes entity-access grants', () => {
    service.listEntityAccessGrants().subscribe();
    expectPagedList(`${SEC}/role-entity-access`).flush(emptyPage);

    service.upsertEntityAccessGrant({ role_ref: 'r1', entity_name: 'contact' } as never).subscribe();
    const upsert = httpMock.expectOne(r => r.url === `${SEC}/role-entity-access` && r.method === 'POST');
    expect(upsert.request.body).toMatchObject({ entity_name: 'contact' });
    upsert.flush({});

    service.deleteEntityAccessGrant('ea1').subscribe();
    httpMock.expectOne(`${SEC}/role-entity-access/ea1`).flush(null);
  });

  // ── User roles ──────────────────────────────────────────────────────────────

  it('nests user roles under the user and removes by role id', () => {
    service.listUserRoles('u1').subscribe();
    expectPagedList(`${SEC}/users/u1/roles`).flush(emptyPage);

    service.assignUserRole('u1', { role_id: 'r1' } as never).subscribe();
    const assign = httpMock.expectOne(r => r.url === `${SEC}/users/u1/roles` && r.method === 'POST');
    expect(assign.request.body).toEqual({ role_id: 'r1' });
    assign.flush({});

    service.removeUserRole('u1', 'r1').subscribe();
    const remove = httpMock.expectOne(`${SEC}/users/u1/roles/r1`);
    expect(remove.request.method).toBe('DELETE');
    remove.flush(null);
  });

  // ── Teams ───────────────────────────────────────────────────────────────────

  it('manages teams, their members and their roles on correctly nested routes', () => {
    service.listTeams().subscribe();
    expectPagedList(`${SEC}/teams`).flush(emptyPage);

    service.createTeam({ name: 'ops' } as never).subscribe();
    httpMock.expectOne(r => r.url === `${SEC}/teams` && r.method === 'POST').flush({});

    service.deleteTeam('t1').subscribe();
    httpMock.expectOne(`${SEC}/teams/t1`).flush(null);

    service.listTeamMembers('t1').subscribe();
    expectPagedList(`${SEC}/teams/t1/members`).flush(emptyPage);

    service.addTeamMember('t1', { user_id: 'u1' } as never).subscribe();
    httpMock.expectOne(r => r.url === `${SEC}/teams/t1/members` && r.method === 'POST').flush({});

    // Member removal keys on the USER id under the team, not the membership row
    // id — a distinction that is invisible until both ids are valid uuids and
    // the wrong one silently removes nobody.
    service.removeTeamMember('t1', 'u1').subscribe();
    const rm = httpMock.expectOne(`${SEC}/teams/t1/members/u1`);
    expect(rm.request.method).toBe('DELETE');
    rm.flush(null);
  });

  it('wraps a bare role id into a role_id body when granting a role to a team', () => {
    service.addTeamRole('t1', 'r1').subscribe();
    const req = httpMock.expectOne(`${SEC}/teams/t1/roles`);
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({ role_id: 'r1' });
    req.flush({});

    service.removeTeamRole('t1', 'r1').subscribe();
    httpMock.expectOne(`${SEC}/teams/t1/roles/r1`).flush(null);
  });

  it('lists team roles', () => {
    service.listTeamRoles('t1').subscribe();
    expectPagedList(`${SEC}/teams/t1/roles`).flush(emptyPage);
  });

  // ── Organizations ───────────────────────────────────────────────────────────

  it('manages organization membership', () => {
    service.listOrganizations().subscribe();
    expectPagedList(`${SEC}/organizations`).flush(emptyPage);

    service.listOrganizationMembers('o1').subscribe();
    expectPagedList(`${SEC}/organizations/o1/members`).flush(emptyPage);

    service.addOrganizationMember('o1', { user_id: 'u1' } as never).subscribe();
    httpMock.expectOne(r => r.url === `${SEC}/organizations/o1/members` && r.method === 'POST').flush({});

    service.removeOrganizationMember('o1', 'u1').subscribe();
    const rm = httpMock.expectOne(`${SEC}/organizations/o1/members/u1`);
    expect(rm.request.method).toBe('DELETE');
    rm.flush(null);
  });

  // ── Record shares ───────────────────────────────────────────────────────────

  it('scopes a record-share listing by entity and record_id query params', () => {
    // Both params are required to identify the record. Dropping record_id
    // would widen the listing to every share on the entity — a disclosure, not
    // an empty result, so it would not look like a bug to the caller.
    service.listRecordShares('contact', 'rec-1').subscribe();
    const req = httpMock.expectOne(r => r.url === `${SEC}/record-shares`);
    expect(req.request.method).toBe('GET');
    expect(req.request.params.get('entity')).toBe('contact');
    expect(req.request.params.get('record_id')).toBe('rec-1');
    req.flush(emptyPage);
  });

  it('creates and deletes a record share', () => {
    service.createRecordShare({ entity: 'contact', record_id: 'rec-1' } as never).subscribe();
    httpMock.expectOne(r => r.url === `${SEC}/record-shares` && r.method === 'POST').flush({});

    service.deleteRecordShare('s1').subscribe();
    httpMock.expectOne(`${SEC}/record-shares/s1`).flush(null);
  });

  it('reassigns an owner on the dedicated sub-route, not the share collection', () => {
    service.reassignOwner({ entity: 'contact', record_id: 'rec-1', user_email: 'u2@example.com' }).subscribe();
    const req = httpMock.expectOne(`${SEC}/record-shares/reassign-owner`);
    // The server mounts this route as PUT only (attome-security admin/shares.rs); POST is a 405.
    expect(req.request.method).toBe('PUT');
    expect(req.request.body).toMatchObject({ user_email: 'u2@example.com' });
    req.flush({});
  });

  it('filters entity default shares by entity', () => {
    service.listEntityDefaultShares('contact').subscribe();
    const req = httpMock.expectOne(r => r.url === `${SEC}/entity-default-shares`);
    expect(req.request.params.get('entity')).toBe('contact');
    req.flush(emptyPage);

    service.createEntityDefaultShare({ entity: 'contact' } as never).subscribe();
    httpMock.expectOne(r => r.url === `${SEC}/entity-default-shares` && r.method === 'POST').flush({});

    service.deleteEntityDefaultShare('ds1').subscribe();
    httpMock.expectOne(`${SEC}/entity-default-shares/ds1`).flush(null);
  });

  // ── Preview and lookup ──────────────────────────────────────────────────────

  it('previews effective access for a user', () => {
    service.effectiveAccessPreview('u1').subscribe();
    const req = httpMock.expectOne(`${SEC}/users/u1/effective-access`);
    expect(req.request.method).toBe('GET');
    req.flush({});
  });

  it('lists users with 1-indexed paging defaulting to the backend maximum', () => {
    service.listUsers().subscribe();
    const req = httpMock.expectOne(r => r.url === `${SEC}/users`);
    expect(req.request.params.get('page')).toBe('1');
    expect(req.request.params.get('page_size')).toBe('200');
    req.flush(emptyPage);
  });

  it('looks a user up by email as a query parameter', () => {
    // As a param, not a path segment: an email contains characters that would
    // need escaping in a path, and `+`-addressed or unicode addresses are the
    // ones that would break first.
    service.findUserByEmail('a+tag@b.test').subscribe();
    const req = httpMock.expectOne(r => r.url === `${SEC}/users/lookup`);
    expect(req.request.params.get('email')).toBe('a+tag@b.test');
    req.flush([]);
  });

  it('sends session credentials on this surface', () => {
    service.effectiveAccessPreview('u1').subscribe();
    const req = httpMock.expectOne(`${SEC}/users/u1/effective-access`);
    expect(req.request.withCredentials).toBe(true);
    req.flush({});
  });
});
