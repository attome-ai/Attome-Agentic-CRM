import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ATTOME_CONFIG } from '@attome/base';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { RecordSharingService } from './record-sharing.service';

/** The SDK sends after a promise turn (Y9-T3). */
const tick = (): Promise<void> => new Promise(resolve => setTimeout(resolve, 0));

/** Addressing only: the realistic defect on these routes is a wrong verb or
 * path (reassign-owner was once sent as POST), not a wrong decision. */
describe('RecordSharingService', () => {
  const SEC = 'http://localhost:7865/api/v1/admin/security';
  let service: RecordSharingService;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
      ],
    });
    service = TestBed.inject(RecordSharingService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('reassigns an owner with PUT on the dedicated sub-route', async () => {
    service.reassignOwner({ entity: 'ticket', record_id: 'r1', user_email: 'a@b.c' }).subscribe();
    await tick();
    const req = http.expectOne(`${SEC}/record-shares/reassign-owner`);
    expect(req.request.method).toBe('PUT');
    expect(req.request.body).toEqual({ entity: 'ticket', record_id: 'r1', user_email: 'a@b.c' });
    req.flush({});
  });

  it('lists, grants and revokes shares on the record-share collection', async () => {
    service.listRecordShares('ticket', 'r1').subscribe();
    await tick();
    const list = http.expectOne(r => r.url === `${SEC}/record-shares`);
    expect(list.request.params.get('entity')).toBe('ticket');
    expect(list.request.params.get('record_id')).toBe('r1');
    list.flush({ items: [], total: 0, page: 1, page_size: 200 });

    service.createRecordShare({ entity: 'ticket', record_id: 'r1', capability: 'view', team_name: 'T' }).subscribe();
    await tick();
    const create = http.expectOne(`${SEC}/record-shares`);
    expect(create.request.method).toBe('POST');
    create.flush({});

    service.deleteRecordShare('s1').subscribe();
    await tick();
    const del = http.expectOne(`${SEC}/record-shares/s1`);
    expect(del.request.method).toBe('DELETE');
    del.flush(null);
  });
});
