import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ATTOME_CONFIG } from '@attome/base';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { FileUploadService } from './file-upload.service';

/** The SDK sends after a promise turn (Y9-T3). */
const tick = (): Promise<void> => new Promise(resolve => setTimeout(resolve, 0));

describe('FileUploadService', () => {
  let service: FileUploadService;
  let httpMock: HttpTestingController;

  const API = 'http://localhost:7865';

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG, useValue: { apiUrl: API } },
      ],
    });
    service = TestBed.inject(FileUploadService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  it('creates an upload session against the entity/record/field-scoped route', async () => {
    service.createSession('contact', 'rec-1', 'resume', {
      filename: 'cv.pdf',
      content_type: 'application/pdf',
      declared_size_bytes: 1234,
      checksum_sha256: 'a'.repeat(64),
    }).subscribe();
    await tick();

    const req = httpMock.expectOne(
      `${API}/api/v1/contact/rec-1/files/resume/upload-session`,
    );
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toMatchObject({ filename: 'cv.pdf', declared_size_bytes: 1234 });
    req.flush({ session_id: 's1', upload_url: 'http://storage/x', expires_in_secs: 900 });
    await tick();
  });

  it('finalizes against the session-scoped route', async () => {
    service.finalize('contact', 'rec-1', 'resume', 's1').subscribe();
    await tick();
    const req = httpMock.expectOne(
      `${API}/api/v1/contact/rec-1/files/resume/upload-session/s1/finalize`,
    );
    expect(req.request.method).toBe('POST');
    req.flush({ session_id: 's1', status: 'uploaded' });
    await tick();
  });

  it('polls session status', async () => {
    service.getStatus('contact', 'rec-1', 'resume', 's1').subscribe();
    await tick();
    const req = httpMock.expectOne(
      `${API}/api/v1/contact/rec-1/files/resume/upload-session/s1`,
    );
    expect(req.request.method).toBe('GET');
    req.flush({
      status: 'clean', reject_reason: null, actual_size_bytes: 1234,
      actual_content_type: 'application/pdf', final_key: 'contact/rec-1/resume/s1-cv.pdf',
    });
    await tick();
  });

  it('resolves a download URL for the record/field, not a client-supplied key', async () => {
    service.getDownloadUrl('contact', 'rec-1', 'resume').subscribe();
    await tick();
    const req = httpMock.expectOne(
      `${API}/api/v1/contact/rec-1/files/resume/download-url`,
    );
    expect(req.request.method).toBe('GET');
    req.flush({ download_url: 'http://storage/y', expires_in_secs: 900 });
    await tick();
  });

  it('resolves one key of a multi-file field with ?key=', async () => {
    service.getDownloadUrl('note', 'rec-1', 'files', 'a/b c.pdf').subscribe();
    await tick();
    const req = httpMock.expectOne(
      r => r.url === `${API}/api/v1/note/rec-1/files/files/download-url` && r.params.get('key') === 'a/b c.pdf',
    );
    req.flush({ download_url: 'http://storage/y', expires_in_secs: 900 });
    await tick();
  });

  it('resolves one recorded version with ?version=, which wins over a key', async () => {
    service.getDownloadUrl('contact', 'rec-1', 'resume', { version: 3, key: 'ignored' }).subscribe();
    await tick();
    const req = httpMock.expectOne(
      r => r.url === `${API}/api/v1/contact/rec-1/files/resume/download-url` && r.params.get('version') === '3' && !r.params.has('key'),
    );
    expect(req.request.method).toBe('GET');
    req.flush({ download_url: 'http://storage/v3', expires_in_secs: 900 });
    await tick();
  });

  it('lists a field version history', async () => {
    let total = -1;
    service.listVersions('contact', 'rec-1', 'resume').subscribe(page => { total = page.total; });
    await tick();
    const req = httpMock.expectOne(`${API}/api/v1/contact/rec-1/files/resume/versions`);
    expect(req.request.method).toBe('GET');
    req.flush({ items: [], total: 0, page: 1, page_size: 1 });
    await tick();
    expect(total).toBe(0);
  });

  it('restores a version with a POST to its restore route', async () => {
    service.restoreVersion('contact', 'rec-1', 'resume', 2).subscribe();
    await tick();
    const req = httpMock.expectOne(`${API}/api/v1/contact/rec-1/files/resume/versions/2/restore`);
    expect(req.request.method).toBe('POST');
    req.flush({ version_no: 2, object_key: 'k2' });
    await tick();
  });

  it('purges a version with a DELETE', async () => {
    service.purgeVersion('contact', 'rec-1', 'resume', 1).subscribe();
    await tick();
    const req = httpMock.expectOne(`${API}/api/v1/contact/rec-1/files/resume/versions/1`);
    expect(req.request.method).toBe('DELETE');
    req.flush(null, { status: 204, statusText: 'No Content' });
    await tick();
  });

  it('opens a multipart upload on the field and reads its received parts', async () => {
    service.startMultipart('contact', 'rec-1', 'resume', {
      filename: 'big.mp4', content_type: 'video/mp4', declared_size_bytes: 20_000_000,
    }).subscribe();
    await tick();
    const start = httpMock.expectOne(`${API}/api/v1/contact/rec-1/files/resume/multipart`);
    expect(start.request.method).toBe('POST');
    start.flush({ session_id: 's1', part_size: 8_388_608, part_count: 3 });
    await tick();

    let received: number[] = [];
    service.multipartStatus('s1').subscribe(s => (received = s.received));
    await tick();
    const status = httpMock.expectOne(`${API}/api/v1/files/uploads/s1`);
    expect(status.request.method).toBe('GET');
    status.flush({ session_id: 's1', status: 'open', part_size: 8_388_608, part_count: 3, received: [1, 2] });
    await tick();
    expect(received).toEqual([1, 2]);

    service.partUrl('s1', 3).subscribe();
    await tick();
    const part = httpMock.expectOne(`${API}/api/v1/files/uploads/s1/parts/3`);
    expect(part.request.method).toBe('PUT');
    part.flush({ part: 3, upload_url: 'http://storage/x.parts/00003', expires_in_secs: 3600 });
    await tick();

    service.completeMultipart('s1').subscribe();
    await tick();
    const complete = httpMock.expectOne(`${API}/api/v1/files/uploads/s1/complete`);
    expect(complete.request.method).toBe('POST');
    complete.flush({ session_id: 's1', size: 20_000_000, checksum_sha256: 'a'.repeat(64) });
    await tick();
  });

  it('PUTs directly to the presigned storage URL, bypassing the configured apiUrl and credentials', async () => {
    const file = new File(['hello'], 'cv.pdf', { type: 'application/pdf' });
    service.putToStorage('http://storage.example/quarantine/key?sig=abc', file).subscribe();
    await tick();

    const req = httpMock.expectOne('http://storage.example/quarantine/key?sig=abc');
    expect(req.request.method).toBe('PUT');
    expect(req.request.body).toBe(file);
    expect(req.request.withCredentials).toBe(false);
    req.flush(null);
    await tick();
  });
});
