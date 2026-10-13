import { Component } from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule } from '@angular/forms';
import { TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { HttpEvent, HttpEventType } from '@angular/common/http';
import { Subject, of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';

import { AttachmentComponent } from './attachment.component';
import { FileUploadService } from '../file-upload.service';

const SESSION_ID_36 = '00000000-0000-0000-0000-000000000000';

@Component({
  standalone: true,
  imports: [ReactiveFormsModule, AttachmentComponent],
  template: `
    <form [formGroup]="form">
      <xrm-attachment fieldName="passport_scan" label="Passport scan"
                      [entityName]="entityName" [recordId]="recordId"
                      [maxSizeBytes]="maxSizeBytes" />
    </form>
  `,
})
class HostComponent {
  entityName: string | null = 'contact';
  recordId:   string | null = 'rec-1';
  maxSizeBytes = 10 * 1024 * 1024;
  form = new FormGroup({ passport_scan: new FormControl<string | null>(null) });
}

function makeDoc(name = 'passport_scan.pdf', type = 'application/pdf', size = 5): File {
  return new File(['x'.repeat(size)], name, { type });
}

/** Yields to the macrotask queue until `predicate` holds — the pipeline's
 *  checksum digest and create-session call are genuinely async. */
async function waitFor(predicate: () => boolean, attempts = 50): Promise<void> {
  for (let i = 0; i < attempts; i++) {
    if (predicate()) return;
    await new Promise(resolve => setTimeout(resolve, 0));
  }
  throw new Error('waitFor timed out');
}

interface MockFileUploadService {
  createSession:  ReturnType<typeof vi.fn>;
  putToStorage:   ReturnType<typeof vi.fn>;
  finalize:       ReturnType<typeof vi.fn>;
  getStatus:      ReturnType<typeof vi.fn>;
  getDownloadUrl: ReturnType<typeof vi.fn>;
}

describe('AttachmentComponent', () => {
  let fileSvc: MockFileUploadService;

  beforeEach(() => {
    fileSvc = {
      createSession:  vi.fn(),
      putToStorage:   vi.fn(),
      finalize:       vi.fn(),
      getStatus:      vi.fn(),
      getDownloadUrl: vi.fn(() => throwError(() => new Error('no file'))),
    };

    TestBed.configureTestingModule({
      imports: [HostComponent],
      providers: [
        { provide: FileUploadService, useValue: fileSvc },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
  });

  function createFixture(entityName: string | null = 'contact', recordId: string | null = 'rec-1') {
    const fixture = TestBed.createComponent(HostComponent);
    fixture.componentInstance.entityName = entityName;
    fixture.componentInstance.recordId = recordId;
    fixture.detectChanges();
    const cmp = fixture.debugElement.query(By.directive(AttachmentComponent))
      .componentInstance as AttachmentComponent;
    return { fixture, cmp };
  }

  function mockCleanUpload(finalKey: string) {
    fileSvc.createSession.mockReturnValue(of({
      session_id: SESSION_ID_36, upload_url: 'http://storage/put', expires_in_secs: 900,
    }));
    fileSvc.putToStorage.mockReturnValue(of({ type: HttpEventType.Response }));
    fileSvc.finalize.mockReturnValue(of({ session_id: SESSION_ID_36, status: 'uploaded' }));
    fileSvc.getStatus.mockReturnValue(of({
      status: 'clean', reject_reason: null, actual_size_bytes: 5,
      actual_content_type: 'application/pdf', final_key: finalKey,
    }));
  }

  it('gates uploading until the record exists (the upload routes are record-scoped)', () => {
    const { fixture } = createFixture(null, null);
    expect(fixture.nativeElement.textContent).toContain('Save the record before attaching a file.');
    expect(fixture.nativeElement.querySelector('.xat-drop')).toBeNull();
  });

  it('renders the label and the empty drop zone', () => {
    const { fixture } = createFixture();
    expect(fixture.nativeElement.querySelector('.xat-label').textContent).toContain('Passport scan');
    expect(fixture.nativeElement.querySelector('.xat-drop').textContent)
      .toContain('Drag document or click to browse');
    expect(fixture.nativeElement.querySelector('.xat-browse').textContent).toContain('Browse');
  });

  it('runs create-session -> PUT -> finalize -> poll and writes final_key onto the control', async () => {
    const finalKey = `contact/rec-1/passport_scan/${SESSION_ID_36}-passport_scan.pdf`;
    const { fixture, cmp } = createFixture();
    mockCleanUpload(finalKey);

    await cmp.onFileSelected([makeDoc()] as unknown as FileList);

    expect(fileSvc.createSession).toHaveBeenCalledWith(
      'contact', 'rec-1', 'passport_scan',
      expect.objectContaining({ filename: 'passport_scan.pdf', content_type: 'application/pdf' }),
    );
    expect(fileSvc.finalize).toHaveBeenCalledWith(
      'contact', 'rec-1', 'passport_scan', SESSION_ID_36,
    );
    expect(cmp.state()).toBe('idle');
    expect(fixture.componentInstance.form.get('passport_scan')!.value).toBe(finalKey);
    expect(fixture.componentInstance.form.get('passport_scan')!.dirty).toBe(true);
  });

  it('strips the session-id prefix off final_key for display', async () => {
    const finalKey = `contact/rec-1/passport_scan/${SESSION_ID_36}-passport_scan.pdf`;
    const { fixture, cmp } = createFixture();
    mockCleanUpload(finalKey);

    await cmp.onFileSelected([makeDoc()] as unknown as FileList);
    fixture.detectChanges();

    expect(cmp.displayName()).toBe('passport_scan.pdf');
    expect(fixture.nativeElement.querySelector('.xat-name').textContent).toContain('passport_scan.pdf');
  });

  it('shows the in-flight filename and percentage while bytes move', async () => {
    const { fixture, cmp } = createFixture();
    fileSvc.createSession.mockReturnValue(of({
      session_id: SESSION_ID_36, upload_url: 'http://storage/put', expires_in_secs: 900,
    }));
    // Held open, so the uploading row is still on screen when it is asserted —
    // the pipeline's checksum + create-session steps run first.
    const bytes = new Subject<HttpEvent<unknown>>();
    fileSvc.putToStorage.mockReturnValue(bytes);

    const done = cmp.onFileSelected([makeDoc()] as unknown as FileList);
    await waitFor(() => fileSvc.putToStorage.mock.calls.length > 0);

    bytes.next({ type: HttpEventType.UploadProgress, loaded: 65, total: 100 } as HttpEvent<unknown>);
    fixture.detectChanges();

    expect(cmp.state()).toBe('uploading');
    expect(cmp.progress()).toBe(65);
    const row = fixture.nativeElement.querySelector('.xat-row-busy');
    expect(row.textContent).toContain('Uploading passport_scan.pdf');
    expect(row.textContent).toContain('65%');
    expect(row.getAttribute('aria-valuenow')).toBe('65');

    // Let the pipeline settle so the test does not leave a pending promise.
    fileSvc.finalize.mockReturnValue(of({ session_id: SESSION_ID_36, status: 'uploaded' }));
    fileSvc.getStatus.mockReturnValue(of({
      status: 'clean', reject_reason: null, actual_size_bytes: 5,
      actual_content_type: 'application/pdf', final_key: 'k',
    }));
    bytes.next({ type: HttpEventType.Response } as HttpEvent<unknown>);
    await done;
  });

  it('rejects a disallowed content type before any session is created', async () => {
    const { cmp } = createFixture();

    await cmp.onFileSelected([makeDoc('evil.exe', 'application/x-msdownload')] as unknown as FileList);

    expect(fileSvc.createSession).not.toHaveBeenCalled();
    expect(cmp.state()).toBe('error');
    expect(cmp.message()).toContain('not accepted');
  });

  it('rejects an oversized file before any session is created', async () => {
    const fixture = TestBed.createComponent(HostComponent);
    fixture.componentInstance.maxSizeBytes = 1;
    fixture.detectChanges();
    const cmp = fixture.debugElement.query(By.directive(AttachmentComponent))
      .componentInstance as AttachmentComponent;

    await cmp.onFileSelected([makeDoc()] as unknown as FileList);

    expect(fileSvc.createSession).not.toHaveBeenCalled();
    expect(cmp.state()).toBe('error');
    expect(cmp.message()).toContain('too large');
  });

  it('surfaces the scan job reject_reason', async () => {
    const { cmp } = createFixture();
    fileSvc.createSession.mockReturnValue(of({
      session_id: SESSION_ID_36, upload_url: 'http://storage/put', expires_in_secs: 900,
    }));
    fileSvc.putToStorage.mockReturnValue(of({ type: HttpEventType.Response }));
    fileSvc.finalize.mockReturnValue(of({ session_id: SESSION_ID_36, status: 'uploaded' }));
    fileSvc.getStatus.mockReturnValue(of({
      status: 'rejected', reject_reason: 'malware detected', actual_size_bytes: null,
      actual_content_type: null, final_key: null,
    }));

    await cmp.onFileSelected([makeDoc()] as unknown as FileList);

    expect(cmp.state()).toBe('rejected');
    expect(cmp.message()).toBe('malware detected');
    expect(cmp.hasValue()).toBe(false);
  });

  it('offers download only for the value the record was loaded with', async () => {
    const persisted = `contact/rec-1/passport_scan/${SESSION_ID_36}-old.pdf`;
    const fixture = TestBed.createComponent(HostComponent);
    fixture.componentInstance.form.get('passport_scan')!.setValue(persisted);
    fixture.detectChanges(); // ngOnInit sees the already-persisted value
    const cmp = fixture.debugElement.query(By.directive(AttachmentComponent))
      .componentInstance as AttachmentComponent;

    expect(cmp.canDownload()).toBe(true);

    // A freshly uploaded key has no persisted column behind it yet.
    mockCleanUpload(`contact/rec-1/passport_scan/${SESSION_ID_36}-new.pdf`);
    await cmp.onFileSelected([makeDoc('new.pdf')] as unknown as FileList);

    expect(cmp.canDownload()).toBe(false);
  });

  it('opens the presigned URL when downloading', () => {
    fileSvc.getDownloadUrl.mockReturnValue(of({ download_url: 'http://storage/dl', expires_in_secs: 900 }));
    const openSpy = vi.spyOn(window, 'open').mockImplementation(() => null);
    const { cmp } = createFixture();

    cmp.download();

    expect(fileSvc.getDownloadUrl).toHaveBeenCalledWith('contact', 'rec-1', 'passport_scan');
    expect(openSpy).toHaveBeenCalledWith('http://storage/dl', '_blank', 'noopener');
    expect(cmp.downloading()).toBe(false);
    openSpy.mockRestore();
  });

  it('clears the value and marks the control dirty', () => {
    const { fixture, cmp } = createFixture();
    fixture.componentInstance.form.get('passport_scan')!.setValue('some/key');

    cmp.clear();

    expect(fixture.componentInstance.form.get('passport_scan')!.value).toBeNull();
    expect(fixture.componentInstance.form.get('passport_scan')!.dirty).toBe(true);
    expect(cmp.state()).toBe('idle');
  });

  it('renders the versions panel trigger once the record exists', () => {
    const { fixture } = createFixture();
    expect(fixture.nativeElement.querySelector('xrm-file-versions .xfv-trigger')).not.toBeNull();
  });

  it('adopts a restored version as the persisted, downloadable value', () => {
    const { fixture, cmp } = createFixture();
    const restoredKey = `contact/rec-1/passport_scan/${SESSION_ID_36}-old.pdf`;

    cmp.onVersionRestored({ version_no: 1, object_key: restoredKey });
    fixture.detectChanges();

    expect(fixture.componentInstance.form.get('passport_scan')!.value).toBe(restoredKey);
    expect(cmp.canDownload()).toBe(true);
    expect(cmp.displayName()).toBe('old.pdf');
  });
});
