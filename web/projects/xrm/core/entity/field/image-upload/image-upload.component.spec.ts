import { Component } from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule } from '@angular/forms';
import { TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { HttpEventType } from '@angular/common/http';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';

import { ImageUploadComponent } from './image-upload.component';
import { FileUploadService } from '../file-upload.service';

const SESSION_ID_36 = '00000000-0000-0000-0000-000000000000';

@Component({
  standalone: true,
  imports: [ReactiveFormsModule, ImageUploadComponent],
  template: `
    <form [formGroup]="form">
      <xrm-image-upload fieldName="profile_image"
                        [entityName]="entityName" [recordId]="recordId"
                        [maxSizeBytes]="maxSizeBytes" />
    </form>
  `,
})
class HostComponent {
  entityName: string | null = 'user_account';
  recordId:   string | null = 'rec-1';
  maxSizeBytes = 5 * 1024 * 1024;
  form = new FormGroup({ profile_image: new FormControl<string | null>(null) });
}

function makeImage(type = 'image/png', size = 5): File {
  const file = new File(['x'.repeat(size)], 'avatar.png', { type });
  return file;
}

interface MockFileUploadService {
  createSession:  ReturnType<typeof vi.fn>;
  putToStorage:   ReturnType<typeof vi.fn>;
  finalize:       ReturnType<typeof vi.fn>;
  getStatus:      ReturnType<typeof vi.fn>;
  getDownloadUrl: ReturnType<typeof vi.fn>;
}

describe('ImageUploadComponent', () => {
  let fileSvc: MockFileUploadService;

  beforeEach(() => {
    fileSvc = {
      createSession:  vi.fn(),
      putToStorage:   vi.fn(),
      finalize:       vi.fn(),
      getStatus:      vi.fn(),
      getDownloadUrl: vi.fn(() => throwError(() => new Error('no file'))),
    };
    // jsdom has no object-URL implementation.
    globalThis.URL.createObjectURL = vi.fn(() => 'blob:preview');
    globalThis.URL.revokeObjectURL = vi.fn();

    TestBed.configureTestingModule({
      imports: [HostComponent],
      providers: [
        { provide: FileUploadService, useValue: fileSvc },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
  });

  function createFixture(entityName: string | null = 'user_account', recordId: string | null = 'rec-1') {
    const fixture = TestBed.createComponent(HostComponent);
    fixture.componentInstance.entityName = entityName;
    fixture.componentInstance.recordId = recordId;
    fixture.detectChanges();
    const cmp = fixture.debugElement.query(By.directive(ImageUploadComponent))
      .componentInstance as ImageUploadComponent;
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
      actual_content_type: 'image/png', final_key: finalKey,
    }));
  }

  it('gates uploading until the record exists (the upload routes are record-scoped)', () => {
    const { fixture } = createFixture(null, null);
    expect(fixture.nativeElement.textContent).toContain('Save the record first');
    expect(fixture.nativeElement.querySelector('.xiu-drop')).toBeNull();
  });

  it('shows the wordless upload prompt when no image is set', () => {
    const { fixture, cmp } = createFixture();
    expect(cmp.previewUrl()).toBeNull();
    expect(cmp.pinned()).toBe(false);
    expect(fixture.nativeElement.querySelector('.xiu-ring')).not.toBeNull();
    expect(fixture.nativeElement.querySelector('.xiu-photo')).toBeNull();
    // The resting card carries no copy; the instructions live in the tooltip.
    expect(fixture.nativeElement.querySelector('.xiu-hint')).toBeNull();
    expect(fixture.nativeElement.querySelector('.xiu-drop').getAttribute('title'))
      .toContain('Drag & drop or click to browse');
  });

  it('pins the prompt layer over a photo that is uploaded but not yet saved', async () => {
    const { fixture, cmp } = createFixture();
    mockCleanUpload('user_account/rec-1/profile_image/k');

    await cmp.onFileSelected([makeImage()] as unknown as FileList);
    fixture.detectChanges();

    expect(cmp.pinned()).toBe(true);
    expect(fixture.nativeElement.querySelector('.xiu-photo')).not.toBeNull();
    expect(fixture.nativeElement.querySelector('.xiu-overlay-pinned')).not.toBeNull();
  });

  it('runs create-session -> PUT -> finalize -> poll and writes final_key onto the control', async () => {
    const finalKey = `user_account/rec-1/profile_image/${SESSION_ID_36}-avatar.png`;
    const { fixture, cmp } = createFixture();
    mockCleanUpload(finalKey);

    await cmp.onFileSelected([makeImage()] as unknown as FileList);

    expect(fileSvc.createSession).toHaveBeenCalledWith(
      'user_account', 'rec-1', 'profile_image',
      expect.objectContaining({ filename: 'avatar.png', content_type: 'image/png' }),
    );
    expect(fileSvc.finalize).toHaveBeenCalledWith(
      'user_account', 'rec-1', 'profile_image', SESSION_ID_36,
    );
    expect(cmp.state()).toBe('idle');
    expect(fixture.componentInstance.form.get('profile_image')!.value).toBe(finalKey);
    expect(fixture.componentInstance.form.get('profile_image')!.dirty).toBe(true);
    // Uploaded but not yet persisted on the record.
    expect(cmp.pendingSave()).toBe(true);
  });

  it('previews the chosen file locally while the upload runs', async () => {
    const { cmp } = createFixture();
    mockCleanUpload('user_account/rec-1/profile_image/k');

    await cmp.onFileSelected([makeImage()] as unknown as FileList);

    expect(globalThis.URL.createObjectURL).toHaveBeenCalled();
    expect(cmp.previewUrl()).toBe('blob:preview');
  });

  it('rejects a non-image file before any session is created', async () => {
    const { cmp } = createFixture();

    await cmp.onFileSelected([new File(['x'], 'cv.pdf', { type: 'application/pdf' })] as unknown as FileList);

    expect(fileSvc.createSession).not.toHaveBeenCalled();
    expect(cmp.state()).toBe('error');
    expect(cmp.message()).toContain('not an image');
  });

  it('rejects an oversized image before any session is created', async () => {
    const fixture = TestBed.createComponent(HostComponent);
    fixture.componentInstance.maxSizeBytes = 1;
    fixture.detectChanges();
    const cmp = fixture.debugElement.query(By.directive(ImageUploadComponent))
      .componentInstance as ImageUploadComponent;

    await cmp.onFileSelected([makeImage()] as unknown as FileList);

    expect(fileSvc.createSession).not.toHaveBeenCalled();
    expect(cmp.state()).toBe('error');
    expect(cmp.message()).toContain('too large');
  });

  it('surfaces the scan job reject_reason and drops the local preview', async () => {
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

    await cmp.onFileSelected([makeImage()] as unknown as FileList);

    expect(cmp.state()).toBe('rejected');
    expect(cmp.message()).toBe('malware detected');
    expect(cmp.previewUrl()).toBeNull();
  });

  it('resolves a presigned preview for an image the record already had', () => {
    fileSvc.getDownloadUrl.mockReturnValue(of({ download_url: 'http://storage/dl', expires_in_secs: 900 }));
    const fixture = TestBed.createComponent(HostComponent);
    fixture.componentInstance.form.get('profile_image')!
      .setValue('user_account/rec-1/profile_image/existing');
    fixture.detectChanges(); // ngOnInit sees the already-persisted value
    const cmp = fixture.debugElement.query(By.directive(ImageUploadComponent))
      .componentInstance as ImageUploadComponent;

    expect(fileSvc.getDownloadUrl).toHaveBeenCalledWith('user_account', 'rec-1', 'profile_image');
    expect(cmp.previewUrl()).toBe('http://storage/dl');
    expect(cmp.pendingSave()).toBe(false);
  });

  it('clears the value and marks the control dirty', () => {
    const { fixture, cmp } = createFixture();
    fixture.componentInstance.form.get('profile_image')!.setValue('some/key');

    cmp.clear();

    expect(fixture.componentInstance.form.get('profile_image')!.value).toBeNull();
    expect(fixture.componentInstance.form.get('profile_image')!.dirty).toBe(true);
    expect(cmp.previewUrl()).toBeNull();
  });
});
