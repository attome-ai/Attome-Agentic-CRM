import { TestBed } from '@angular/core/testing';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';

import { ImageThumbComponent } from './image-thumb.component';
import { FileUploadService } from '../file-upload.service';

describe('ImageThumbComponent', () => {
  let getDownloadUrl: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    getDownloadUrl = vi.fn(() => of({ download_url: 'https://store.example/thumb.png' }));
    TestBed.configureTestingModule({
      imports: [ImageThumbComponent],
      providers: [
        { provide: FileUploadService, useValue: { getDownloadUrl } },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
  });

  function create(value: unknown) {
    const fixture = TestBed.createComponent(ImageThumbComponent);
    fixture.componentRef.setInput('entityName', 'account');
    fixture.componentRef.setInput('recordId', 'rec-1');
    fixture.componentRef.setInput('fieldName', 'logo');
    fixture.componentRef.setInput('label', 'Logo');
    fixture.componentRef.setInput('value', value);
    fixture.detectChanges();
    return fixture;
  }

  it('asks for a presigned URL and renders the thumbnail', () => {
    const fixture = create('account/rec-1/logo/k-logo.png');
    expect(getDownloadUrl).toHaveBeenCalledWith('account', 'rec-1', 'logo');
    const img = fixture.nativeElement.querySelector('img') as HTMLImageElement;
    expect(img.getAttribute('src')).toBe('https://store.example/thumb.png');
    expect(img.getAttribute('alt')).toBe('fieldInput.imageThumbAlt');
  });

  it('requests nothing for an empty cell', () => {
    const fixture = create(null);
    expect(getDownloadUrl).not.toHaveBeenCalled();
    expect(fixture.nativeElement.querySelector('img')).toBeNull();
    expect(fixture.nativeElement.querySelector('.xit-placeholder')).toBeNull();
  });

  it('shows the placeholder when the URL cannot be had', () => {
    getDownloadUrl.mockReturnValue(throwError(() => new Error('403')));
    const fixture = create('account/rec-1/logo/k-logo.png');
    expect(fixture.nativeElement.querySelector('img')).toBeNull();
    expect(fixture.nativeElement.querySelector('.xit-placeholder')).not.toBeNull();
  });
});
