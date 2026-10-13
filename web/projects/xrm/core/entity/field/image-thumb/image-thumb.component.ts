import {
  ChangeDetectionStrategy, Component, OnDestroy, effect, inject, input, signal,
} from '@angular/core';
import { Subscription } from 'rxjs';
import { TranslatePipe } from '@attome/base';

import { FileUploadService } from '../file-upload.service';

/**
 * U9 — a small thumbnail of an `image` field's stored object, for list
 * cells. The object key alone is not fetchable: a presigned download URL is
 * asked for (`GET .../files/{field}/download-url`, D-144), which also
 * re-checks the viewer's read access to the record. Nothing is requested
 * when the cell is empty, and a failure shows the placeholder glyph rather
 * than an error — a thumbnail is decoration, the record is still reachable.
 */
@Component({
  selector: 'xrm-image-thumb',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    @if (url(); as src) {
      <img class="xit-img" [src]="src" [alt]="'fieldInput.imageThumbAlt' | translate: { label: label() }"
           loading="lazy" decoding="async" />
    } @else if (value()) {
      <span class="xit-placeholder" aria-hidden="true"><i class="las la-image"></i></span>
    }
  `,
  styles: [`
    :host { display: inline-flex; align-items: center; }
    .xit-img, .xit-placeholder {
      inline-size: 32px; block-size: 32px; border-radius: 6px;
      object-fit: cover; display: inline-flex; align-items: center; justify-content: center;
      background: var(--xf-hover, #f4f4f5);
    }
  `],
})
export class ImageThumbComponent implements OnDestroy {
  readonly entityName = input.required<string>();
  readonly recordId   = input.required<string>();
  readonly fieldName  = input.required<string>();
  /** The stored object key — only its presence matters here. */
  readonly value      = input<unknown>(null);
  readonly label      = input('');

  private readonly fileSvc = inject(FileUploadService);
  readonly url = signal<string | null>(null);
  private sub?: Subscription;

  constructor() {
    effect(() => {
      const entity = this.entityName();
      const id     = this.recordId();
      const field  = this.fieldName();
      const value  = this.value();
      this.sub?.unsubscribe();
      this.url.set(null);
      if (!value || !entity || !id) return;
      this.sub = this.fileSvc.getDownloadUrl(entity, id, field).subscribe({
        next:  res => this.url.set(res.download_url),
        error: () => this.url.set(null),
      });
    });
  }

  ngOnDestroy(): void { this.sub?.unsubscribe(); }
}
