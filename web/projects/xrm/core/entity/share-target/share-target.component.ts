import { ChangeDetectionStrategy, Component, inject, OnInit, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { AuthService, TranslatePipe } from '@attome/base';
import { FileUploadService } from '../field/file-upload.service';
import { UploadPipeline } from '../field/upload-pipeline';
import { EntityService } from '../services/entity.service';
import { firstValueFrom } from 'rxjs';

/** What the service worker (`src/sw.js`) kept from a share. */
interface SharedMeta {
  title: string;
  text: string;
  url: string;
  files: { name: string; type: string }[];
}

const SHARE_CACHE = 'attome-share';
const SHARE_PATH = '/share-target';
const DOCUMENT_ENTITY = 'attome_document';
/** The folder shared files land in, on the person's own user record. */
const SHARED_FOLDER = 'shared';

type FileState = 'waiting' | 'saving' | 'saved' | 'failed';

/**
 * B19-T2 — the share target's landing page. Another app shared files into
 * Attome; the service worker kept them, and this page saves each one as a
 * document in the "shared" folder of the person's own record, through the
 * same upload path every document takes (a document row, an upload session
 * scoped to it, the virus scan, then its file key). The kept copies are
 * removed once saved or dismissed.
 */
@Component({
  selector: 'xrm-share-target',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe, RouterLink],
  template: `
    <section class="share" data-share>
      <h2>{{ 'shareTarget.title' | translate }}</h2>
      @if (loading()) {
        <p>{{ 'shareTarget.loading' | translate }}</p>
      } @else if (!files().length) {
        <p data-share-empty>{{ 'shareTarget.empty' | translate }}</p>
      } @else {
        @if (meta()?.text || meta()?.url) {
          <p class="share-text">{{ meta()?.text }} {{ meta()?.url }}</p>
        }
        <ul class="share-files">
          @for (file of files(); track $index; let i = $index) {
            <li [attr.data-share-file]="file.name">
              <span>{{ file.name }}</span>
              <span class="share-state">{{ ('shareTarget.state.' + states()[i]) | translate }}</span>
            </li>
          }
        </ul>
        @if (done()) {
          <p role="status" data-share-done>{{ 'shareTarget.done' | translate }}</p>
          <a routerLink="/xrm/documents">{{ 'shareTarget.openDocuments' | translate }}</a>
        } @else {
          <div class="share-actions">
            <button type="button" (click)="save()" [disabled]="saving()" data-share-save>
              {{ 'shareTarget.save' | translate }}
            </button>
            <button type="button" (click)="dismiss()" [disabled]="saving()" data-share-dismiss>
              {{ 'shareTarget.dismiss' | translate }}
            </button>
          </div>
        }
      }
    </section>
  `,
  styles: [`
    :host { display: block; padding: 16px; }
    .share-files { list-style: none; padding: 0; }
    .share-files li { display: flex; gap: 12px; padding-block: 6px; }
    .share-state { margin-inline-start: auto; font-size: 13px; }
    .share-actions { display: flex; gap: 8px; }
  `],
})
export class ShareTargetComponent implements OnInit {
  private readonly auth = inject(AuthService);
  private readonly entities = inject(EntityService);
  private readonly pipeline = new UploadPipeline(inject(FileUploadService));

  readonly loading = signal(true);
  readonly meta = signal<SharedMeta | null>(null);
  readonly files = signal<File[]>([]);
  readonly states = signal<FileState[]>([]);
  readonly saving = signal(false);
  readonly done = signal(false);

  async ngOnInit(): Promise<void> {
    try {
      const cache = await caches.open(SHARE_CACHE);
      const metaResponse = await cache.match(`${SHARE_PATH}/meta`);
      if (metaResponse) {
        const meta = (await metaResponse.json()) as SharedMeta;
        const files: File[] = [];
        for (const [i, f] of meta.files.entries()) {
          const body = await cache.match(`${SHARE_PATH}/file/${i}`);
          if (body) files.push(new File([await body.blob()], f.name, { type: f.type }));
        }
        this.meta.set(meta);
        this.files.set(files);
        this.states.set(files.map(() => 'waiting'));
      }
    } catch {
      // No Cache Storage (a private window): nothing was kept to show.
    }
    this.loading.set(false);
  }

  async save(): Promise<void> {
    const me = this.auth.userId();
    if (!me) return;
    this.saving.set(true);
    const files = this.files();
    for (const [i, file] of files.entries()) {
      this.setState(i, 'saving');
      try {
        const created = await firstValueFrom(this.entities.create(DOCUMENT_ENTITY, {
          name: file.name, entity_name: 'user_account', record_id: me, folder: SHARED_FOLDER,
        }));
        const result = await this.pipeline.run(
          { entityName: DOCUMENT_ENTITY, recordId: created.id, fieldName: 'file' },
          file,
        );
        if (result.kind === 'clean') {
          await firstValueFrom(this.entities.update(DOCUMENT_ENTITY, created.id, { file: result.finalKey }, 0));
          this.setState(i, 'saved');
        } else {
          this.setState(i, 'failed');
        }
      } catch {
        this.setState(i, 'failed');
      }
    }
    this.saving.set(false);
    if (this.states().every(s => s === 'saved')) {
      await this.forget();
      this.done.set(true);
    }
  }

  async dismiss(): Promise<void> {
    await this.forget();
    this.files.set([]);
    this.states.set([]);
  }

  private setState(i: number, state: FileState): void {
    this.states.update(all => all.map((s, j) => (j === i ? state : s)));
  }

  private async forget(): Promise<void> {
    try { await caches.delete(SHARE_CACHE); } catch { /* nothing kept */ }
  }
}
