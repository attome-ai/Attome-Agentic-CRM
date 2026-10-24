import {
  ChangeDetectionStrategy, Component, DestroyRef, ElementRef, inject, output, signal, viewChild,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { ApiError, ApiService, LangService, Page, TranslatePipe } from '@attome/base';
import { ScanService } from '@attome/base/scan';
import { entityFormRoute } from '@attome/xrm/core/entity';
import { Subscription, catchError, of } from 'rxjs';

/** A record a scanned code points at (`GET /api/v1/scan/find`, `ScanHit`). */
export interface ScanHit {
  entity: string;
  id: string;
  name?: string | null;
  attribute: string;
}

/**
 * B16-T6: scan-to-find in the command palette. The button opens the rear
 * camera (`ScanService`, `@attome/base/scan`); a USB or Bluetooth scanner
 * types into the field instead and ends with Enter. The code goes to
 * `GET /api/v1/scan/find`, which answers with the readable records holding
 * it: one opens straight away, several are listed to pick from, none says
 * so. `done` tells the palette to close after a record opens.
 */
@Component({
  selector: 'xrm-scan-find',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  template: `
    <button type="button" class="sf-button" data-testid="scan-find" [attr.aria-label]="'shell.scan.button' | translate"
            [attr.aria-expanded]="open()" (click)="toggle()">
      <i class="las la-barcode" aria-hidden="true"></i>
    </button>
    @if (open()) {
      <div class="sf-panel" role="dialog" [attr.aria-label]="'shell.scan.title' | translate" data-testid="scan-panel">
        <video #video class="sf-video" playsinline muted [hidden]="!cameraOn()"></video>
        <form class="sf-form" (ngSubmit)="find(typed())">
          <label for="sf-value">{{ 'shell.scan.typeOrScan' | translate }}</label>
          <input id="sf-value" name="value" dir="ltr" autocomplete="off" data-testid="scan-value"
                 [ngModel]="typed()" (ngModelChange)="typed.set($event)" />
          <button type="submit" [disabled]="!typed().trim() || busy()">{{ 'shell.scan.find' | translate }}</button>
          <button type="button" (click)="startCamera()" [disabled]="cameraOn()">{{ 'shell.scan.camera' | translate }}</button>
        </form>
        @if (message(); as m) { <p class="sf-message" role="status" data-testid="scan-message">{{ m | translate }}</p> }
        @if (hits().length > 1) {
          <ul class="sf-hits" data-testid="scan-hits">
            @for (h of hits(); track h.entity + h.id) {
              <li><button type="button" (click)="openHit(h)">{{ h.name || h.id }} <span class="sf-sub">{{ h.entity }}</span></button></li>
            }
          </ul>
        }
      </div>
    }
  `,
  styles: [`
    :host { position: relative; display: inline-flex; }
    .sf-button { background: none; border: none; cursor: pointer; padding: 0 .375rem; font-size: 1.25rem; color: inherit; }
    .sf-panel { position: absolute; inset-block-start: 100%; inset-inline-end: 0; z-index: 10; inline-size: min(22rem, 90vw);
                padding: .75rem; display: grid; gap: .5rem; background: var(--color-bg, #fff);
                border: 1px solid var(--color-border, #ddd); border-radius: 8px; box-shadow: 0 6px 20px var(--color-shadow, rgba(0,0,0,.12)); }
    .sf-video { inline-size: 100%; border-radius: 6px; background: var(--color-media-bg, #000); }
    .sf-form { display: flex; flex-wrap: wrap; gap: .375rem; align-items: center; }
    .sf-form label { flex-basis: 100%; font-size: .8125rem; }
    .sf-form input { flex: 1; min-inline-size: 8rem; }
    .sf-hits { list-style: none; margin: 0; padding: 0; display: grid; gap: .25rem; }
    .sf-hits button { inline-size: 100%; text-align: start; background: none; border: 1px solid var(--color-border, #ddd);
                      border-radius: 6px; padding: .375rem .5rem; cursor: pointer; }
    .sf-sub { color: var(--color-text-secondary, #666); font-size: .75rem; margin-inline-start: .375rem; }
    .sf-message { margin: 0; font-size: .875rem; }
  `],
})
export class ScanFindComponent {
  private readonly api = inject(ApiService);
  private readonly scanner = inject(ScanService);
  private readonly router = inject(Router);
  private readonly lang = inject(LangService);

  /** A record opened: the palette closes. */
  readonly done = output<void>();

  private readonly video = viewChild<ElementRef<HTMLVideoElement>>('video');
  protected readonly open = signal(false);
  protected readonly cameraOn = signal(false);
  protected readonly typed = signal('');
  protected readonly busy = signal(false);
  protected readonly hits = signal<ScanHit[]>([]);
  protected readonly message = signal<string | null>(null);
  private camera: Subscription | null = null;

  constructor() {
    inject(DestroyRef).onDestroy(() => this.stopCamera());
  }

  protected toggle(): void {
    if (this.open()) this.close();
    else this.open.set(true);
  }

  protected startCamera(): void {
    const video = this.video()?.nativeElement;
    if (!video) return;
    this.cameraOn.set(true);
    this.message.set(null);
    this.camera = this.scanner.startCamera(video, { continuous: false }).subscribe({
      next: result => {
        this.stopCamera();
        this.find(result.rawValue);
      },
      error: () => {
        this.stopCamera();
        this.message.set('shell.scan.cameraDenied');
      },
    });
  }

  /** Looks a scanned or typed value up. */
  find(value: string): void {
    const code = value.trim();
    if (!code) return;
    this.busy.set(true);
    this.message.set(null);
    this.hits.set([]);
    this.api.get<Page<ScanHit>>('/api/v1/scan/find', { value: code }).pipe(
      catchError((e: unknown) => {
        this.busy.set(false);
        this.message.set((e as ApiError).status === 404 ? 'shell.scan.off' : this.lang.errorText(e as ApiError));
        return of(null);
      }),
    ).subscribe(page => {
      if (!page) return;
      this.busy.set(false);
      if (page.items.length === 1) this.openHit(page.items[0]);
      else if (page.items.length === 0) this.message.set('shell.scan.noMatch');
      else this.hits.set(page.items);
    });
  }

  protected openHit(hit: ScanHit): void {
    void this.router.navigate(entityFormRoute(hit.entity), { queryParams: { id: hit.id } });
    this.close();
    this.done.emit();
  }

  private close(): void {
    this.stopCamera();
    this.open.set(false);
    this.hits.set([]);
    this.message.set(null);
    this.typed.set('');
  }

  private stopCamera(): void {
    this.camera?.unsubscribe();
    this.camera = null;
    this.scanner.stop();
    this.cameraOn.set(false);
  }
}
