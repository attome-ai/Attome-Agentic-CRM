import {
  ChangeDetectionStrategy, Component, DestroyRef, ElementRef, afterNextRender, computed, inject, input, output,
  signal, viewChild,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { ScanService } from '@attome/base/scan';
import { Subscription } from 'rxjs';

import { EntityService } from '../services/entity.service';

/** A repeat of the same code within this time is the camera seeing it again, not a new scan. */
export const SAME_SCAN_MS = 1500;
/** Accepted scans written per bulk request. */
export const SCAN_BATCH = 20;

/** One code scanned in this session and how many lines it added. */
export interface ScannedLine { value: string; count: number; }

/** A parent link every line carries (`field = value`), as the related grid has it. */
export interface ScanLineLink { field: string; value: string; }

/**
 * B16-T10: continuous scanning into a related grid's lines. The camera
 * stays on; each code read adds a line of the grid's entity with the code
 * in `valueField` and the grid's parent links set, with a short beep. The
 * camera seeing the same code again within 1.5 s is ignored; a code already
 * added asks whether to add it again or skip. Lines are written 20 at a
 * time through the bulk create route, and the rest on Close. A USB or
 * Bluetooth scanner types into the field and ends with Enter.
 */
@Component({
  selector: 'xrm-continuous-scan-dialog',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  template: `
    <div class="cs-backdrop" aria-hidden="true"></div>
    <div class="cs-dialog" role="dialog" aria-modal="true" aria-labelledby="cs-title" data-testid="continuous-scan">
      <header class="cs-head">
        <h3 id="cs-title">{{ 'relatedGrid.scan.title' | translate }}</h3>
        <span class="cs-count" role="status" aria-live="polite" data-testid="scan-count">
          {{ 'relatedGrid.scan.count' | translate: { count: accepted() } }}
        </span>
      </header>
      <video #video class="cs-video" playsinline muted></video>
      <form class="cs-form" (ngSubmit)="typedIn()">
        <label for="cs-value">{{ 'relatedGrid.scan.typeOrScan' | translate }}</label>
        <input id="cs-value" name="value" dir="ltr" autocomplete="off" [ngModel]="typed()" (ngModelChange)="typed.set($event)" />
      </form>
      @if (duplicate(); as d) {
        <div class="cs-duplicate" role="alert" data-testid="scan-duplicate">
          <p>{{ 'relatedGrid.scan.duplicate' | translate: { value: d } }}</p>
          <button type="button" data-testid="scan-add-again" (click)="addAgain()">{{ 'relatedGrid.scan.addAgain' | translate }}</button>
          <button type="button" (click)="skip()">{{ 'relatedGrid.scan.skip' | translate }}</button>
        </div>
      }
      @if (error(); as e) { <p class="cs-error" role="alert">{{ e }}</p> }
      <ul class="cs-lines">
        @for (l of lines(); track l.value) {
          <li><bdi dir="ltr">{{ l.value }}</bdi> <span class="cs-times">× {{ l.count }}</span></li>
        }
      </ul>
      <p class="cs-hint">{{ 'relatedGrid.scan.written' | translate: { count: written(), pending: pendingCount() } }}</p>
      <footer class="cs-foot">
        <button type="button" class="dialog-button dialog-button-primary" data-testid="scan-close" (click)="close()">
          {{ 'relatedGrid.scan.done' | translate }}
        </button>
      </footer>
    </div>
  `,
  styles: [`
    .cs-backdrop { position: fixed; inset: 0; background: rgba(0,0,0,.35); z-index: 1000; }
    .cs-dialog { position: fixed; inset-block-start: 5vh; inset-inline: 0; margin-inline: auto; z-index: 1001;
                 inline-size: min(28rem, 94vw); max-block-size: 90vh; overflow: auto; display: grid; gap: .5rem;
                 padding: 1rem; background: var(--color-bg, #fff); border-radius: 10px; }
    .cs-head { display: flex; justify-content: space-between; align-items: baseline; gap: .5rem; }
    .cs-head h3 { margin: 0; }
    .cs-count { font-weight: 700; }
    .cs-video { inline-size: 100%; border-radius: 6px; background: #000; }
    .cs-form { display: grid; gap: .25rem; }
    .cs-duplicate { display: flex; flex-wrap: wrap; gap: .5rem; align-items: center; padding: .5rem;
                    border-radius: 6px; background: var(--color-warning-bg, #fff4e0); }
    .cs-duplicate p { flex-basis: 100%; margin: 0; }
    .cs-lines { list-style: none; margin: 0; padding: 0; display: grid; gap: .125rem; max-block-size: 10rem; overflow: auto; }
    .cs-times { color: var(--color-text-secondary, #666); }
    .cs-hint { margin: 0; font-size: .8125rem; color: var(--color-text-secondary, #666); }
    .cs-error { color: var(--color-danger, #c53030); margin: 0; }
    .cs-foot { display: flex; justify-content: flex-end; }
  `],
})
export class ContinuousScanDialogComponent {
  private readonly scanner = inject(ScanService);
  private readonly entities = inject(EntityService);
  private readonly lang = inject(LangService);

  /** The lines' entity (the related grid's). */
  readonly entityName = input.required<string>();
  /** The field each code goes into. */
  readonly valueField = input.required<string>();
  /** The parent links each line carries. */
  readonly links = input<readonly ScanLineLink[]>([]);
  /** Closed: how many lines were written. */
  readonly closed = output<number>();

  private readonly video = viewChild<ElementRef<HTMLVideoElement>>('video');
  readonly lines = signal<ScannedLine[]>([]);
  readonly accepted = signal(0);
  readonly written = signal(0);
  readonly duplicate = signal<string | null>(null);
  readonly error = signal<string | null>(null);
  readonly typed = signal('');
  private readonly pending = signal<Record<string, unknown>[]>([]);
  readonly pendingCount = computed(() => this.pending().length);
  private last: { value: string; at: number } | null = null;
  private camera: Subscription | null = null;
  private audio: AudioContext | null = null;

  constructor() {
    afterNextRender(() => this.startCamera());
    inject(DestroyRef).onDestroy(() => this.stopCamera());
  }

  /** One code read: ignored when the camera just saw it, held for a choice when already added. */
  onScan(raw: string): void {
    const value = raw.trim();
    if (!value) return;
    const now = Date.now();
    if (this.last && this.last.value === value && now - this.last.at < SAME_SCAN_MS) {
      this.last = { value, at: now };
      return;
    }
    this.last = { value, at: now };
    if (this.lines().some(l => l.value === value)) {
      this.duplicate.set(value);
      return;
    }
    this.accept(value);
  }

  protected typedIn(): void {
    this.onScan(this.typed());
    this.typed.set('');
  }

  protected addAgain(): void {
    const value = this.duplicate();
    this.duplicate.set(null);
    if (value) this.accept(value);
  }

  protected skip(): void {
    this.duplicate.set(null);
  }

  /** Writes the lines not yet written. */
  flush(): void {
    const batch = this.pending();
    if (batch.length === 0) return;
    this.pending.set([]);
    this.entities.bulkCreate(this.entityName(), batch.map(data => ({ data }))).subscribe({
      next: () => this.written.update(n => n + batch.length),
      error: (e: ApiError) => {
        // Kept for the next flush, so nothing scanned is lost.
        this.pending.update(rest => [...batch, ...rest]);
        this.error.set(this.lang.errorText(e));
      },
    });
  }

  close(): void {
    this.stopCamera();
    this.flush();
    this.closed.emit(this.written() + this.pending().length);
  }

  private accept(value: string): void {
    this.lines.update(list => {
      const at = list.findIndex(l => l.value === value);
      if (at === -1) return [...list, { value, count: 1 }];
      const next = [...list];
      next[at] = { value, count: next[at].count + 1 };
      return next;
    });
    const data: Record<string, unknown> = { [this.valueField()]: value };
    for (const l of this.links()) data[l.field] = l.value;
    this.pending.update(list => [...list, data]);
    this.accepted.update(n => n + 1);
    this.beep();
    if (this.pending().length >= SCAN_BATCH) this.flush();
  }

  /** A short tone for each accepted scan; silent where audio is unavailable. */
  private beep(): void {
    try {
      const Ctx = (globalThis as unknown as { AudioContext?: typeof AudioContext }).AudioContext;
      if (!Ctx) return;
      this.audio ??= new Ctx();
      const osc = this.audio.createOscillator();
      const gain = this.audio.createGain();
      osc.frequency.value = 880;
      gain.gain.value = 0.1;
      osc.connect(gain).connect(this.audio.destination);
      osc.start();
      osc.stop(this.audio.currentTime + 0.08);
    } catch {
      // No sound is not an error.
    }
  }

  private startCamera(): void {
    const video = this.video()?.nativeElement;
    if (!video || !navigator.mediaDevices?.getUserMedia) return;
    this.camera = this.scanner.startCamera(video, { continuous: true }).subscribe({
      next: r => this.onScan(r.rawValue),
      error: () => this.error.set(this.lang.translate('relatedGrid.scan.cameraDenied')),
    });
  }

  private stopCamera(): void {
    this.camera?.unsubscribe();
    this.camera = null;
    this.scanner.stop();
    void this.audio?.close().catch(() => undefined);
    this.audio = null;
  }
}
