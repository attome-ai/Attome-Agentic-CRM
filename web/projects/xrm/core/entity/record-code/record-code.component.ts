import {
  ChangeDetectionStrategy, Component, computed, input, signal,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { TranslatePipe } from '@attome/base';
import { renderCode, type CodeKind } from '@attome/base/scan';
import type { FieldSchema } from '@attome/xrm';

/** The link a record's QR code carries: entity and id only, so it grants nothing. Pure. */
export function recordLink(origin: string, entity: string, id: string): string {
  return `${origin.replace(/\/+$/, '')}/r/${encodeURIComponent(entity)}/${encodeURIComponent(id)}`;
}

/**
 * B16-T11: "Show code" on a record's header. It draws a QR code of the
 * record's link (`/r/{entity}/{id}`; whoever scans it signs in and the
 * record's own access decides what they see), or a barcode of one of the
 * record's text or number values, as an SVG image that can be downloaded
 * or printed.
 */
@Component({
  selector: 'xrm-record-code',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  template: `
    <button type="button" class="xf-btn xf-btn-secondary" data-testid="record-code" [attr.aria-expanded]="open()"
            (click)="toggle()">
      <i class="las la-qrcode" aria-hidden="true"></i> {{ 'recordCode.show' | translate }}
    </button>
    @if (open()) {
      <div class="rc-panel" role="dialog" [attr.aria-label]="'recordCode.title' | translate" data-testid="record-code-panel">
        <label>{{ 'recordCode.what' | translate }}
          <select [ngModel]="source()" (ngModelChange)="source.set($event); draw()">
            <option value="">{{ 'recordCode.link' | translate }}</option>
            @for (f of valueFields(); track f.name) {
              <option [value]="f.name">{{ f.display_name || f.name }}</option>
            }
          </select>
        </label>
        @if (source()) {
          <label>{{ 'recordCode.kind' | translate }}
            <select [ngModel]="kind()" (ngModelChange)="kind.set($event); draw()">
              @for (k of kinds; track k) { <option [value]="k">{{ 'recordCode.kinds.' + k | translate }}</option> }
            </select>
          </label>
        }
        @if (error(); as e) { <p class="rc-error" role="alert">{{ e | translate }}</p> }
        @if (image(); as src) {
          <img class="rc-image" data-testid="record-code-image" [src]="src" [attr.alt]="'recordCode.alt' | translate" />
          <a class="xf-btn xf-btn-secondary" [href]="src" [attr.download]="fileName()">{{ 'recordCode.download' | translate }}</a>
        }
      </div>
    }
  `,
  styles: [`
    :host { position: relative; display: inline-flex; }
    .rc-panel { position: absolute; inset-block-start: 100%; inset-inline-end: 0; z-index: 20; inline-size: 16rem;
                display: grid; gap: .5rem; padding: .75rem; background: var(--color-bg, #fff);
                border: 1px solid var(--color-border, #ddd); border-radius: 8px; box-shadow: 0 6px 20px var(--color-shadow, rgba(0,0,0,.12)); }
    .rc-panel label { display: grid; gap: .25rem; font-size: .8125rem; }
    .rc-image { inline-size: 100%; background: var(--color-code-bg, #fff); }
    .rc-error { color: var(--color-danger, #c53030); margin: 0; font-size: .8125rem; }
  `],
})
export class RecordCodeComponent {
  readonly entity = input.required<string>();
  readonly recordId = input.required<string>();
  /** The record's fields and current values, for a barcode of a value. */
  readonly fields = input<readonly FieldSchema[]>([]);
  readonly values = input<Readonly<Record<string, unknown>>>({});

  readonly kinds: readonly CodeKind[] = ['qr', 'code128', 'ean13', 'datamatrix'];
  readonly open = signal(false);
  /** `''` is the record's link; else a field name. */
  readonly source = signal('');
  readonly kind = signal<CodeKind>('code128');
  readonly image = signal<string | null>(null);
  readonly error = signal<string | null>(null);

  readonly valueFields = computed(() =>
    this.fields().filter(f => (f.field_type === 'text' || f.field_type === 'number')
      && this.values()[f.name] !== null && this.values()[f.name] !== undefined && this.values()[f.name] !== ''));
  readonly fileName = computed(() => `${this.entity()}-${this.source() || 'link'}.svg`);

  toggle(): void {
    this.open.update(o => !o);
    if (this.open()) this.draw();
  }

  /** Draws the chosen code. */
  async draw(): Promise<void> {
    this.error.set(null);
    const field = this.source();
    const text = field
      ? String(this.values()[field] ?? '')
      : recordLink(typeof location !== 'undefined' ? location.origin : '', this.entity(), this.recordId());
    const kind: CodeKind = field ? this.kind() : 'qr';
    try {
      const svg = await renderCode(kind, text);
      this.image.set(`data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`);
    } catch {
      this.image.set(null);
      this.error.set('recordCode.cannot');
    }
  }
}
