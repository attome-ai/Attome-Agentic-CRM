import { ChangeDetectionStrategy, Component, inject, input } from '@angular/core';
import { LangService, LocalDatePipe, LocalNumberPipe } from '@attome/base';

import type {
  ColumnFormat,
  DeclarativeWidgetColumn,
  DeclarativeWidgetConfig,
  LinkSpec,
} from './declarative-widget.types';
import { isSafeLinkTarget, resolveConditionalColor, substitutePlaceholders } from './declarative-widget.util';

/**
 * Renders a `declarative_widget`'s already-fetched query rows according to
 * its validated config — columns, per-column formatting, conditional
 * colors and links (M67 Phase 1, Step 1 only; see the
 * backend crate's `declarative_widget.rs` doc comment for the Step 2
 * boundary this component never crosses).
 *
 * **The one property this component exists to guarantee: no config string
 * — a label, a format pattern, a link template, a row value — is ever
 * interpreted as HTML.** Every dynamic value reaches the DOM through Angular
 * `{{ }}` text interpolation (auto-escaped) or a sanitized property binding
 * (`[href]`, `[style.*]`); this file contains no `[innerHTML]`,
 * `bypassSecurityTrustHtml`, `bypassSecurityTrustUrl`, `bypassSecurityTrustStyle`,
 * or `document.write`. See this directory's `.spec.ts` for the executable
 * proof. Data fetching (resolving `config.query_ref` via `QueryService`) is
 * the host page's job, same separation `attome-report`'s own
 * `WidgetRendererComponent` already uses between fetch and render — this
 * component is pure `config + rows -> DOM`, which is also what makes the
 * injection proof exhaustive rather than incidental.
 */
@Component({
  selector: 'xrm-declarative-widget-renderer',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  providers: [LocalNumberPipe, LocalDatePipe],
  styleUrls: ['./declarative-widget-renderer.component.css'],
  templateUrl: './declarative-widget-renderer.component.html',
})
export class DeclarativeWidgetRendererComponent {
  private readonly lang = inject(LangService);
  private readonly localNumber = inject(LocalNumberPipe);
  private readonly localDate = inject(LocalDatePipe);

  readonly config = input.required<DeclarativeWidgetConfig>();
  readonly rows = input<Record<string, unknown>[]>([]);
  readonly loading = input(false);
  readonly error = input<string | null>(null);
  readonly emptyMessage = input('No records found.');

  // Dashboard 10/10 Phase 4.5: an `action` link renders as plain text. No host
  // ever invoked the action it named, so a button would promise something
  // that never happens; publish warns about such a config instead. In-place
  // actions arrive with Phase 6 through the authoritative Approval and State
  // routes.

  columnLabel(column: DeclarativeWidgetColumn): string {
    return this.lang.current() === 'ar' && column.label_ar ? column.label_ar : column.label;
  }

  cellDisplay(row: Record<string, unknown>, column: DeclarativeWidgetColumn): string {
    const raw = row[column.field];
    const format: ColumnFormat = column.format ?? { kind: 'text' };
    switch (format.kind) {
      case 'number': {
        const n = typeof raw === 'number' ? raw : Number(raw);
        if (raw === null || raw === undefined || raw === '') return '';
        if (Number.isNaN(n)) return String(raw);
        const options =
          format.decimals != null
            ? { minimumFractionDigits: format.decimals, maximumFractionDigits: format.decimals }
            : undefined;
        return this.localNumber.transform(n, options);
      }
      case 'currency': {
        const n = typeof raw === 'number' ? raw : Number(raw);
        if (raw === null || raw === undefined || raw === '') return '';
        if (Number.isNaN(n)) return String(raw);
        return this.localNumber.transform(n, { style: 'currency', currency: format.currency_code ?? 'USD' });
      }
      case 'date': {
        if (raw === null || raw === undefined || raw === '') return '';
        const dateStyle = mapDateStyle(format.pattern);
        try {
          return this.localDate.transform(raw as string | number | Date, dateStyle ? { dateStyle } : undefined);
        } catch {
          return String(raw);
        }
      }
      case 'badge':
      case 'text':
      default:
        return raw === null || raw === undefined ? '' : String(raw);
    }
  }

  cellColor(row: Record<string, unknown>, column: DeclarativeWidgetColumn): string | null {
    return resolveConditionalColor(row, column.conditional_colors);
  }

  /** Same `color-mix()` tinted-background technique
   * `xrm-choice-pill.component.ts` already uses — kept identical so a
   * declarative widget's colored cells match the rest of the design system
   * rather than inventing a second "colored chip" look. */
  cellBackground(color: string | null): string | null {
    return color ? `color-mix(in srgb, ${color} 16%, transparent)` : null;
  }

  linkKind(column: DeclarativeWidgetColumn): LinkSpec['kind'] | null {
    return column.link?.kind ?? null;
  }

  /** `null` when the column has no external link, or when the resolved
   * target fails [`isSafeLinkTarget`] (fail-safe: render as plain text
   * rather than a possibly-unsafe link) — re-checked here independent of
   * the backend's own write-time check (`validate_link_target`), so a
   * config from any source still cannot produce a `javascript:`/`data:`
   * `href`. */
  externalHref(row: Record<string, unknown>, column: DeclarativeWidgetColumn): string | null {
    if (column.link?.kind !== 'external') return null;
    const resolved = substitutePlaceholders(column.link.target, row);
    return isSafeLinkTarget(resolved) ? resolved : null;
  }

}

/** A tiny, closed allow-list — the backend's own `format.pattern` is a free
 * (but character-restricted) string admins may type, and the only shapes
 * this renderer actually understands are `Intl.DateTimeFormat`'s four named
 * styles. Anything else falls back to the locale default rather than being
 * interpreted as a format mini-language. */
function mapDateStyle(pattern: string | undefined): 'short' | 'medium' | 'long' | 'full' | undefined {
  if (!pattern) return undefined;
  const normalized = pattern.trim().toLowerCase();
  return (['short', 'medium', 'long', 'full'] as const).find(style => style === normalized);
}
