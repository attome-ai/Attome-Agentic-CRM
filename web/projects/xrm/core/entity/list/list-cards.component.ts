import { ChangeDetectionStrategy, Component, computed, input, output, signal } from '@angular/core';
import { TranslatePipe } from '@attome/base';
import type { EntityRecord } from '@attome/xrm';

/** A swipe action (`view_metadata.mobile`, B17-T6). */
export type SwipeAction = 'call' | 'complete' | 'assign' | 'open';

/** A phone list's settings from its view. */
export interface MobileListOptions {
  card_title?: string | null;
  card_lines?: string[];
  swipe_start?: SwipeAction | null;
  swipe_end?: SwipeAction | null;
}

const ACTIONS: readonly SwipeAction[] = ['call', 'complete', 'assign', 'open'];
/** How far a finger must travel, in pixels, for a swipe to count. */
export const SWIPE_DISTANCE = 72;

/** A view's phone settings, or none; anything malformed is dropped. Pure. */
export function mobileOptions(viewMetadata: unknown): MobileListOptions | null {
  const raw = (viewMetadata as { mobile?: unknown } | null | undefined)?.mobile;
  if (!raw || typeof raw !== 'object') return null;
  const m = raw as Record<string, unknown>;
  const action = (v: unknown): SwipeAction | null =>
    typeof v === 'string' && (ACTIONS as readonly string[]).includes(v) ? (v as SwipeAction) : null;
  return {
    card_title: typeof m['card_title'] === 'string' ? m['card_title'] : null,
    card_lines: Array.isArray(m['card_lines'])
      ? (m['card_lines'] as unknown[]).filter((l): l is string => typeof l === 'string').slice(0, 3)
      : undefined,
    swipe_start: action(m['swipe_start']),
    swipe_end: action(m['swipe_end']),
  };
}

/**
 * Which side a horizontal drag went, in the list's own writing direction:
 * toward the inline end (right in LTR, left in RTL) or the inline start.
 * `null` for a drag too short to count. Pure.
 */
export function swipeSide(dx: number, rtl: boolean): 'start' | 'end' | null {
  if (Math.abs(dx) < SWIPE_DISTANCE) return null;
  const towardRight = dx > 0;
  return towardRight !== rtl ? 'end' : 'start';
}

/**
 * B17-T6: a list as cards for a phone — the title and up to three lines per
 * record (the view's `mobile.card_title` / `card_lines`, else the first
 * column and the next two), and a swipe toward either side running the
 * view's `swipe_start` / `swipe_end`. Directions follow the writing
 * direction, so Arabic mirrors without a special case.
 */
@Component({
  selector: 'xrm-list-cards',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <ul class="lc" data-testid="list-cards">
      @for (row of records(); track row.id) {
        <li class="lc-card" data-testid="list-card"
            [style.transform]="dragging() === row.id ? 'translateX(' + offset() + 'px)' : null"
            (pointerdown)="down($event, row)" (pointermove)="move($event, row)"
            (pointerup)="up($event, row)" (pointercancel)="cancel()">
          <button type="button" class="lc-open" (click)="activate.emit({ action: 'open', record: row })">
            <strong class="lc-title">{{ text(row, titleField()) }}</strong>
            @for (line of lineFields(); track line) {
              @if (text(row, line)) { <span class="lc-line">{{ text(row, line) }}</span> }
            }
          </button>
        </li>
      } @empty {
        <li class="lc-empty">{{ 'entityList.noRecords' | translate }}</li>
      }
    </ul>
  `,
  styles: [`
    .lc { list-style: none; margin: 0; padding: 0; display: grid; gap: 8px; touch-action: pan-y; }
    .lc-card { border: 1px solid var(--color-border); border-radius: 10px; background: var(--color-bg);
               transition: transform .15s; }
    .lc-open { inline-size: 100%; display: grid; gap: 2px; text-align: start; background: none; border: none;
               padding-block: 10px; padding-inline: 12px; color: var(--color-text-primary); font: inherit; cursor: pointer; }
    .lc-title { font-size: 15px; }
    .lc-line { font-size: 13px; color: var(--color-text-secondary); }
    .lc-empty { color: var(--color-text-secondary); padding-block: 12px; }
  `],
})
export class ListCardsComponent {
  readonly records = input.required<EntityRecord[]>();
  /** The list's column names, in order (the default title and lines). */
  readonly columns = input<string[]>([]);
  readonly options = input<MobileListOptions | null>(null);
  readonly rtl = input(false);

  /** A swipe or a tap: the action and the record. */
  readonly activate = output<{ action: SwipeAction; record: EntityRecord }>();

  readonly titleField = computed(() => this.options()?.card_title || this.columns()[0] || 'id');
  readonly lineFields = computed(() => {
    const lines = this.options()?.card_lines;
    if (lines?.length) return lines;
    return this.columns().filter(c => c !== this.titleField()).slice(0, 2);
  });

  readonly dragging = signal<string | null>(null);
  readonly offset = signal(0);
  private startX = 0;

  text(row: EntityRecord, field: string): string {
    const v = row.data?.[field];
    return v === null || v === undefined ? '' : String(v);
  }

  down(event: PointerEvent, row: EntityRecord): void {
    this.startX = event.clientX;
    this.dragging.set(row.id);
    this.offset.set(0);
  }

  move(event: PointerEvent, row: EntityRecord): void {
    if (this.dragging() !== row.id) return;
    this.offset.set(event.clientX - this.startX);
  }

  up(event: PointerEvent, row: EntityRecord): void {
    if (this.dragging() !== row.id) return;
    const side = swipeSide(event.clientX - this.startX, this.rtl());
    this.cancel();
    const action = side === 'end' ? this.options()?.swipe_end : side === 'start' ? this.options()?.swipe_start : null;
    if (action) this.activate.emit({ action, record: row });
  }

  cancel(): void {
    this.dragging.set(null);
    this.offset.set(0);
  }
}
