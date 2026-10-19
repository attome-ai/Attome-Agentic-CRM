import {
  ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, effect, inject, signal,
} from '@angular/core';
import { NavigationEnd, Router } from '@angular/router';
import { LangService, TourService, TranslatePipe, localText } from '@attome/base';
import { filter } from 'rxjs';

/** Where the bubble goes, in viewport pixels. */
export interface BubblePlace {
  top: number;
  left: number;
}

const GAP = 12;
const BUBBLE_WIDTH = 320;

/**
 * Places a bubble of `width` beside `target` on `placement`'s side, inside
 * the viewport; `start`/`end` follow the text direction. Pure.
 */
export function placeBubble(
  target: { top: number; left: number; width: number; height: number } | null,
  placement: string | undefined,
  rtl: boolean,
  viewport: { width: number; height: number },
  width = BUBBLE_WIDTH,
  height = 160,
): BubblePlace {
  const clampLeft = (x: number) => Math.max(GAP, Math.min(x, viewport.width - width - GAP));
  const clampTop = (y: number) => Math.max(GAP, Math.min(y, viewport.height - height - GAP));
  if (!target) {
    return { top: clampTop((viewport.height - height) / 2), left: clampLeft((viewport.width - width) / 2) };
  }
  const side = placement === 'start' ? (rtl ? 'right' : 'left')
    : placement === 'end' ? (rtl ? 'left' : 'right')
    : placement === 'top' ? 'top' : 'bottom';
  switch (side) {
    case 'top': return { top: clampTop(target.top - height - GAP), left: clampLeft(target.left) };
    case 'left': return { top: clampTop(target.top), left: clampLeft(target.left - width - GAP) };
    case 'right': return { top: clampTop(target.top), left: clampLeft(target.left + target.width + GAP) };
    default: return { top: clampTop(target.top + target.height + GAP), left: clampLeft(target.left) };
  }
}

/**
 * B14-T1: shows the running guided tour: a ring around the step's element,
 * and a bubble beside it with the step's text in the page language, the
 * step count and back / next / skip. Starts a route's tour by itself after
 * a navigation (once per person, `TourService`). A step whose element is
 * not on the page shows its bubble in the middle.
 */
@Component({
  selector: 'xrm-tour-overlay',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    @if (view(); as v) {
      @if (v.ring; as r) {
        <div class="to-ring" aria-hidden="true"
             [style.top.px]="r.top - 4" [style.left.px]="r.left - 4"
             [style.width.px]="r.width + 8" [style.height.px]="r.height + 8"></div>
      }
      <section class="to-bubble" role="dialog" aria-modal="false" [attr.aria-label]="v.tourTitle"
               [style.top.px]="v.place.top" [style.left.px]="v.place.left" data-tour-bubble>
        <header class="to-head">
          <strong>{{ v.title }}</strong>
          <button type="button" class="to-close" (click)="tours.finish()"
                  [attr.aria-label]="'tour.skip' | translate"><i class="las la-times" aria-hidden="true"></i></button>
        </header>
        <p class="to-text" data-tour-text>{{ v.text }}</p>
        <footer class="to-foot">
          <small class="to-count">{{ 'tour.stepOf' | translate: { step: v.step, total: v.total } }}</small>
          <span class="to-actions">
            @if (v.step > 1) {
              <button type="button" (click)="tours.back()" data-tour-back>{{ 'tour.back' | translate }}</button>
            }
            <button type="button" class="to-primary" (click)="tours.next()" data-tour-next>
              {{ (v.step === v.total ? 'tour.done' : 'tour.next') | translate }}
            </button>
          </span>
        </footer>
      </section>
    }
  `,
  styles: [`
    .to-ring { position: fixed; z-index: 1000; pointer-events: none; border-radius: 0.5rem;
      box-shadow: 0 0 0 3px var(--color-primary), 0 0 0 9999px var(--color-backdrop, rgb(0 0 0 / 0.35)); }
    .to-bubble { position: fixed; z-index: 1001; inline-size: min(20rem, calc(100vw - 1.5rem));
      background: var(--color-bg); color: var(--color-text); border: 1px solid var(--color-border);
      border-radius: 0.75rem; padding-block: 0.75rem; padding-inline: 1rem;
      box-shadow: 0 8px 24px var(--color-shadow, rgb(0 0 0 / 0.2)); display: flex; flex-direction: column; gap: 0.5rem; }
    .to-head, .to-foot { display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; }
    .to-close { background: none; border: none; cursor: pointer; color: inherit; }
    .to-text { margin: 0; line-height: 1.5; }
    .to-count { color: var(--color-text-secondary); }
    .to-actions { display: flex; gap: 0.5rem; }
    .to-primary { font-weight: 600; }
  `],
})
export class TourOverlayComponent implements OnInit {
  readonly tours = inject(TourService);
  private readonly lang = inject(LangService);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);

  /** Bumped on resize and scroll so the ring follows its element. */
  private readonly layout = signal(0);

  readonly view = computed(() => {
    this.layout();
    const active = this.tours.active();
    const step = this.tours.step();
    if (!active || !step) return null;
    const lang = this.lang.current();
    const element = typeof document !== 'undefined' ? document.querySelector(step.selector) : null;
    const rect = element?.getBoundingClientRect() ?? null;
    const ring = rect ? { top: rect.top, left: rect.left, width: rect.width, height: rect.height } : null;
    const viewport = typeof window !== 'undefined'
      ? { width: window.innerWidth, height: window.innerHeight }
      : { width: 1024, height: 768 };
    return {
      ring,
      place: placeBubble(ring, step.placement, this.lang.isRtl(), viewport),
      tourTitle: localText(active.tour.title, lang),
      title: localText(step.title, lang) || localText(active.tour.title, lang),
      text: localText(step.text, lang),
      step: active.step + 1,
      total: active.tour.steps.length,
    };
  });

  constructor() {
    // The element may be off screen: bring it into view when a step opens.
    effect(() => {
      const step = this.tours.step();
      if (step && typeof document !== 'undefined') {
        document.querySelector(step.selector)?.scrollIntoView?.({ block: 'center', inline: 'nearest' });
        this.layout.update(n => n + 1);
      }
    });
  }

  ngOnInit(): void {
    void this.tours.onNavigate(this.router.url).catch(() => undefined);
    const sub = this.router.events
      .pipe(filter((e): e is NavigationEnd => e instanceof NavigationEnd))
      .subscribe(e => void this.tours.onNavigate(e.urlAfterRedirects).catch(() => undefined));
    const relayout = () => this.layout.update(n => n + 1);
    if (typeof window !== 'undefined') {
      window.addEventListener('resize', relayout);
      window.addEventListener('scroll', relayout, true);
    }
    this.destroyRef.onDestroy(() => {
      sub.unsubscribe();
      if (typeof window !== 'undefined') {
        window.removeEventListener('resize', relayout);
        window.removeEventListener('scroll', relayout, true);
      }
    });
  }
}
