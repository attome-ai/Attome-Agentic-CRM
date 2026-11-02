import { ChangeDetectionStrategy, Component, effect, inject, input, signal } from '@angular/core';
import { DecimalPipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { LangService, TranslatePipe } from '@attome/base';

import { MemberExplainDialogComponent } from './member-explain-dialog.component';
import {
  MarketingListCount, MarketingListSample, MarketingListUse, SegmentInsightService,
} from './segment-insight.service';

/**
 * The Segment tab of a marketing list's form (roadmap E7-T12): the list's
 * estimated size, an exact count on request, how many people can be reached
 * for a consent purpose, a sample of up to 20 people the reader may see
 * (each with "why", which opens {@link MemberExplainDialogComponent}), and
 * the sends, programmes and journeys that use the list. Everything is
 * computed by the server as the reader. The list itself, its query and its
 * combinations are edited on the generic form; nothing is hand-coded here.
 * Numbers stay left to right inside Arabic text.
 */
@Component({
  selector: 'xrm-segment-insight-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [DecimalPipe, FormsModule, MemberExplainDialogComponent, TranslatePipe],
  template: `
    <section class="si" [attr.dir]="lang.isRtl() ? 'rtl' : 'ltr'" aria-labelledby="si-title" data-testid="si">
      <h3 id="si-title">{{ 'segmentInsight.title' | translate }}</h3>

      <div class="si-counts">
        <p data-testid="si-count">
          {{ (count()?.basis === 'exact' ? 'segmentInsight.exact' : 'segmentInsight.estimated') | translate }}:
          <span dir="ltr" class="si-number">{{ count()?.count ?? 0 | number }}</span>
        </p>
        <button type="button" class="btn" (click)="exact()" [disabled]="busy()" data-testid="si-exact">
          {{ 'segmentInsight.countExactly' | translate }}
        </button>
      </div>

      <form class="si-reach" (ngSubmit)="reach()">
        <label for="si-purpose">{{ 'segmentInsight.purpose' | translate }}</label>
        <input id="si-purpose" name="purpose" dir="auto" [(ngModel)]="purpose" data-testid="si-purpose" />
        <button type="submit" class="btn" [disabled]="busy() || !purpose.trim()" data-testid="si-reach">
          {{ 'segmentInsight.countReachable' | translate }}
        </button>
        @if (reachable(); as r) {
          <p data-testid="si-reachable">
            {{ 'segmentInsight.reachable' | translate }}
            <bdi>{{ r.purpose }}</bdi>:
            <span dir="ltr" class="si-number">{{ r.count | number }}</span>
          </p>
        }
      </form>

      @if (error()) {
        <p class="si-error" role="alert">{{ 'segmentInsight.failed' | translate }}</p>
      }

      <h4>{{ 'segmentInsight.sample' | translate }}</h4>
      @if (sample(); as s) {
        @if (s.person_ids.length === 0) {
          <p class="si-empty">{{ 'segmentInsight.noSample' | translate }}</p>
        } @else {
          <ul class="si-sample" data-testid="si-sample">
            @for (person of s.person_ids; track person) {
              <li>
                <a [href]="'/xrm/' + s.target_entity + '/' + person" dir="ltr">{{ person }}</a>
                <button type="button" class="btn-link" (click)="explaining.set(person)"
                        data-testid="si-why">{{ 'segmentInsight.why' | translate }}</button>
              </li>
            }
          </ul>
        }
      }

      <h4>{{ 'segmentInsight.usedBy' | translate }}</h4>
      @if (uses().length === 0) {
        <p class="si-empty">{{ 'segmentInsight.unused' | translate }}</p>
      } @else {
        <ul class="si-uses" data-testid="si-uses">
          @for (use of uses(); track use.kind + use.id) {
            <li>
              <span class="si-kind">{{ 'segmentInsight.kind.' + use.kind | translate }}</span>
              <bdi>{{ use.name ?? use.id }}</bdi>
              @if (use.status) {
                <span class="si-status">{{ use.status }}</span>
              }
            </li>
          }
        </ul>
      }

      @if (explaining(); as person) {
        <xrm-member-explain-dialog [listId]="recordId() ?? ''" [personId]="person"
                                   (closed)="explaining.set(null)" />
      }
    </section>
  `,
  styles: [`
    .si { display: grid; gap: .75rem; padding-block: .5rem; }
    .si-counts, .si-reach { display: flex; flex-wrap: wrap; gap: .5rem; align-items: center; }
    .si-number { font-weight: 600; }
    .si-sample, .si-uses { list-style: none; margin: 0; padding: 0; display: grid; gap: .25rem; }
    .si-sample li, .si-uses li { display: flex; gap: .5rem; align-items: baseline; }
    .si-kind, .si-status, .si-empty { color: var(--color-text-secondary, #666); font-size: .875rem; }
    .si-error { color: var(--color-danger, #c53030); }
  `],
})
export class SegmentInsightPanelComponent {
  protected readonly lang = inject(LangService);
  private readonly insight = inject(SegmentInsightService);

  /** The form's entity (always `marketing_list` here). */
  readonly entityName = input<string>('marketing_list');
  /** The list being shown. */
  readonly recordId = input<string | null>(null);

  readonly count = signal<MarketingListCount | null>(null);
  readonly sample = signal<MarketingListSample | null>(null);
  readonly uses = signal<MarketingListUse[]>([]);
  readonly reachable = signal<{ purpose: string; count: number } | null>(null);
  readonly busy = signal(false);
  readonly error = signal(false);
  readonly explaining = signal<string | null>(null);
  protected purpose = '';

  constructor() {
    effect(() => {
      const list = this.recordId();
      if (!list) return;
      this.count.set(null);
      this.sample.set(null);
      this.uses.set([]);
      this.reachable.set(null);
      this.error.set(false);
      this.insight.count(list).subscribe({ next: c => this.count.set(c), error: () => this.error.set(true) });
      this.insight.sample(list).subscribe({ next: s => this.sample.set(s), error: () => this.error.set(true) });
      this.insight.usage(list).subscribe({ next: u => this.uses.set(u), error: () => this.error.set(true) });
    });
  }

  /** Evaluates the list for its exact size. */
  exact(): void {
    const list = this.recordId();
    if (!list) return;
    this.busy.set(true);
    this.insight.count(list, { exact: true }).subscribe({
      next: c => { this.count.set(c); this.busy.set(false); },
      error: () => { this.error.set(true); this.busy.set(false); },
    });
  }

  /** How many of the list can be emailed for the purpose typed. */
  reach(): void {
    const list = this.recordId();
    const purpose = this.purpose.trim();
    if (!list || !purpose) return;
    this.busy.set(true);
    this.insight.count(list, { purpose }).subscribe({
      next: c => {
        this.reachable.set({ purpose, count: c.reachable ?? 0 });
        this.busy.set(false);
      },
      error: () => { this.error.set(true); this.busy.set(false); },
    });
  }
}
