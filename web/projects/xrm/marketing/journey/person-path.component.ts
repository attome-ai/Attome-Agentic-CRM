import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { LangService, TranslatePipe } from '@attome/base';

import { JourneyService, PersonRun } from './journey.service';

/**
 * Replays one person's path through a journey on the workflow editor's
 * canvas (roadmap E8-T13): their newest run's nodes in the order they ran,
 * one step at a time, with the blocks recorded at a node and how the run
 * ended. Each step's node is handed to `stepChanged`, which the editor uses
 * to outline it. A person the reader may not see is not found.
 */
@Component({
  selector: 'xrm-person-path',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [DatePipe, TranslatePipe],
  template: `
    <section class="pp" [attr.dir]="lang.isRtl() ? 'rtl' : 'ltr'" aria-labelledby="pp-title" data-testid="pp">
      <h5 id="pp-title">{{ 'journeyEditor.replayTitle' | translate }}</h5>
      @if (failed()) {
        <p role="alert">{{ 'journeyEditor.pathFailed' | translate }}</p>
      } @else if (run(); as r) {
        @if (current(); as step) {
          <p data-testid="pp-step">
            <span dir="ltr">{{ index() + 1 }} / {{ r.steps.length }}</span>
            <bdi>{{ step.node_id }}</bdi>
            <span class="pp-status">{{ step.status }}</span>
            @if (step.started_at) {
              <span dir="ltr" class="pp-at">{{ step.started_at | date: 'yyyy-MM-dd HH:mm' }}</span>
            }
          </p>
          @for (b of blocksHere(); track b.at) {
            <p class="pp-block" data-testid="pp-block">{{ 'journeyEditor.blockedBecause' | translate }} <bdi>{{ b.reason }}</bdi></p>
          }
        }
        <div class="pp-nav">
          <button type="button" class="btn" (click)="move(-1)" [disabled]="index() === 0"
                  data-testid="pp-prev">{{ 'journeyEditor.previous' | translate }}</button>
          <button type="button" class="btn" (click)="move(1)" [disabled]="index() >= r.steps.length - 1"
                  data-testid="pp-next">{{ 'journeyEditor.next' | translate }}</button>
        </div>
        @if (r.ended_at) {
          <p class="pp-end">{{ 'journeyEditor.endedWith' | translate }} <bdi>{{ r.end_reason ?? r.status }}</bdi></p>
        }
      } @else if (loaded()) {
        <p>{{ 'journeyEditor.noRuns' | translate }}</p>
      }
    </section>
  `,
  styles: [`
    .pp { display: grid; gap: .25rem; font-size: 12px; }
    .pp p { margin: 0; display: flex; flex-wrap: wrap; gap: .5rem; }
    .pp-status, .pp-at, .pp-end { color: var(--color-text-secondary); }
    .pp-block { color: var(--color-warning); }
    .pp-nav { display: flex; gap: .5rem; }
  `],
})
export class PersonPathComponent {
  protected readonly lang = inject(LangService);
  private readonly journeys = inject(JourneyService);

  /** The marketing journey record. */
  readonly journeyId = input.required<string>();
  /** The contact or lead to replay. */
  readonly personId = input.required<string>();
  /** Told the node of each step shown (null when there is none). */
  readonly stepChanged = input<(node: string | null) => void>(() => undefined);

  readonly runs = signal<PersonRun[]>([]);
  readonly loaded = signal(false);
  readonly failed = signal(false);
  readonly index = signal(0);

  /** The newest run. */
  readonly run = computed(() => this.runs().at(-1) ?? null);
  readonly current = computed(() => this.run()?.steps[this.index()] ?? null);
  readonly blocksHere = computed(() => {
    const step = this.current();
    return step ? (this.run()?.blocks ?? []).filter(b => b.node_id === step.node_id) : [];
  });

  constructor() {
    effect(() => {
      const journey = this.journeyId();
      const person = this.personId();
      this.loaded.set(false);
      this.failed.set(false);
      this.index.set(0);
      this.journeys.path(journey, person).subscribe({
        next: runs => { this.runs.set(runs); this.loaded.set(true); },
        error: () => { this.runs.set([]); this.failed.set(true); },
      });
    });
    effect(() => this.stepChanged()(this.current()?.node_id ?? null));
  }

  /** Steps forward (1) or back (-1) through the run. */
  move(by: number): void {
    const steps = this.run()?.steps.length ?? 0;
    this.index.update(i => Math.min(Math.max(i + by, 0), Math.max(steps - 1, 0)));
  }
}
