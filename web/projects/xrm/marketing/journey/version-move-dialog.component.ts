import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal } from '@angular/core';
import { DecimalPipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { LangService, TranslatePipe } from '@attome/base';

import { JourneyPublishResult, JourneyService, NodeWaiting, VersionMode } from './journey.service';

/**
 * Publishing a journey version (roadmap E8-T13): who waits at which node of
 * the live runs, whether the new version keeps that node and how many a
 * move would move, then the choice the journey's publish takes: everyone
 * finishes on the version they started (the default), or people waiting at
 * a node the new version keeps move to it. `done` gets the outcome, or
 * null when the person cancels.
 */
@Component({
  selector: 'xrm-version-move-dialog',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [DecimalPipe, FormsModule, TranslatePipe],
  template: `
    <div class="vm-backdrop"></div>
    <div class="vm" role="dialog" aria-modal="true" aria-labelledby="vm-title"
         [attr.dir]="lang.isRtl() ? 'rtl' : 'ltr'" data-testid="vm">
      <h3 id="vm-title">{{ 'journeyEditor.moveTitle' | translate }}</h3>
      @if (rows().length > 0) {
        <table class="vm-table">
          <thead>
            <tr>
              <th scope="col">{{ 'journeyEditor.node' | translate }}</th>
              <th scope="col">{{ 'journeyEditor.waiting' | translate }}</th>
              <th scope="col">{{ 'journeyEditor.inNewVersion' | translate }}</th>
              <th scope="col">{{ 'journeyEditor.wouldMove' | translate }}</th>
            </tr>
          </thead>
          <tbody>
            @for (r of rows(); track r.node_id) {
              <tr data-testid="vm-row">
                <td><bdi>{{ r.node_id }}</bdi></td>
                <td dir="ltr">{{ r.waiting_count | number }}</td>
                <td>{{ (r.exists_in_new ? 'journeyEditor.yes' : 'journeyEditor.no') | translate }}</td>
                <td dir="ltr">{{ r.movable_count | number }}</td>
              </tr>
            }
          </tbody>
        </table>
      } @else if (loaded()) {
        <p>{{ 'journeyEditor.nobodyWaiting' | translate }}</p>
      }

      <fieldset class="vm-choice">
        <legend>{{ 'journeyEditor.peopleInJourney' | translate }}</legend>
        <label>
          <input type="radio" name="vm-mode" value="finish_on_old" [(ngModel)]="mode" data-testid="vm-finish" />
          {{ 'journeyEditor.finishOnOld' | translate }}
        </label>
        <label>
          <input type="radio" name="vm-mode" value="move_matching" [(ngModel)]="mode" data-testid="vm-move" />
          {{ 'journeyEditor.moveMatching' | translate }}
          <span dir="ltr">({{ movable() | number }})</span>
        </label>
      </fieldset>

      @if (error()) {
        <p class="vm-error" role="alert">{{ 'journeyEditor.publishFailed' | translate }} <bdi>{{ error() }}</bdi></p>
      }
      <div class="vm-actions">
        <button type="button" class="btn btn-primary" (click)="publish()" [disabled]="busy()"
                data-testid="vm-publish">{{ 'journeyEditor.publish' | translate }}</button>
        <button type="button" class="btn" (click)="done()(null)" [disabled]="busy()"
                data-testid="vm-cancel">{{ 'journeyEditor.cancel' | translate }}</button>
      </div>
    </div>
  `,
  styles: [`
    .vm-backdrop { position: fixed; inset: 0; background: var(--color-backdrop, rgb(0 0 0 / .3)); z-index: 20; }
    .vm {
      position: fixed; inset-block-start: 10%; inset-inline: 0; margin-inline: auto; z-index: 21;
      inline-size: min(36rem, calc(100% - 2rem)); padding: 1rem; display: grid; gap: .75rem;
      background: var(--color-bg, var(--color-surface)); border-radius: .5rem;
    }
    .vm-table { inline-size: 100%; border-collapse: collapse; font-size: 13px; }
    .vm-table th, .vm-table td { text-align: start; padding-block: 2px; padding-inline: 6px; }
    .vm-choice { display: grid; gap: .25rem; border: 0; padding: 0; }
    .vm-actions { display: flex; gap: .5rem; justify-content: flex-end; }
    .vm-error { color: var(--color-danger); }
  `],
})
export class VersionMoveDialogComponent {
  protected readonly lang = inject(LangService);
  private readonly journeys = inject(JourneyService);

  /** The marketing journey record. */
  readonly journeyId = input.required<string>();
  /** The draft version to publish. */
  readonly versionId = input.required<string>();
  /** Told the outcome once published, or null when cancelled. */
  readonly done = input<(result: JourneyPublishResult | null) => void>(() => undefined);

  readonly rows = signal<NodeWaiting[]>([]);
  readonly loaded = signal(false);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  protected mode: VersionMode = 'finish_on_old';

  readonly movable = computed(() => this.rows().reduce((sum, r) => sum + r.movable_count, 0));

  constructor() {
    effect(() => {
      const journey = this.journeyId();
      const version = this.versionId();
      this.loaded.set(false);
      this.journeys.preview(journey, version).subscribe({
        next: rows => { this.rows.set(rows); this.loaded.set(true); },
        error: () => { this.rows.set([]); this.loaded.set(true); },
      });
    });
  }

  publish(): void {
    this.busy.set(true);
    this.error.set(null);
    this.journeys.publish(this.journeyId(), this.versionId(), this.mode).subscribe({
      next: result => { this.busy.set(false); this.done()(result); },
      error: (e: { message?: string }) => { this.busy.set(false); this.error.set(e?.message ?? ''); },
    });
  }
}
