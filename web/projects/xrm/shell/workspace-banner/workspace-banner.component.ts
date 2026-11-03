import { DOCUMENT } from '@angular/common';
import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { TranslatePipe, WorkspaceState } from '@attome/base';

/**
 * T5-T7 — while this tab works inside a Develop workspace, says so on every
 * page in a coloured band, with a way back to live. Shows nothing otherwise.
 */
@Component({
  selector: 'xrm-workspace-banner',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    @if (state.active(); as w) {
      <div class="wb" role="status" data-workspace-banner>
        <i class="las la-layer-group" aria-hidden="true"></i>
        <p class="wb-text">{{ 'workspaces.banner.inside' | translate: { name: w.name } }}</p>
        <button type="button" class="wb-leave" (click)="leave()">
          {{ 'workspaces.banner.leave' | translate }}
        </button>
      </div>
    }
  `,
  styles: [`
    .wb { display: flex; align-items: center; gap: 0.75rem; padding-block: 0.5rem; padding-inline: 1rem;
      background: var(--color-warning-bg, var(--color-bg)); border-block-end: 2px solid var(--color-warning, #b45309);
      font-size: 0.875rem; }
    .wb-text { margin: 0; flex: 1; }
    .wb-leave { margin-inline-start: auto; }
  `],
})
export class WorkspaceBannerComponent {
  private readonly document = inject(DOCUMENT);
  readonly state = inject(WorkspaceState);

  leave(): void {
    this.state.leave();
    try {
      this.document.defaultView?.location.reload();
    } catch {
      // No reload where there is no window (tests).
    }
  }
}
