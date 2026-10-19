import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiService, TranslatePipe } from '@attome/base';

/** The part of `GET /api/v1/admin/setup/region` this prompt reads. */
interface RegionSetupState {
  country: string | null;
  pack_available: boolean;
}

/**
 * X12-T3: until the deployment has a country, an administrator sees a line
 * leading to the first-run wizard. The setup route is administrator-only, so
 * anyone else gets a refusal and sees nothing; it is read once per shell.
 */
@Component({
  selector: 'xrm-first-run-prompt',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe, RouterLink],
  template: `
    @if (needed()) {
      <p class="frp" role="status" data-first-run-prompt>
        <i class="las la-flag" aria-hidden="true"></i>
        {{ 'firstRun.prompt' | translate }}
        <a routerLink="/xrm/admin/first-run">{{ 'firstRun.promptLink' | translate }}</a>
      </p>
    }
  `,
  styles: [`
    .frp { margin: 0; display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem;
      padding-block: 0.5rem; padding-inline: 1rem; font-size: 0.875rem;
      background: var(--color-info-bg, var(--color-bg)); border-block-end: 1px solid var(--color-border); }
  `],
})
export class FirstRunPromptComponent implements OnInit {
  private readonly api = inject(ApiService);

  readonly needed = signal(false);

  ngOnInit(): void {
    this.api.get<RegionSetupState>('/api/v1/admin/setup/region').subscribe({
      next: state => this.needed.set(state.country === null && state.pack_available),
      error: () => undefined,
    });
  }
}
