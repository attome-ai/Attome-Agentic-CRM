import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { ModelService } from '@attome/xrm/model';
import type { ObjectSummary } from '@attome/xrm/model';

/** A21-T3: the apps (navigation objects) to open in the app designer, at `/xrm/admin/apps`. */
@Component({
  selector: 'xrm-app-list',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, TranslatePipe],
  template: `
    <section class="al" data-app-list>
      <h2 class="al-title">{{ 'appDesigner.apps' | translate }}</h2>
      <a class="btn btn-primary" data-new-app [routerLink]="['/xrm', 'admin', 'apps', 'new', 'design']">{{ 'appDesigner.newApp' | translate }}</a>
      @if (error()) { <p class="al-error" role="alert">{{ error() }}</p> }
      <ul class="al-list">
        @for (a of apps(); track a.id) {
          <li><a [routerLink]="['/xrm', 'admin', 'apps', a.id, 'design']" [attr.data-app]="a.id"><bdi>{{ a.name }}</bdi></a>
            <span class="al-note">{{ 'appDesigner.version' | translate: { version: a.version_no, state: a.state } }}</span></li>
        } @empty {
          <li class="al-note">{{ 'appDesigner.noApps' | translate }}</li>
        }
      </ul>
    </section>
  `,
  styles: [`
    .al { display: flex; flex-direction: column; gap: 12px; padding-inline: 16px; padding-block: 12px; align-items: start; }
    .al-title { margin: 0; font-size: 1.25rem; }
    .al-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 6px; }
    .al-note { margin-inline-start: 8px; color: var(--color-text-secondary); }
    .al-error { margin: 0; color: var(--color-danger); }
  `],
})
export class AppListComponent {
  private readonly model = inject(ModelService);
  private readonly lang = inject(LangService);

  readonly apps = signal<ObjectSummary[]>([]);
  readonly error = signal<string | null>(null);

  constructor() {
    this.model.objects('navigation', 1).subscribe({
      next: page => this.apps.set(page.items ?? []),
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }
}
