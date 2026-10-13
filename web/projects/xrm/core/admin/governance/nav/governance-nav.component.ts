import { ChangeDetectionStrategy, Component } from '@angular/core';
import { RouterLink, RouterLinkActive } from '@angular/router';
import { TranslatePipe } from '@attome/base';

/**
 * The strip of links shared by the four governance screens, so each is one
 * click from the others. The sidebar itself is database-driven
 * (`sidebar` rows), so this is the in-app way between them.
 */
@Component({
  selector: 'xrm-governance-nav',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, RouterLinkActive, TranslatePipe],
  styleUrl: './governance-nav.component.css',
  template: `
    <nav class="gov-nav" [attr.aria-label]="'governance.nav.label' | translate">
      @for (link of links; track link.path) {
        <a class="gov-nav__link" [routerLink]="link.path"
           routerLinkActive="gov-nav__link--active" ariaCurrentWhenActive="page">
          <i [class]="'las ' + link.icon" aria-hidden="true"></i>
          {{ link.key | translate }}
        </a>
      }
    </nav>
  `,
})
export class GovernanceNavComponent {
  readonly links = [
    { path: '/xrm/admin/data/quality', key: 'governance.nav.quality',     icon: 'la-chart-line' },
    { path: '/xrm/admin/data/catalog', key: 'governance.nav.catalog',     icon: 'la-book' },
    { path: '/xrm/admin/changes',      key: 'governance.nav.changes',     icon: 'la-history' },
    { path: '/xrm/admin/state-models', key: 'governance.nav.stateModels', icon: 'la-project-diagram' },
  ] as const;
}
