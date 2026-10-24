import { ChangeDetectionStrategy, Component } from '@angular/core';
import { TranslatePipe } from '@attome/base';
import { HeldQueueComponent, XrefSearchComponent } from '@attome/xrm/core/admin/governance/master-data';
import { GovernanceNavComponent } from '../nav/governance-nav.component';

/**
 * L1-T9 — `/xrm/admin/master-data`: the steward's page. Find a golden
 * record by a source system's id, and work the held queue. A golden
 * record's values, sources and pins are on its own form (the Golden record
 * tab).
 */
@Component({
  selector: 'xrm-master-data-page',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe, GovernanceNavComponent, HeldQueueComponent, XrefSearchComponent],
  styleUrls: ['../../../../styles/admin-page.css', '../governance.css'],
  template: `
    <xrm-governance-nav />
    <div class="page-header">
      <div>
        <h2>{{ 'masterData.title' | translate }}</h2>
        <p class="subtitle">{{ 'masterData.subtitle' | translate }}</p>
      </div>
    </div>
    <section [attr.aria-label]="'masterData.xref.title' | translate">
      <h3>{{ 'masterData.xref.title' | translate }}</h3>
      <xrm-master-xref-search />
    </section>
    <section [attr.aria-label]="'masterData.held.title' | translate">
      <h3>{{ 'masterData.held.title' | translate }}</h3>
      <xrm-master-held-queue />
    </section>
  `,
})
export class MasterDataPageComponent {}
