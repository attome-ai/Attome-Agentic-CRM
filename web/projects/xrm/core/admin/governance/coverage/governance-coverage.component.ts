import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { ApiError, ApiService, LocalNumberPipe, TranslatePipe } from '@attome/base';
import { GovernanceNavComponent } from '../nav/governance-nav.component';

interface DomainRef { id: string; name: string }

/** `GET /api/v1/admin/governance/coverage` (L3-T6). */
export interface Coverage {
  entities_without_domain: string[];
  domains_without_owner: DomainRef[];
  personal_attributes_without_policy: { entity: string; attribute: string; classification: string }[];
  policies_without_enforcement: { id: string; domain_id: string; name: string }[];
  stewards_with_overdue_items: { user_id: string; overdue_items: number }[];
  truncated: boolean;
}

/** `GET /api/v1/admin/governance/domains/{id}/scorecard` (L3-T6). */
export interface Scorecard {
  domain: DomainRef;
  quality: { entity: string; dimension: string; score: number; computed_at: string }[];
  quality_average?: number | null;
  open_items: number;
  overdue_items: number;
  open_exceptions: number;
  policies: number;
  enforced_policies: number;
}

/**
 * L3-T7 — accountability coverage and a domain's scorecard: entities in no
 * domain, domains with no owner, personal attributes with no policy,
 * policies nothing enforces, stewards with overdue work; any listed domain
 * opens its scorecard. Logical CSS only.
 */
@Component({
  selector: 'xrm-governance-coverage',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalNumberPipe, TranslatePipe, GovernanceNavComponent],
  styleUrls: ['../../../../styles/admin-page.css', '../governance.css'],
  styles: [`
    .gc-grid { display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit, minmax(16rem, 1fr)); }
    .gc-card { padding: 0.75rem; border: 1px solid var(--color-border); border-radius: 0.5rem; }
    .gc-card ul { margin: 0; padding-inline-start: 1rem; }
    .gc-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
  `],
  template: `
    <xrm-governance-nav />
    <div class="page-header">
      <div>
        <h2>{{ 'governance.coverage.title' | translate }}</h2>
        <p class="subtitle">{{ 'governance.coverage.subtitle' | translate }}</p>
      </div>
    </div>
    @if (error(); as message) { <p class="error-msg" role="alert">{{ message }}</p> }
    @if (coverage(); as c) {
      @if (c.truncated) { <p class="gc-muted" role="status">{{ 'governance.coverage.truncated' | translate }}</p> }
      <div class="gc-grid">
        <section class="gc-card" data-testid="gc-unowned">
          <h3>{{ 'governance.coverage.unowned' | translate }}</h3>
          @if (c.domains_without_owner.length === 0) { <p class="gc-muted">{{ 'governance.coverage.none' | translate }}</p> }
          <ul>
            @for (d of c.domains_without_owner; track d.id) {
              <li dir="auto">{{ d.name }}
                <button type="button" (click)="openScorecard(d.id)">{{ 'governance.coverage.scorecard' | translate }}</button>
              </li>
            }
          </ul>
        </section>
        <section class="gc-card">
          <h3>{{ 'governance.coverage.noDomain' | translate }}</h3>
          @if (c.entities_without_domain.length === 0) { <p class="gc-muted">{{ 'governance.coverage.none' | translate }}</p> }
          <ul>@for (e of c.entities_without_domain; track e) { <li dir="ltr">{{ e }}</li> }</ul>
        </section>
        <section class="gc-card">
          <h3>{{ 'governance.coverage.personal' | translate }}</h3>
          @if (c.personal_attributes_without_policy.length === 0) { <p class="gc-muted">{{ 'governance.coverage.none' | translate }}</p> }
          <ul>@for (a of c.personal_attributes_without_policy; track a.entity + a.attribute) { <li dir="ltr">{{ a.entity }}.{{ a.attribute }}</li> }</ul>
        </section>
        <section class="gc-card">
          <h3>{{ 'governance.coverage.unenforced' | translate }}</h3>
          @if (c.policies_without_enforcement.length === 0) { <p class="gc-muted">{{ 'governance.coverage.none' | translate }}</p> }
          <ul>@for (p of c.policies_without_enforcement; track p.id) { <li dir="auto">{{ p.name }}</li> }</ul>
        </section>
        <section class="gc-card">
          <h3>{{ 'governance.coverage.overdue' | translate }}</h3>
          @if (c.stewards_with_overdue_items.length === 0) { <p class="gc-muted">{{ 'governance.coverage.none' | translate }}</p> }
          <ul>
            @for (s of c.stewards_with_overdue_items; track s.user_id) {
              <li><span dir="ltr">{{ s.user_id }}</span> — {{ s.overdue_items | localNumber }}</li>
            }
          </ul>
        </section>
      </div>
    }
    @if (scorecard(); as s) {
      <section class="gc-card" data-testid="gc-scorecard" [attr.aria-label]="'governance.coverage.scorecard' | translate">
        <h3 dir="auto">{{ s.domain.name }}</h3>
        <p>{{ 'governance.coverage.quality' | translate }}:
          @if (s.quality_average !== null && s.quality_average !== undefined) {
            {{ s.quality_average | localNumber }}
          } @else {
            {{ 'governance.coverage.notScored' | translate }}
          }
        </p>
        <p>{{ 'governance.coverage.items' | translate: { open: s.open_items, overdue: s.overdue_items } }}</p>
        <p>{{ 'governance.coverage.policies' | translate: { enforced: s.enforced_policies, total: s.policies } }}</p>
        <p>{{ 'governance.coverage.exceptions' | translate: { n: s.open_exceptions } }}</p>
        <button type="button" (click)="scorecard.set(null)">{{ 'governance.coverage.close' | translate }}</button>
      </section>
    }
  `,
})
export class GovernanceCoverageComponent implements OnInit {
  private readonly api = inject(ApiService);

  readonly coverage = signal<Coverage | null>(null);
  readonly scorecard = signal<Scorecard | null>(null);
  readonly error = signal<string | null>(null);

  ngOnInit(): void {
    this.api.get<Coverage>('/api/v1/admin/governance/coverage').subscribe({
      next: c => this.coverage.set(c),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  openScorecard(domainId: string): void {
    this.api.get<Scorecard>(`/api/v1/admin/governance/domains/${encodeURIComponent(domainId)}/scorecard`).subscribe({
      next: s => this.scorecard.set(s),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }
}
