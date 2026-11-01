import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { ApiError, ApiService, TranslatePipe } from '@attome/base';
import { GovernanceNavComponent } from '../nav/governance-nav.component';

/** One row of `GET /api/v1/admin/governance/domains`. */
export interface GovernanceDomain {
  id: string;
  name: string;
  description?: string | null;
  parent_ref?: string | null;
}

/** One row of `GET /api/v1/admin/governance/domains/{id}/roles`. */
export interface GovernanceRole { user_id: string; role: string }

/** One row of `GET /api/v1/admin/governance/policies?domain=`. */
export interface GovernancePolicy {
  id: string;
  name_en: string;
  name_ar?: string | null;
  version: number;
  enforcements: { kind: string; target_ref: string }[];
}

/** A domain placed in the tree, with its depth. */
export interface TreeRow { domain: GovernanceDomain; depth: number }

/**
 * The domains as a tree: each parent, then its sub-domains, by name; a
 * domain whose parent is not in the list (or that loops) is a root. Pure.
 */
export function domainTree(domains: GovernanceDomain[]): TreeRow[] {
  const ids = new Set(domains.map(d => d.id));
  const children = new Map<string | null, GovernanceDomain[]>();
  for (const d of domains) {
    const parent = d.parent_ref && ids.has(d.parent_ref) && d.parent_ref !== d.id ? d.parent_ref : null;
    const list = children.get(parent) ?? [];
    list.push(d);
    children.set(parent, list);
  }
  for (const list of children.values()) {
    list.sort((a, b) => a.name.localeCompare(b.name));
  }
  const out: TreeRow[] = [];
  const seen = new Set<string>();
  const walk = (parent: string | null, depth: number) => {
    for (const d of children.get(parent) ?? []) {
      if (seen.has(d.id)) {
        continue;
      }
      seen.add(d.id);
      out.push({ domain: d, depth });
      walk(d.id, depth + 1);
    }
  };
  walk(null, 0);
  // Anything left sits in a parent loop: list it as a root.
  for (const d of domains) {
    if (!seen.has(d.id)) {
      seen.add(d.id);
      out.push({ domain: d, depth: 0 });
      walk(d.id, 1);
    }
  }
  return out;
}

/**
 * L3-T7 — the data domains as a tree with sub-domains; choosing one shows
 * who holds which governance role in it and its policy register, each
 * policy enforced or not, its English and Arabic names side by side.
 * Logical CSS only.
 */
@Component({
  selector: 'xrm-governance-domains',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe, GovernanceNavComponent],
  styleUrls: ['../../../../styles/admin-page.css', '../governance.css'],
  styles: [`
    .gd-layout { display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit, minmax(16rem, 1fr)); }
    .gd-tree { list-style: none; padding-inline-start: 0; margin: 0; }
    .gd-tree button { text-align: start; }
    .gd-active { font-weight: 600; }
    .gd-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .gd-enforced { color: var(--color-success); }
    .gd-unenforced { color: var(--color-danger); }
    .gd-names { display: flex; flex-wrap: wrap; gap: 0.5rem 1rem; }
  `],
  template: `
    <xrm-governance-nav />
    <div class="page-header">
      <div>
        <h2>{{ 'governance.domains.title' | translate }}</h2>
        <p class="subtitle">{{ 'governance.domains.subtitle' | translate }}</p>
      </div>
    </div>
    @if (error(); as message) { <p class="error-msg" role="alert">{{ message }}</p> }
    <div class="gd-layout">
      <section [attr.aria-label]="'governance.domains.tree' | translate">
        @if (tree().length === 0) { <p class="gd-muted">{{ 'governance.domains.none' | translate }}</p> }
        <ul class="gd-tree" data-testid="gd-tree">
          @for (row of tree(); track row.domain.id) {
            <li [style.padding-inline-start.rem]="row.depth * 1.25">
              <button type="button" [class.gd-active]="selected()?.id === row.domain.id" (click)="select(row.domain)">
                <span dir="auto">{{ row.domain.name }}</span>
              </button>
            </li>
          }
        </ul>
      </section>
      @if (selected(); as d) {
        <section data-testid="gd-roles" [attr.aria-label]="'governance.domains.roles' | translate">
          <h3 dir="auto">{{ d.name }}</h3>
          <h4>{{ 'governance.domains.roles' | translate }}</h4>
          @if (roles().length === 0) { <p class="gd-muted">{{ 'governance.domains.noRoles' | translate }}</p> }
          <ul>
            @for (r of roles(); track r.role + r.user_id) {
              <li>{{ ('governance.domains.roleNames.' + r.role) | translate }} — <span dir="ltr">{{ r.user_id }}</span></li>
            }
          </ul>
          <h4>{{ 'governance.domains.policies' | translate }}</h4>
          @if (policies().length === 0) { <p class="gd-muted">{{ 'governance.domains.noPolicies' | translate }}</p> }
          <ul data-testid="gd-policies">
            @for (p of policies(); track p.id) {
              <li>
                <span class="gd-names">
                  <span dir="ltr" lang="en">{{ p.name_en }}</span>
                  @if (p.name_ar) { <span dir="rtl" lang="ar">{{ p.name_ar }}</span> }
                </span>
                @if (p.enforcements.length) {
                  <span class="gd-enforced">{{ 'governance.domains.enforced' | translate }}</span>
                } @else {
                  <span class="gd-unenforced">{{ 'governance.domains.notEnforced' | translate }}</span>
                }
              </li>
            }
          </ul>
        </section>
      }
    </div>
  `,
})
export class GovernanceDomainsComponent implements OnInit {
  private readonly api = inject(ApiService);

  readonly domains = signal<GovernanceDomain[]>([]);
  readonly tree = computed(() => domainTree(this.domains()));
  readonly selected = signal<GovernanceDomain | null>(null);
  readonly roles = signal<GovernanceRole[]>([]);
  readonly policies = signal<GovernancePolicy[]>([]);
  readonly error = signal<string | null>(null);

  ngOnInit(): void {
    this.api.getAllPages<GovernanceDomain>('/api/v1/admin/governance/domains').subscribe({
      next: d => this.domains.set(d),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  select(domain: GovernanceDomain): void {
    this.selected.set(domain);
    this.roles.set([]);
    this.policies.set([]);
    const id = encodeURIComponent(domain.id);
    this.api.getAllPages<GovernanceRole>(`/api/v1/admin/governance/domains/${id}/roles`).subscribe({
      next: r => this.roles.set(r),
      error: (e: ApiError) => this.error.set(e.message),
    });
    this.api.getAllPages<GovernancePolicy>('/api/v1/admin/governance/policies', { domain: domain.id }).subscribe({
      next: p => this.policies.set(p),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }
}
