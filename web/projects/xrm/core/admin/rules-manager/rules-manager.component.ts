import {
  ChangeDetectionStrategy, Component, computed, DestroyRef, inject, OnInit, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import {
  AdminService, AudienceRoleOption, BusinessRule, BusinessRulesService, EntityMeta,
} from '@attome/xrm/core/admin/data';
import { OwnerLayerBadgeComponent } from '@attome/xrm/core/generic/components';
import { BusinessRuleEditorComponent } from './business-rule-editor/business-rule-editor.component';

/** Counts of what a rule's policies do, for the list's summary column. */
export interface PolicySummary { hides: number; locks: number; errors: number; sets: number }

export function summarizePolicies(rule: Pick<BusinessRule, 'policies'>): PolicySummary {
  const out: PolicySummary = { hides: 0, locks: 0, errors: 0, sets: 0 };
  for (const p of rule.policies) {
    if (p.type === 'hidden') out.hides++;
    else if (p.type === 'disabled') out.locks++;
    else if (p.type === 'error') out.errors++;
    else out.sets++;
  }
  return out;
}

/**
 * D-789 section 10 — the business-rule editor page (same route as the old
 * rules manager, title "Business rules"). The list: entity filter, audience
 * (all users or role names), policy summary, active and layer badges, and
 * flags for a rule that applies to nobody or that a release turned off.
 * Selecting a rule loads it (with its editor warnings) into
 * `<xrm-business-rule-editor>`. Calls `/api/v1/admin/business-rules`
 * (D-790 removed `/api/v1/admin/rules*`).
 */
@Component({
  selector: 'xrm-rules-manager',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe, OwnerLayerBadgeComponent, BusinessRuleEditorComponent],
  styleUrls: ['./rules-manager.component.css'],
  templateUrl: './rules-manager.component.html',
})
export class RulesManagerComponent implements OnInit {
  private readonly service = inject(BusinessRulesService);
  private readonly admin = inject(AdminService);
  private readonly lang = inject(LangService);
  private readonly destroyRef = inject(DestroyRef);

  readonly rules = signal<readonly BusinessRule[]>([]);
  readonly entities = signal<readonly EntityMeta[]>([]);
  readonly staffRoles = signal<readonly AudienceRoleOption[]>([]);
  readonly portalRoles = signal<readonly AudienceRoleOption[]>([]);
  readonly loading = signal(true);
  readonly error = signal('');

  readonly search = signal('');
  readonly entityFilter = signal('');

  /** The rule open in the editor (`null` with `editing` = a new rule). */
  readonly selected = signal<BusinessRule | null>(null);
  readonly editing = signal(false);
  readonly opening = signal<string | null>(null);

  readonly filtered = computed(() => {
    const q = this.search().trim().toLowerCase();
    return this.rules().filter(r =>
      !q
      || r.name.toLowerCase().includes(q)
      || (r.display_name ?? '').toLowerCase().includes(q)
      || r.entity_logicalname.toLowerCase().includes(q));
  });

  ngOnInit(): void {
    this.admin.listEntities().pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: items => this.entities.set([...items].sort((a, b) => a.name.localeCompare(b.name))),
      error: (e: ApiError) => this.error.set(e.message || this.lang.errorText(e)),
    });
    this.service.staffRoles().pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: roles => this.staffRoles.set(roles),
      error: () => this.staffRoles.set([]),
    });
    this.service.portalRoles().pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: roles => this.portalRoles.set(roles),
    });
    this.reload();
  }

  reload(): void {
    this.loading.set(true);
    this.error.set('');
    const entity = this.entityFilter();
    this.service.list(entity ? { entity } : {}).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: items => { this.rules.set(items); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(e.message || this.lang.errorText(e)); this.loading.set(false); },
    });
  }

  setEntityFilter(entity: string): void {
    this.entityFilter.set(entity);
    this.reload();
  }

  /** Opens a rule: a single read carries its editor warnings (lists do not). */
  open(rule: BusinessRule): void {
    this.opening.set(rule.id);
    this.service.get(rule.id).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: full => { this.opening.set(null); this.selected.set(full); this.editing.set(true); },
      error: (e: ApiError) => { this.opening.set(null); this.error.set(e.message || this.lang.errorText(e)); },
    });
  }

  startCreate(): void {
    this.selected.set(null);
    this.editing.set(true);
  }

  close(): void {
    this.editing.set(false);
    this.selected.set(null);
  }

  onSaved(rule: BusinessRule): void {
    this.rules.update(items => items.some(r => r.id === rule.id)
      ? items.map(r => r.id === rule.id ? rule : r)
      : [...items, rule]);
    this.selected.set(rule);
  }

  onRetired(): void {
    this.close();
    this.reload();
  }

  /** "All users", or the role names (portal roles with their portal). */
  audienceText(rule: BusinessRule): string {
    if (rule.kind !== 'business' || rule.applies_to === 'all') return this.lang.translate('businessRules.audience.all');
    const names = rule.roles.filter(r => r.live).map(r => r.portal_role && r.portal ? `${r.portal}: ${r.name}` : r.name);
    return names.length ? names.join(', ') : this.lang.translate('businessRules.list.nobody');
  }

  /** "hides 2, locks 1, 1 error, sets 1". */
  policyText(rule: BusinessRule): string {
    if (rule.kind !== 'business') return this.lang.translate('businessRules.badge.legacy', { kind: rule.kind });
    const s = summarizePolicies(rule);
    const parts: string[] = [];
    if (s.hides) parts.push(this.lang.translate('businessRules.list.hides', { count: s.hides }));
    if (s.locks) parts.push(this.lang.translate('businessRules.list.locks', { count: s.locks }));
    if (s.errors) parts.push(this.lang.translate('businessRules.list.errors', { count: s.errors }));
    if (s.sets) parts.push(this.lang.translate('businessRules.list.sets', { count: s.sets }));
    return parts.length ? parts.join(', ') : this.lang.translate('businessRules.list.noPolicies');
  }

  label(rule: BusinessRule): string {
    return rule.display_name?.trim() || rule.name;
  }
}
