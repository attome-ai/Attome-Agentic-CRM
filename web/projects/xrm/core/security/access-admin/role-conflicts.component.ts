import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { DialogService } from '@attome/base/dialog';

import { FeatureFlagsService } from '@attome/xrm/core/admin/data';
import {
  ConflictRule,
  CurrentConflict,
  PermissionSetItem,
  PrivilegeItem,
  RoleItem,
  SECURITY_FLAGS,
  SecurityAdminService,
  UserListItem,
} from '@attome/xrm/core/security';

/** What one side of a conflict rule names. */
export type ConflictKind = 'role' | 'privilege' | 'set';

/** The label key of each kind, spelled out so the catalog scan sees every key. */
const KIND_KEYS: Record<ConflictKind, string> = {
  role: 'roleConflicts.kind_role',
  privilege: 'roleConflicts.kind_privilege',
  set: 'roleConflicts.kind_set',
};

/**
 * Q10-T12 — conflict rules (Q10-T8): two roles, privileges or permission sets
 * one person must not hold together, refused outright or sent for a second
 * administrator's approval, and who holds a pair today. Behind
 * `security.role_conflicts`.
 */
@Component({
  selector: 'xrm-role-conflicts',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  styleUrls: ['../../../styles/admin-page.css'],
  template: `
    <div class="page-header">
      <div>
        <h2>{{ 'roleConflicts.title' | translate }}</h2>
        <p class="subtitle">{{ 'roleConflicts.subtitle' | translate }}</p>
      </div>
    </div>

    @if (!enabled()) {
      <p class="state-msg">{{ 'roleConflicts.off' | translate }}</p>
    } @else {
      @if (error()) { <p class="error-msg" role="alert">{{ error() }}</p> }

      <div class="create-panel">
        <h3>{{ 'roleConflicts.new' | translate }}</h3>
        <div class="form-row-2">
          @for (side of sides; track side) {
            <fieldset>
              <legend>{{ (side === 'left' ? 'roleConflicts.first' : 'roleConflicts.second') | translate }}</legend>
              <div class="field">
                <label [for]="'rc-kind-' + side">{{ 'roleConflicts.kind' | translate }}</label>
                <select [id]="'rc-kind-' + side" [ngModel]="draft()[side].kind" (ngModelChange)="setKind(side, $event)">
                  @for (k of kinds; track k) { <option [value]="k">{{ kindKeys[k] | translate }}</option> }
                </select>
              </div>
              <div class="field">
                <label [for]="'rc-ref-' + side">{{ 'roleConflicts.which' | translate }}</label>
                <select [id]="'rc-ref-' + side" [ngModel]="draft()[side].ref" (ngModelChange)="setRef(side, $event)">
                  <option value="" disabled>{{ 'roleConflicts.choose' | translate }}</option>
                  @for (o of options(draft()[side].kind); track o.id) { <option [value]="o.id">{{ o.label }}</option> }
                </select>
              </div>
            </fieldset>
          }
        </div>
        <div class="form-row-2">
          <div class="field">
            <label for="rc-mode">{{ 'roleConflicts.mode' | translate }}</label>
            <select id="rc-mode" [(ngModel)]="mode">
              <option value="refuse">{{ 'roleConflicts.mode_refuse' | translate }}</option>
              <option value="approval">{{ 'roleConflicts.mode_approval' | translate }}</option>
            </select>
          </div>
          <div class="field">
            <label for="rc-reason">{{ 'roleConflicts.reason' | translate }}</label>
            <input id="rc-reason" [(ngModel)]="reason">
          </div>
        </div>
        <div class="btn-row">
          <button class="btn-primary" (click)="create()" [disabled]="busy()">{{ 'roleConflicts.save' | translate }}</button>
        </div>
      </div>

      <div class="card">
        <h3>{{ 'roleConflicts.rules' | translate }} <span class="count">{{ rules().length }}</span></h3>
        @if (rules().length === 0) {
          <p class="state-msg">{{ 'roleConflicts.noRules' | translate }}</p>
        } @else {
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{{ 'roleConflicts.first' | translate }}</th>
                  <th>{{ 'roleConflicts.second' | translate }}</th>
                  <th>{{ 'roleConflicts.mode' | translate }}</th>
                  <th>{{ 'roleConflicts.reason' | translate }}</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                @for (r of rules(); track r.id) {
                  <tr>
                    <td>{{ refLabel(r.left_kind, r.left_ref) }}</td>
                    <td>{{ refLabel(r.right_kind, r.right_ref) }}</td>
                    <td>{{ ('roleConflicts.mode_' + r.mode) | translate }}</td>
                    <td class="cell-muted">{{ r.reason }}</td>
                    <td class="actions">
                      <button class="btn-sm btn-sm-danger" (click)="remove(r)">{{ 'roleConflicts.delete' | translate }}</button>
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        }
      </div>

      <div class="card">
        <h3>{{ 'roleConflicts.current' | translate }} <span class="count">{{ current().length }}</span></h3>
        @if (current().length === 0) {
          <p class="state-msg">{{ 'roleConflicts.noCurrent' | translate }}</p>
        } @else {
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{{ 'roleConflicts.person' | translate }}</th>
                  <th>{{ 'roleConflicts.rule' | translate }}</th>
                </tr>
              </thead>
              <tbody>
                @for (c of current(); track c.user_id + c.rule_id) {
                  <tr>
                    <td>{{ userLabel(c.user_id) }}</td>
                    <td>{{ ruleLabel(c.rule_id) }}</td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        }
      </div>
    }
  `,
})
export class RoleConflictsComponent implements OnInit {
  private readonly svc       = inject(SecurityAdminService);
  private readonly dialogSvc = inject(DialogService);
  private readonly lang      = inject(LangService);
  private readonly flags     = inject(FeatureFlagsService);

  readonly kinds: ConflictKind[] = ['role', 'privilege', 'set'];
  readonly kindKeys = KIND_KEYS;
  readonly sides = ['left', 'right'] as const;
  readonly enabled = computed(() => this.flags.flags()[SECURITY_FLAGS.roleConflicts] === true);

  readonly rules       = signal<ConflictRule[]>([]);
  readonly current     = signal<CurrentConflict[]>([]);
  readonly roles       = signal<RoleItem[]>([]);
  readonly privileges  = signal<PrivilegeItem[]>([]);
  readonly sets        = signal<PermissionSetItem[]>([]);
  readonly users       = signal<UserListItem[]>([]);
  readonly busy        = signal(false);
  readonly error       = signal<string | null>(null);
  readonly draft = signal<Record<'left' | 'right', { kind: ConflictKind; ref: string }>>({
    left:  { kind: 'role', ref: '' },
    right: { kind: 'role', ref: '' },
  });

  mode: 'refuse' | 'approval' = 'refuse';
  reason = '';

  ngOnInit(): void {
    this.flags.ensureLoaded();
    this.load();
    this.svc.listRoles().subscribe({ next: rs => this.roles.set(rs) });
    this.svc.listPrivileges().subscribe({ next: ps => this.privileges.set(ps) });
    this.svc.listPermissionSets().subscribe({ next: ss => this.sets.set(ss) });
    this.svc.listUsers().subscribe({ next: page => this.users.set(page.items) });
  }

  private load(): void {
    this.svc.listConflictRules().subscribe({
      next:  rs => this.rules.set(rs),
      error: (e: ApiError) => this.error.set(e.message),
    });
    this.svc.listCurrentConflicts().subscribe({
      next:  cs => this.current.set(cs),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  options(kind: ConflictKind): { id: string; label: string }[] {
    switch (kind) {
      case 'role':      return this.roles().map(r => ({ id: r.id, label: r.name }));
      case 'privilege': return this.privileges().map(p => ({ id: p.id, label: `${p.name} (${p.key})` }));
      case 'set':       return this.sets().map(s => ({ id: s.id, label: s.name }));
    }
  }

  refLabel(kind: string, ref: string): string {
    const found = this.options(kind as ConflictKind).find(o => o.id === ref);
    return `${this.lang.translate(KIND_KEYS[kind as ConflictKind] ?? kind)}: ${found?.label ?? ref}`;
  }

  userLabel(id: string): string {
    const u = this.users().find(x => x.id === id);
    return u?.user_name ?? u?.email ?? id;
  }

  ruleLabel(id: string): string {
    const r = this.rules().find(x => x.id === id);
    return r ? `${this.refLabel(r.left_kind, r.left_ref)} + ${this.refLabel(r.right_kind, r.right_ref)}` : id;
  }

  setKind(side: 'left' | 'right', kind: ConflictKind): void {
    this.draft.update(d => ({ ...d, [side]: { kind, ref: '' } }));
  }

  setRef(side: 'left' | 'right', ref: string): void {
    this.draft.update(d => ({ ...d, [side]: { ...d[side], ref } }));
  }

  create(): void {
    const { left, right } = this.draft();
    const reason = this.reason.trim();
    if (!left.ref || !right.ref || !reason) {
      this.error.set(this.lang.translate('roleConflicts.required'));
      return;
    }
    if (left.kind === right.kind && left.ref === right.ref) {
      this.error.set(this.lang.translate('roleConflicts.sameTwice'));
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    this.svc.createConflictRule({
      left_kind: left.kind, left_ref: left.ref,
      right_kind: right.kind, right_ref: right.ref,
      mode: this.mode, reason,
    }).subscribe({
      next: r => {
        this.busy.set(false);
        this.rules.update(list => [...list, r]);
        this.reason = '';
        this.draft.set({ left: { kind: 'role', ref: '' }, right: { kind: 'role', ref: '' } });
        this.svc.listCurrentConflicts().subscribe({ next: cs => this.current.set(cs) });
      },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  async remove(r: ConflictRule): Promise<void> {
    const confirmed = await this.dialogSvc.confirm({
      message: this.lang.translate('roleConflicts.confirmDelete'),
      variant: 'warning',
      confirmText: this.lang.translate('roleConflicts.delete'),
    });
    if (!confirmed) return;
    this.svc.deleteConflictRule(r.id).subscribe({
      next: () => {
        this.rules.update(list => list.filter(x => x.id !== r.id));
        this.current.update(list => list.filter(c => c.rule_id !== r.id));
      },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }
}
