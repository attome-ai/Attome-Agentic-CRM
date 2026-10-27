import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ApiError, LangService, TranslatePipe } from '@attome/base';

import {
  ACCESS_LEVELS,
  InstalledRole,
  RoleTemplateItem,
  SecurityAdminService,
} from './security-admin.service';

/**
 * Q10-T12 — the roles the licensed modules suggest (Q10-T7). Installing one
 * creates an ordinary role with the template's privileges and levels, which
 * administrators then own; a privilege or entity this deployment does not
 * have is skipped and named.
 */
@Component({
  selector: 'xrm-role-templates',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, RouterLink, TranslatePipe],
  styleUrls: ['../../styles/admin-page.css'],
  template: `
    <div class="page-header">
      <div>
        <h2>{{ 'roleTemplates.title' | translate }}</h2>
        <p class="subtitle">{{ 'roleTemplates.subtitle' | translate }}</p>
      </div>
    </div>

    @if (error()) { <p class="error-msg" role="alert">{{ error() }}</p> }
    @if (installed(); as r) {
      <p class="state-msg" role="status">
        {{ 'roleTemplates.installed' | translate: { name: r.name } }}
        <a class="cell-link" [routerLink]="['/xrm/core/role/form']" [queryParams]="{ id: r.role_id }">{{ 'roleTemplates.open' | translate }}</a>
      </p>
      @if (r.skipped.length > 0) {
        <p class="warn-msg">{{ 'roleTemplates.skipped' | translate: { items: r.skipped.join(', ') } }}</p>
      }
    }

    @if (loading()) {
      <p class="state-msg">{{ 'roleTemplates.loading' | translate }}</p>
    } @else if (templates().length === 0) {
      <div class="empty-state"><p>{{ 'roleTemplates.empty' | translate }}</p></div>
    } @else {
      @for (t of templates(); track t.key) {
        <div class="card">
          <h3>{{ templateName(t) }} <span class="badge">{{ t.module }}</span></h3>
          <p class="cell-muted">{{ t.description }}</p>
          <p class="hint">{{ 'roleTemplates.privileges' | translate: { count: t.privileges.length } }}</p>
          @if (t.entity_access.length > 0) {
            <table class="nested-table">
              <thead>
                <tr>
                  <th>{{ 'permissionSets.entity' | translate }}</th>
                  <th>{{ 'roleEntityAccess.read' | translate }}</th>
                  <th>{{ 'roleEntityAccess.write' | translate }}</th>
                  <th>{{ 'roleEntityAccess.delete' | translate }}</th>
                </tr>
              </thead>
              <tbody>
                @for (a of t.entity_access; track a[0]) {
                  <tr>
                    <td class="cell-mono">{{ a[0] }}</td>
                    @for (level of a[1]; track $index) { <td>{{ levelLabel(level) }}</td> }
                  </tr>
                }
              </tbody>
            </table>
          }
          <div class="form-row-2 inline-form-panel">
            <div class="field">
              <label [for]="'rt-name-' + t.key">{{ 'roleTemplates.roleName' | translate }}</label>
              <input [id]="'rt-name-' + t.key" [placeholder]="t.name" [ngModel]="names()[t.key] ?? ''"
                     (ngModelChange)="setName(t.key, $event)">
            </div>
            <div class="btn-row">
              <button class="btn-sm btn-primary" (click)="install(t)" [disabled]="busy() === t.key">
                {{ 'roleTemplates.install' | translate }}
              </button>
            </div>
          </div>
        </div>
      }
    }
  `,
})
export class RoleTemplatesComponent implements OnInit {
  private readonly svc  = inject(SecurityAdminService);
  private readonly lang = inject(LangService);

  readonly templates = signal<RoleTemplateItem[]>([]);
  readonly names     = signal<Record<string, string>>({});
  readonly installed = signal<InstalledRole | null>(null);
  readonly loading   = signal(true);
  readonly busy      = signal<string | null>(null);
  readonly error     = signal<string | null>(null);

  ngOnInit(): void {
    this.svc.listRoleTemplates().subscribe({
      next:  ts => { this.templates.set(ts); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  templateName(t: RoleTemplateItem): string {
    return this.lang.current() === 'ar' && t.name_ar ? t.name_ar : t.name;
  }

  levelLabel(value: number): string {
    const key = ACCESS_LEVELS.find(l => l.value === value)?.label;
    return key ? this.lang.translate(key) : String(value);
  }

  setName(key: string, name: string): void {
    this.names.update(n => ({ ...n, [key]: name }));
  }

  install(t: RoleTemplateItem): void {
    this.busy.set(t.key);
    this.error.set(null);
    this.installed.set(null);
    this.svc.installRoleTemplate(t.key, this.names()[t.key]?.trim() || null).subscribe({
      next:  r => { this.busy.set(null); this.installed.set(r); },
      error: (e: ApiError) => { this.busy.set(null); this.error.set(e.message); },
    });
  }
}
