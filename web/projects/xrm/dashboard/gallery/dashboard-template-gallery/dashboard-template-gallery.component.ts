import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import { ApiError, TranslatePipe } from '@attome/base';
import { entityFormRoute, EntityService } from '@attome/xrm/core/entity';
import { EntityRecord } from '@attome/xrm';
import { DashboardService } from '@attome/xrm/dashboard/data';

/** M26 (Dashboard) gap-fill — the template gallery (plan §3 "`is_template`
 * filter + a gallery view"). `/xrm/dashboard-templates` (wired alongside the
 * other bespoke dashboard routes in `xrm-shell.routes.ts`). Moved from
 * `@attome/xrm/report` to `@attome/xrm/dashboard` (R-10 step 1) — new-module
 * UI belongs in the module that owns it.
 *
 * Reads `attome_dashboard` through the ordinary generic-entity list path
 * (`EntityService.list`, filtered `is_template = true`) rather than a
 * bespoke endpoint — same "the generic engine already has this" posture
 * every other list in this module follows. No server-rendered thumbnail:
 * that needs M57 (out of scope here, see the module plan and
 * `crates/engine/attome-dashboard/src/seed.rs`'s "Template Gallery" view comment),
 * so every card shows a placeholder icon instead.
 *
 * "Use as Template" calls the existing `POST /api/v1/attome-dashboard/{id}/clone`
 * (`attome-dashboard`'s `lifecycle.rs`, via `DashboardService.clone`) directly —
 * the clone starts life as an ordinary `draft` dashboard the caller owns,
 * same as cloning any other dashboard; nothing template-specific happens to
 * the copy.
 */
@Component({
  selector:   'attome-dashboard-template-gallery',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styleUrls: ['./dashboard-template-gallery.component.css'],
  templateUrl: './dashboard-template-gallery.component.html',
})
export class DashboardTemplateGalleryComponent implements OnInit {
  private readonly entities = inject(EntityService);
  private readonly dashboardApi = inject(DashboardService);
  private readonly router = inject(Router);

  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  readonly templates = signal<EntityRecord[]>([]);
  /** Id of the template currently being cloned, so its own card can show a
   * busy state without disabling every other card's button. */
  readonly cloning = signal<string | null>(null);

  ngOnInit(): void {
    this.load();
  }

  private load(): void {
    this.loading.set(true);
    this.error.set(null);
    this.entities
      .list('attome_dashboard', {
        filters: [{ field: 'is_template', op: 'eq', value: 'true' }],
      })
      .subscribe({
        next: (res) => {
          this.templates.set(res.data);
          this.loading.set(false);
        },
        error: (e: ApiError) => {
          this.error.set(e.message);
          this.loading.set(false);
        },
      });
  }

  useAsTemplate(templateId: string): void {
    this.cloning.set(templateId);
    this.dashboardApi.clone(templateId).subscribe({
      next: (res) => {
        this.cloning.set(null);
        // `entityFormRoute`, not a hand-typed path: 'attome_dashboard' maps to
        // URL segment 'dashboard' (logicalToUrlPath), not a literal
        // 'attome_dashboard' segment — this previously navigated to a URL that
        // reconstructed to the nonexistent logicalname 'xrm_dashboard'
        // (found as part of the M26 Phase 2 backlog).
        this.router.navigate(entityFormRoute('attome_dashboard'), { queryParams: { id: res.id } });
      },
      error: (e: ApiError) => {
        this.cloning.set(null);
        this.error.set(e.message);
      },
    });
  }
}
