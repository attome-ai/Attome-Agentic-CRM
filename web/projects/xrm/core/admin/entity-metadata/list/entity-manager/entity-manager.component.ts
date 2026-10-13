import { ChangeDetectionStrategy, Component, computed, inject, OnInit, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ApiError, TranslatePipe } from '@attome/base';

import {
  AdminService, DevToolsInfo, EntityMeta, ScaffoldKind, ScaffoldResult,
} from '@attome/xrm/core/admin/data';
import { OwnerLayerBadgeComponent } from '@attome/xrm/core/generic/components';

// ── Prefix → icon / label maps ────────────────────────────────────────────────

const PREFIX_ICON: Record<string, string> = {
  atm:          'las la-cube',
  automation:   'las la-robot',
  api:          'las la-code',
  core:         'las la-server',
  doc:          'las la-file-alt',
  audit:        'las la-history',
  report:       'las la-chart-bar',
  job:          'las la-briefcase',
  enum:         'las la-list-ul',
  constraint:   'las la-lock',
  branch:       'las la-code-branch',
  country:      'las la-globe',
  language:     'las la-language',
  notification: 'las la-bell',
  privilege:    'las la-shield-alt',
  ss:           'las la-layer-group',
  cv:           'las la-id-card',
  sidebar:      'las la-th-list',
  ve2:          'las la-project-diagram',
};

const PREFIX_LABEL: Record<string, string> = {
  atm:          'ATM',
  automation:   'Automation',
  api:          'API',
  core:         'Core',
  doc:          'Documents',
  audit:        'Audit',
  report:       'Reports',
  job:          'Jobs',
  enum:         'Enumerations',
  constraint:   'Constraints',
  branch:       'Branches',
  country:      'Countries',
  language:     'Languages',
  notification: 'Notifications',
  privilege:    'Privileges',
  ss:           'SS',
  cv:           'CV',
  sidebar:      'Sidebar',
  ve2:          'VE2',
};

const DEFAULT_ICON = 'las la-database';

function prefixOf(logicalname: string): string {
  const idx = logicalname.indexOf('_');
  return idx > 0 ? logicalname.slice(0, idx) : logicalname;
}

// ── Component ─────────────────────────────────────────────────────────────────

@Component({
  selector:   'attome-metadata-manager',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [OwnerLayerBadgeComponent, FormsModule, RouterLink, TranslatePipe],
  styleUrls:  ['../../../../../styles/admin-page.css', './entity-manager.component.css'],
  templateUrl: './entity-manager.component.html',
})
export class EntityManagerComponent implements OnInit {
  private readonly svc = inject(AdminService);

  readonly entities     = signal<EntityMeta[]>([]);
  readonly loading      = signal(true);
  readonly error        = signal<string | null>(null);
  readonly activePrefix = signal('');

  // Dev-only scaffold tool — see AdminService.devToolsAvailable(); the
  // buttons this backs are invisible against a real deployment (404 -> null),
  // not just disabled, per the "no bypass surface" gating this feature
  // requires. The payload also carries the backend's own angular/ path, so
  // the destination box can be pre-filled with something that will actually
  // pass the server's containment check instead of making the user guess it.
  readonly devTools       = signal<DevToolsInfo | null>(null);
  readonly scaffoldTarget = signal<{ entity: EntityMeta; kind: ScaffoldKind } | null>(null);
  readonly scaffolding    = signal(false);
  readonly scaffoldError  = signal<string | null>(null);
  readonly scaffoldDone   = signal<ScaffoldResult | null>(null);

  scaffoldPath = '';

  search = '';

  readonly prefixes = computed(() =>
    [...new Set(this.entities().map(e => prefixOf(e.logicalname)))].sort()
  );

  readonly filtered = computed(() => {
    const q = this.search.toLowerCase();
    const p = this.activePrefix();
    return this.entities().filter(e =>
      (p === '' || prefixOf(e.logicalname) === p) &&
      (q === '' || e.logicalname.includes(q) || e.name.toLowerCase().includes(q))
    );
  });

  ngOnInit(): void {
    this.load();
    // 404s against any non-debug backend, which is the intended "buttons
    // never appear" behavior — not an error to surface to the user.
    this.svc.devToolsAvailable().subscribe({
      next:  r => this.devTools.set(r),
      error: () => this.devTools.set(null),
    });
  }

  private load(): void {
    this.loading.set(true);
    this.svc.listEntities().subscribe({
      next:  es => { this.entities.set(es); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  // ── Dev-only scaffolding ──────────────────────────────────────────────────

  openScaffold(e: EntityMeta, kind: ScaffoldKind): void {
    this.scaffoldTarget.set({ entity: e, kind });
    this.scaffoldError.set(null);
    this.scaffoldDone.set(null);
    this.scaffoldPath = this.defaultScaffoldPath(e);
  }

  closeScaffold(): void {
    this.scaffoldTarget.set(null);
    this.scaffoldError.set(null);
    this.scaffoldDone.set(null);
  }

  /**
   * `{suggested_dir}/{logicalname-with-dashes}` — a guess, not a rule; the
   * folder is a free-text box precisely because naming it is the developer's
   * call. Joined with the separator the backend itself used so a Windows path
   * doesn't come back half-slashed.
   */
  private defaultScaffoldPath(e: EntityMeta): string {
    const base = this.devTools()?.suggested_dir ?? '';
    const sep  = base.includes('\\') ? '\\' : '/';
    return base ? `${base}${sep}${e.logicalname.replace(/_/g, '-')}` : '';
  }

  runScaffold(): void {
    const target = this.scaffoldTarget();
    if (!target) return;
    const dir = this.scaffoldPath.trim();
    if (!dir) { this.scaffoldError.set('A destination folder is required.'); return; }

    this.scaffolding.set(true);
    this.scaffoldError.set(null);
    this.scaffoldDone.set(null);
    this.svc.scaffoldComponent(target.entity.id, target.kind, dir).subscribe({
      next: r => { this.scaffolding.set(false); this.scaffoldDone.set(r); },
      error: (err: ApiError) => {
        this.scaffolding.set(false);
        this.scaffoldError.set(err.message);
      },
    });
  }

  entityIcon(e: EntityMeta):  string { return PREFIX_ICON[prefixOf(e.logicalname)] ?? DEFAULT_ICON; }
  prefixIcon(p: string):      string { return PREFIX_ICON[p] ?? DEFAULT_ICON; }
  prefixLabel(p: string):     string { return PREFIX_LABEL[p] ?? (p.charAt(0).toUpperCase() + p.slice(1)); }

  clearSearch(): void { this.search = ''; this.activePrefix.set(''); }
}
