import {
  ChangeDetectionStrategy, Component, computed, effect, inject, OnInit, signal, untracked,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterOutlet } from '@angular/router';
import {
  BrandService, CommandRegistry, LangService, ShortcutRegistry, TranslatePipe, UiTextOverrides,
  isTypingTarget,
} from '@attome/base';
import { AdminService, SidebarItem } from '@attome/xrm/core/admin/data';
import { entityFormRoute, entityListRoute, urlPathToLogical } from '@attome/xrm/core/entity';
import { WebVitals } from '../services/web-vitals.service';
import { DEBOUNCE_MS, MIN_QUERY_LENGTH, OmniSearchComponent, SearchService } from '@attome/xrm/search/omni';
import type { OmniSelection } from '@attome/xrm/search/omni';
import { AppSwitcherComponent } from '../app-switcher/app-switcher.component';
import { ChangesetIndicatorComponent } from '../changeset-indicator/changeset-indicator.component';
import { CopilotLauncherComponent } from '../copilot-launcher/copilot-launcher.component';
import { FavouritesComponent } from '../favourites/favourites.component';
import { FavouriteItem, FavouritesService } from '../favourites/favourites.service';
import { PersonalSettingsService } from '../settings/personal-settings.service';
import { NotificationBellComponent } from '../notification-bell/notification-bell.component';
import { ProfileMenuComponent } from '../profile-menu/profile-menu.component';
import { ShellSidebarComponent } from '../shell-sidebar/shell-sidebar.component';
import { StatusBannerComponent } from '../status-banner/status-banner.component';
import { PaletteUses, entityMatchesPrefix, parsePaletteQuery, rankByUse } from '../command-palette/palette';

// ── Constants ─────────────────────────────────────────────────────────────────

const PREFIX_ICON: Record<string, { icon: string }> = {
  atm:          { icon: 'las la-cube' },
  automation:   { icon: 'las la-robot' },
  api:          { icon: 'las la-code' },
  core:         { icon: 'las la-server' },
  doc:          { icon: 'las la-file-alt' },
  audit:        { icon: 'las la-history' },
  report:       { icon: 'las la-chart-bar' },
  job:          { icon: 'las la-briefcase' },
  enum:         { icon: 'las la-list-ul' },
  constraint:   { icon: 'las la-lock' },
  branch:       { icon: 'las la-code-branch' },
  country:      { icon: 'las la-globe' },
  language:     { icon: 'las la-language' },
  notification: { icon: 'las la-bell' },
  privilege:    { icon: 'las la-shield-alt' },
};

const DEFAULT_ICON = 'las la-database';

function prefixOf(logicalname: string): string {
  const idx = logicalname.indexOf('_');
  return idx > 0 ? logicalname.slice(0, idx) : logicalname;
}

function iconFor(logicalname: string): string {
  return PREFIX_ICON[prefixOf(logicalname)]?.icon ?? DEFAULT_ICON;
}

/**
 * M65 Phase 1 (D-467) — the entity logicalname a sidebar item's `route`
 * resolves to, or `null` when the route isn't recognizable as one. Only
 * trusts a route that round-trips exactly through `entityListRoute` (e.g.
 * `/xrm/core/entity/info/list` -> `entity_info` -> back to the same
 * string) — a custom admin page, dashboard, or hand-authored nav route never
 * matches this shape and is correctly treated as "not an entity route"
 * rather than mis-parsed into a wrong logicalname.
 */
function routeLogicalname(route: string): string | null {
  const trimmed = route.replace(/^\/+/, '');
  if (!trimmed.endsWith('/list')) return null;
  const withoutSuffix = trimmed.slice(0, -'/list'.length);
  if (!withoutSuffix) return null;
  const logicalname = urlPathToLogical(withoutSuffix);
  // Round-trip: only trust this route if `entityListRoute` would produce the
  // exact same string back for the logicalname it implies.
  const expected = entityListRoute(logicalname).join('/').replace(/^\/+/, '');
  return expected === trimmed ? logicalname : null;
}

// ── Types ─────────────────────────────────────────────────────────────────────

type QsItem =
  | { kind: 'entity'; id: string; name: string; sub: string; icon: string; logicalname: string }
  | { kind: 'nav';    id: string; name: string; sub: string; icon: string; route: string }
  // B9-T3: a pinned or recent item, shown while the query is empty.
  | { kind: 'fav';    id: string; name: string; sub: string; icon: string;
      target: Pick<FavouriteItem, 'kind' | 'entity' | 'ref'> }
  // B10-T1: a registered command, and a record from the search index.
  | { kind: 'cmd';    id: string; name: string; sub: string; icon: string; context: boolean; run: () => void }
  | { kind: 'record'; id: string; name: string; sub: string; icon: string; entity: string; recordId: string };

/** Records the palette lists at most. */
const PALETTE_RECORDS = 8;

// ── Component ─────────────────────────────────────────────────────────────────

/**
 * The XRM application shell: layout frame, header, routed outlet, and quick
 * search.
 *
 * Navigation, the notification bell and the profile menu are their own
 * components (D-315) — this file was 1,321 lines with 498 of them CSS, which is
 * what pushed the `anyComponentStyle` budget to a blanket 20 kB. It keeps the
 * sidebar *fetch* rather than pushing it down, because quick search searches
 * the same tree and one request should feed both.
 */
@Component({
  selector:   'xrm-shell',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [
    RouterOutlet, FormsModule, TranslatePipe,
    ShellSidebarComponent, NotificationBellComponent, ProfileMenuComponent, AppSwitcherComponent,
    CopilotLauncherComponent, OmniSearchComponent, ChangesetIndicatorComponent, FavouritesComponent,
    StatusBannerComponent,
  ],
  host: {
    '(window:keydown)': 'onKeydown($event)',
  },
  styleUrls: ['./shell.component.css'],
  templateUrl: './shell.component.html',
})
export class ShellComponent implements OnInit {
  private readonly admin  = inject(AdminService);
  private readonly router = inject(Router);
  protected readonly favourites = inject(FavouritesService);
  private readonly personalSettings = inject(PersonalSettingsService);
  private readonly brand = inject(BrandService);
  private readonly uiText = inject(UiTextOverrides);
  private readonly vitals = inject(WebVitals);
  private readonly lang = inject(LangService);
  private readonly search = inject(SearchService);
  private readonly commandRegistry = inject(CommandRegistry);
  private readonly paletteUses = inject(PaletteUses);
  readonly shortcutRegistry = inject(ShortcutRegistry);
  /** B10-T2: the `?` help listing the shortcuts that work here. */
  readonly shortcutsOpen = signal(false);

  // ── Sidebar data (owned here because quick search searches the same tree) ──
  readonly sidebarItems   = signal<SidebarItem[]>([]);
  readonly sidebarLoading = signal(true);
  readonly sidebarError   = signal(false);

  // ── App switcher (M65 Phase 1, D-467) ───────────────────────────────────
  //
  // "Apps only filter navigation, they never authorize" — `selectedAppEntities`
  // is a pure client-side view of `sidebarItems`, nothing downstream of it is
  // a permission check. `null` (the default, and whenever no app is picked or
  // the deployment has none configured) means "show the full tree exactly as
  // it always rendered", so a deployment that never sets up an app sees no
  // behavior change from this feature at all.
  readonly selectedAppEntities = signal<string[] | null>(null);

  onAppChanged(entities: string[] | null): void {
    this.selectedAppEntities.set(entities);
  }

  /**
   * `sidebarItems` narrowed to the selected app's `entities[]`. Only a leaf
   * item whose `route` is *exactly* what `entityListRoute` would produce for
   * some logicalname is treated as "belongs to an entity" at all — any other
   * route (a dashboard, a custom admin page, …) is left alone rather than
   * guessed at, and a group is kept whenever at least one descendant survives
   * the filter. That conservative "unknown route → always keep" default is
   * deliberate: this filter is a navigation convenience, not a security
   * control, so a parsing miss should under- rather than over-hide.
   */
  readonly filteredSidebarItems = computed<SidebarItem[]>(() => {
    const entities = this.selectedAppEntities();
    if (!entities) return this.sidebarItems();
    const allow = new Set(entities);
    const keep = (items: SidebarItem[]): SidebarItem[] => {
      const out: SidebarItem[] = [];
      for (const item of items) {
        const hadChildren = item.child.length > 0;
        const child = hadChildren ? keep(item.child) : [];
        let keepItem: boolean;
        if (hadChildren) {
          // A container: survives only if at least one descendant does —
          // this is what drops a group whose every child was filtered out,
          // rather than leaving an empty group visible.
          keepItem = child.length > 0;
        } else {
          const logicalname = item.route ? routeLogicalname(item.route) : null;
          keepItem = logicalname === null || allow.has(logicalname);
        }
        if (keepItem) out.push(child.length !== item.child.length ? { ...item, child } : item);
      }
      return out;
    };
    return keep(this.sidebarItems());
  });

  // ── Quick search ──────────────────────────────────────────────────────────
  readonly quickSearchOpen = signal(false);
  readonly qsQuery         = signal('');
  readonly qsActive        = signal(0);

  private lastShiftTime = 0;
  /** B10-T1: records from the search index for the current query. */
  readonly qsRecords = signal<QsItem[]>([]);
  private recordTimer: ReturnType<typeof setTimeout> | null = null;

  constructor() {
    // B10-T1: search records a moment after typing stops.
    effect(() => {
      const raw = this.quickSearchOpen() ? this.qsQuery() : null;
      untracked(() => this.queueRecordSearch(raw));
    });
  }

  /**
   * B10-T1, the command palette: with no query, the open page's commands,
   * pinned items and recent records; `>` lists commands, `acc:` searches
   * records of the entities that word starts; anything else searches pages,
   * commands and records. The open page's commands come first, then what
   * this person picks most.
   */
  readonly qsResults = computed((): QsItem[] => {
    const parsed = parsePaletteQuery(this.qsQuery());
    const q = parsed.text.toLowerCase();
    const uses = (id: string) => this.paletteUses.count(id);
    if (parsed.scope === 'all' && !q) {
      return [...this.commandResults('', true), ...this.favouriteResults()];
    }
    if (parsed.scope === 'commands') return rankByUse(this.commandResults(q, false), uses);
    if (parsed.scope === 'records') return rankByUse(this.qsRecords(), uses);
    const results: QsItem[] = [...this.commandResults(q, false)];
    const firstRoute = (item: SidebarItem): string => {
      if (item.route) return item.route;
      for (const c of item.child) { const r = firstRoute(c); if (r) return r; }
      return '';
    };
    const collectNav = (items: SidebarItem[]) => {
      for (const item of items) {
        if (!item.is_disabled && item.name.toLowerCase().includes(q)) {
          const route = firstRoute(item);
          if (route) results.push({ kind: 'nav', id: item.id, name: item.name, sub: item.route || item.child[0]?.name || '', icon: item.icon || DEFAULT_ICON, route });
        }
        if (item.child.length) collectNav(item.child);
      }
    };
    // M65 Phase 1 (D-467) — searches the same app-filtered tree the sidebar
    // shows, so quick search never surfaces an entity the switcher just hid.
    collectNav(this.filteredSidebarItems());
    return rankByUse([...results, ...this.qsRecords()], uses);
  });

  /** Registered commands whose name contains `q`; `contextOnly` keeps the page's own. */
  private commandResults(q: string, contextOnly: boolean): QsItem[] {
    return this.commandRegistry.commands()
      .filter(c => !contextOnly || c.context)
      .map(c => ({
        kind: 'cmd' as const, id: `cmd:${c.id}`, name: this.lang.translate(c.labelKey),
        sub: this.lang.translate('shell.paletteCommand'), icon: c.icon ?? 'las la-play',
        context: c.context ?? false, run: c.run,
      }))
      .filter(c => !q || c.name.toLowerCase().includes(q));
  }

  /** B10-T1: asks the search index for records once typing pauses. */
  private queueRecordSearch(raw: string | null): void {
    if (this.recordTimer) { clearTimeout(this.recordTimer); this.recordTimer = null; }
    const parsed = raw === null ? null : parsePaletteQuery(raw);
    if (!parsed || parsed.scope === 'commands' || parsed.text.length < MIN_QUERY_LENGTH) {
      this.qsRecords.set([]);
      return;
    }
    this.recordTimer = setTimeout(() => {
      this.recordTimer = null;
      // A scoped search asks for more, as other entities' hits are dropped.
      const pageSize = parsed.entityPrefix ? 50 : PALETTE_RECORDS;
      this.search.search(parsed.text, { pageSize }).subscribe({
        next: response => {
          if (this.qsQuery() !== raw) return;
          const prefix = parsed.entityPrefix;
          this.qsRecords.set((response.items ?? [])
            .filter(hit => !prefix || entityMatchesPrefix(hit.entity_logicalname, prefix))
            .slice(0, PALETTE_RECORDS)
            .map(hit => ({
              kind: 'record' as const, id: `rec:${hit.entity_logicalname}:${hit.record_id}`,
              name: hit.title || hit.record_id.slice(0, 8), sub: hit.subtitle || hit.entity_logicalname,
              icon: iconFor(hit.entity_logicalname), entity: hit.entity_logicalname, recordId: hit.record_id,
            })));
        },
        error: () => this.qsRecords.set([]),
      });
    }, DEBOUNCE_MS);
  }

  readonly iconFor = iconFor;

  /** B9-T3: pinned items, then recent records, for an empty quick search. */
  private favouriteResults(): QsItem[] {
    const pinned: QsItem[] = this.favourites.pinned().map((item, i) => ({
      kind: 'fav', id: `pin-${item.id}`, name: item.label || item.ref, sub: `Ctrl+${i + 1}`,
      icon: 'las la-flag', target: item,
    }));
    const recent: QsItem[] = this.favourites.recent()
      .filter(item => !item.deleted)
      .slice(0, 8)
      .map(item => ({
        kind: 'fav', id: `recent-${item.entity}-${item.record_id}`,
        name: item.label || item.record_id.slice(0, 8), sub: item.entity, icon: 'las la-history',
        target: { kind: 'record', entity: item.entity, ref: item.record_id },
      }));
    return [...pinned, ...recent];
  }

  // ── Lifecycle ─────────────────────────────────────────────────────────────
  ngOnInit(): void {
    this.favourites.start();
    // B10-T2: the shell's own shortcuts, listed by `?`.
    this.shortcutRegistry.register(
      { keys: 'Ctrl+K', labelKey: 'shell.shortcutPalette' },
      { keys: 'Shift Shift', labelKey: 'shell.shortcutQuickSearch' },
      { keys: 'Ctrl+1…9', labelKey: 'shell.shortcutPinned' },
      { keys: '?', labelKey: 'shell.shortcutHelp' },
      { keys: 'Esc', labelKey: 'shell.shortcutClose' },
    );
    // B13-T8: the caller's brand adds their business unit's theme.
    this.brand.loadMine();
    // B20-T3: this deployment's rewording of built-in text.
    this.uiText.start();
    // AA12-T1: page speed, reported when the page is hidden.
    this.vitals.start();
    // B11-T2: the person's settings apply at once; a chosen start page opens
    // when they land on the app's front door.
    this.personalSettings.load().subscribe({
      next: () => {
        const page = this.personalSettings.startPage();
        const here = this.router.url.split('?')[0];
        if (page && page !== here && ['/', '/xrm', '/xrm/'].includes(here)) {
          void this.router.navigateByUrl(page);
        }
      },
      error: () => undefined,
    });
    this.admin.getSidebar().subscribe({
      next:  items => {
        this.sidebarItems.set(this.normalizeSidebar(items));
        this.sidebarLoading.set(false);
      },
      error: () => { this.sidebarError.set(true); this.sidebarLoading.set(false); },
    });
  }

  private normalizeSidebar(items: SidebarItem[]): SidebarItem[] {
    return items.map(i => ({ ...i, child: this.normalizeSidebar(i.child ?? []) }));
  }

  // ── Quick search ──────────────────────────────────────────────────────────
  toggleQuickSearch(): void {
    const opening = !this.quickSearchOpen();
    this.quickSearchOpen.set(opening);
    if (opening) {
      this.qsQuery.set(''); this.qsActive.set(0);
      setTimeout(() => (document.querySelector('.qs-input') as HTMLInputElement | null)?.focus(), 50);
    } else {
      this.qsQuery.set('');
    }
  }

  closeQuickSearch(): void { this.quickSearchOpen.set(false); this.qsQuery.set(''); }

  onQuickSearchBackdropKeydown(event: KeyboardEvent): void {
    if (event.key === 'Escape') this.closeQuickSearch();
  }

  /** U13 (M11) — the header's record search (`GET /api/v1/search`) opens the
   * picked record's form, through the same route helper every entity link
   * uses. The sidebar quick search above is unchanged. */
  openSearchHit(selection: OmniSelection): void {
    const { entity_logicalname, record_id } = selection.hit;
    void this.router.navigate(entityFormRoute(entity_logicalname), { queryParams: { id: record_id } });
  }

  navigateTo(item: QsItem): void {
    this.paletteUses.bump(item.id);
    if (item.kind === 'cmd') {
      this.closeQuickSearch();
      item.run();
      return;
    }
    if (item.kind === 'record') {
      void this.router.navigate(entityFormRoute(item.entity), { queryParams: { id: item.recordId } });
      this.closeQuickSearch();
      return;
    }
    if (item.kind === 'fav') {
      this.favourites.open(item.target);
      this.closeQuickSearch();
      return;
    }
    const commands = item.kind === 'entity'
      ? entityListRoute(item.logicalname)
      : [item.route];
    this.router.navigate(commands);
    this.closeQuickSearch();
  }

  // ── Keyboard ──────────────────────────────────────────────────────────────
  onKeydown(e: KeyboardEvent): void {
    // B10-T2: `?` shows the shortcuts; Esc hides them.
    if (this.shortcutsOpen() && e.key === 'Escape') {
      this.shortcutsOpen.set(false);
      return;
    }
    if (e.key === '?' && !e.ctrlKey && !e.metaKey && !e.altKey && !isTypingTarget(e.target)) {
      e.preventDefault();
      this.shortcutsOpen.update(open => !open);
      return;
    }
    // B10-T1: Ctrl+K opens and closes the command palette.
    if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      this.toggleQuickSearch();
      return;
    }
    // B9-T3: Ctrl+1..9 opens the pinned item with that number.
    if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && /^[1-9]$/.test(e.key)) {
      if (this.favourites.openPinned(Number(e.key))) {
        e.preventDefault();
        this.closeQuickSearch();
      }
      return;
    }
    if (e.key === 'Shift') {
      if (e.repeat) return;
      if (!this.quickSearchOpen()) {
        const now = Date.now();
        if (now - this.lastShiftTime < 300) {
          this.toggleQuickSearch(); this.lastShiftTime = 0;
        } else { this.lastShiftTime = now; }
      }
      return;
    }
    if (!this.quickSearchOpen()) return;
    this.onQuickSearchKeydown(e);
  }

  onQuickSearchKeydown(e: KeyboardEvent): void {
    e.stopPropagation();
    const results = this.qsResults();
    switch (e.key) {
      case 'Escape': e.preventDefault(); this.closeQuickSearch(); break;
      case 'ArrowDown':
        if (!results.length) break;
        e.preventDefault();
        this.qsActive.update(i => (i + 1) % results.length);
        this.scrollToSelected(); break;
      case 'ArrowUp':
        if (!results.length) break;
        e.preventDefault();
        this.qsActive.update(i => (i - 1 + results.length) % results.length);
        this.scrollToSelected(); break;
      case 'Enter':
        e.preventDefault();
        if (results[this.qsActive()]) this.navigateTo(results[this.qsActive()]);
        break;
    }
  }

  private scrollToSelected(): void {
    setTimeout(() => {
      const el = document.querySelector('.qs-results')?.children[this.qsActive()] as HTMLElement | undefined;
      el?.scrollIntoView({ block: 'nearest', behavior: 'auto' });
    }, 0);
  }
}
