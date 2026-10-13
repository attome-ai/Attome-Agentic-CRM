import {
  ChangeDetectionStrategy, Component, DestroyRef,
  ElementRef, HostListener, computed, effect, inject, input, signal, untracked, viewChild,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { NgTemplateOutlet } from '@angular/common';
import { ScrollingModule } from '@angular/cdk/scrolling';
import { ApiComponents, ApiService, TranslatePipe } from '@attome/base';
import { DialogService } from '@attome/base/dialog';
import { EntityService, EntityRecordResponse } from '../services/entity.service';
import { FileUploadService } from '../field/file-upload.service';
import { UploadPipeline } from '../field/upload-pipeline';

// P-api-contract (C-26): these used to be hand-written wire shapes of
// `crates/engine/attome-api/src/documents_tree.rs::TreeResponse` and friends —
// this component's own doc comment admitted they predated codegen for this
// route and should be swapped once the backend's OpenAPI annotation landed.
// It has: `documents_tree.rs`'s structs all carry `ToSchema` now, so these
// are `ApiComponents['schemas'][...]` instead.
type EntityGroup   = ApiComponents['schemas']['EntityGroup'];
type RecordGroup   = ApiComponents['schemas']['RecordGroup'];
// `FolderGroup` (`TreeResponse['folders']`'s element type) has no local alias:
// every read of `data.folders` below infers its element type from `TreeResponse`
// directly, so a same-named local type would be unused by name.
type DocumentFile  = ApiComponents['schemas']['DocumentFile'];
type TreeResponse  = ApiComponents['schemas']['TreeResponse'];
/** A node in the sidebar's persistent folder tree — `path` is the full slash-joined path from the record's root.
 *  Client-side only, no wire twin: built by walking `TreeResponse['folders']` responses across requests, not
 *  returned whole by any one endpoint. */
interface FolderNode { path: string; label: string; count: number; created_at?: string | null; }
type SortColumn = 'name' | 'created_at' | 'modified_at' | 'size';

const DOCUMENT_ENTITY = 'attome_document';

/** One entry of the main list's top level — an entity, a record, or a folder to step into. */
type BrowserTile =
  | { kind: 'entity'; key: string; label: string; count: number; raw: EntityGroup; created_at: string | null }
  | { kind: 'record'; key: string; label: string; count: number; raw: RecordGroup; created_at: string | null }
  | { kind: 'folder'; key: string; label: string; count: number; created_at: string | null };

/**
 * What the main list actually renders, flattened into one array so a single
 * `cdk-virtual-scroll-viewport` can window over it (FE-6). The tree route
 * (`documents_tree.rs`) has no `LIMIT` on files-per-folder, records-per-entity
 * or folders, so any of these three sections can be as long as the customer's
 * data — the DOM must not be.
 */
type MainListItem =
  | { kind: 'tile'; key: string; tile: BrowserTile }
  | { kind: 'busy'; key: string }
  | { kind: 'file'; key: string; row: DocumentFile; index: number };

/**
 * Every main-list row is exactly this tall (`.xdf-main .xdf-row`,
 * `.xdf-row-busy`) — the fixed `itemSize` the virtual scroll strategy needs.
 * Kept in one place so the CSS and the viewport cannot drift apart silently.
 */
export const DOCUMENT_ROW_HEIGHT_PX = 40;

/**
 * File-row icon + accent color by extension — the generic `la-file-alt`
 * icon every row used to get regardless of content. Keyed by the lowercased
 * extension (no leading dot); anything not listed falls back to the plain
 * `la-file-alt` with no tint, same as before this table existed.
 */
const EXTENSION_ICONS: Record<string, { icon: string; tint: string }> = {
  pdf: { icon: 'la-file-pdf', tint: 'xdf-ext-pdf' },
  doc: { icon: 'la-file-word', tint: 'xdf-ext-word' },
  docx: { icon: 'la-file-word', tint: 'xdf-ext-word' },
  rtf: { icon: 'la-file-word', tint: 'xdf-ext-word' },
  xls: { icon: 'la-file-excel', tint: 'xdf-ext-excel' },
  xlsx: { icon: 'la-file-excel', tint: 'xdf-ext-excel' },
  csv: { icon: 'la-file-csv', tint: 'xdf-ext-excel' },
  ppt: { icon: 'la-file-powerpoint', tint: 'xdf-ext-ppt' },
  pptx: { icon: 'la-file-powerpoint', tint: 'xdf-ext-ppt' },
  zip: { icon: 'la-file-archive', tint: 'xdf-ext-archive' },
  rar: { icon: 'la-file-archive', tint: 'xdf-ext-archive' },
  '7z': { icon: 'la-file-archive', tint: 'xdf-ext-archive' },
  tar: { icon: 'la-file-archive', tint: 'xdf-ext-archive' },
  gz: { icon: 'la-file-archive', tint: 'xdf-ext-archive' },
  jpg: { icon: 'la-file-image', tint: 'xdf-ext-image' },
  jpeg: { icon: 'la-file-image', tint: 'xdf-ext-image' },
  png: { icon: 'la-file-image', tint: 'xdf-ext-image' },
  gif: { icon: 'la-file-image', tint: 'xdf-ext-image' },
  svg: { icon: 'la-file-image', tint: 'xdf-ext-image' },
  webp: { icon: 'la-file-image', tint: 'xdf-ext-image' },
  bmp: { icon: 'la-file-image', tint: 'xdf-ext-image' },
  mp4: { icon: 'la-file-video', tint: 'xdf-ext-video' },
  mov: { icon: 'la-file-video', tint: 'xdf-ext-video' },
  avi: { icon: 'la-file-video', tint: 'xdf-ext-video' },
  mkv: { icon: 'la-file-video', tint: 'xdf-ext-video' },
  webm: { icon: 'la-file-video', tint: 'xdf-ext-video' },
  mp3: { icon: 'la-file-audio', tint: 'xdf-ext-audio' },
  wav: { icon: 'la-file-audio', tint: 'xdf-ext-audio' },
  ogg: { icon: 'la-file-audio', tint: 'xdf-ext-audio' },
  flac: { icon: 'la-file-audio', tint: 'xdf-ext-audio' },
  json: { icon: 'la-file-code', tint: 'xdf-ext-code' },
  xml: { icon: 'la-file-code', tint: 'xdf-ext-code' },
  yml: { icon: 'la-file-code', tint: 'xdf-ext-code' },
  yaml: { icon: 'la-file-code', tint: 'xdf-ext-code' },
  html: { icon: 'la-file-code', tint: 'xdf-ext-code' },
  css: { icon: 'la-file-code', tint: 'xdf-ext-code' },
  js: { icon: 'la-file-code', tint: 'xdf-ext-code' },
  ts: { icon: 'la-file-code', tint: 'xdf-ext-code' },
  txt: { icon: 'la-file-alt', tint: '' },
  md: { icon: 'la-file-alt', tint: '' },
};

/** A breadcrumb carries the full nav state `goTo` jumps straight to — no index arithmetic to get wrong. */
interface Crumb {
  label: string; entity: string | null; recordId: string | null; recordName: string | null; folder: string | null;
}

/**
 * The Documents feature's one piece of new UI (D-36x) — a folder-tile/file-row
 * browser over `attome_document`, driven entirely by `GET /api/v1/documents/tree`
 * (the one bespoke read endpoint the feature needed; every write reuses
 * ordinary generic entity CRUD against `attome_document`).
 *
 * Two call sites, one component, deliberately — "the per-record tab and the
 * system-wide page are the same data" is a property of reusing this
 * component in two modes, not something kept in sync by hand:
 *
 *   <!-- Per-record Documents tab: fixed to one record, starts in its
 *        uploads folder. -->
 *   <attome-document-folder-browser [entityName]="entityName()"
 *                                [recordId]="recordId()" folder="uploads" />
 *
 *   <!-- System-wide Documents page: root mode, browse from every entity
 *        down. -->
 *   <attome-document-folder-browser [entityName]="null" [recordId]="null" [folder]="null" />
 *
 * A dropped/pasted file becomes its own `attome_document` row (D-362's
 * multi-file-field JSONB-array shape was deliberately NOT reused here — a
 * document needs independent metadata, its own delete/download, and its own
 * audit trail, which only a real row gives you). Because `attome_document.file`
 * can't be filled in at create time (an upload session must be scoped to an
 * *existing* record — the same "save the record before attaching a file"
 * constraint `AttachmentComponent` already has), a manual upload is a
 * two-phase create: empty `attome_document` row -> upload session scoped to
 * *that row's own id* -> PATCH the resulting key on. Mirrored rows
 * (`source_field != null`) are never created here — they come from the
 * generic mutation path's own sync, and are read-only in this view.
 */
@Component({
  selector: 'attome-document-folder-browser',
  standalone: true,
  imports: [NgTemplateOutlet, ScrollingModule, TranslatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls: ['./document-folder-browser.component.css'],
  templateUrl: './document-folder-browser.component.html',
})
export class DocumentFolderBrowserComponent {
  /** `null` at every level = system-wide root mode. */
  readonly entityName = input<string | null>(null);
  readonly recordId   = input<string | null>(null);
  readonly folder      = input<string | null>(null);

  private readonly api      = inject(ApiService);
  private readonly entitySvc = inject(EntityService);
  private readonly fileSvc  = inject(FileUploadService);
  private readonly dialogSvc = inject(DialogService);
  private readonly destroyRef = inject(DestroyRef);

  // Local navigation state — seeded from inputs, then driven entirely by
  // drilling in/out inside this component. Keeping it local (rather than
  // re-deriving from the inputs on every drill) is what lets one component
  // serve both the fixed per-record tab and the free-roaming system-wide
  // page without two code paths.
  private readonly curEntity     = signal<string | null>(null);
  private readonly curRecordId   = signal<string | null>(null);
  private readonly curRecordName = signal<string | null>(null);
  private readonly curFolder     = signal<string | null>(null);

  readonly loading = signal(false);
  /** True once the first tree has arrived: later loads keep the current view
   * on screen (no skeleton swap) so moving between folders does not flicker. */
  readonly loadedOnce = signal(false);
  readonly error   = signal<string | null>(null);
  private readonly treeData = signal<TreeResponse | null>(null);

  readonly downloadingId = signal<string | null>(null);
  readonly busy          = signal(false);

  readonly uploadState    = signal<'idle' | 'uploading' | 'processing' | 'error'>('idle');
  readonly uploadProgress = signal(0);
  readonly uploadingName  = signal('');
  readonly uploadMessage  = signal<string | null>(null);
  readonly dragging       = signal(false);
  readonly sortColumn     = signal<SortColumn>('created_at');
  readonly sortDirection  = signal<'asc' | 'desc'>('desc');
  readonly selectedIds    = signal<Set<string>>(new Set());
  readonly clipboardIds   = signal<Set<string>>(new Set());
  readonly clipboardMode  = signal<'cut' | 'copy' | null>(null);
  readonly dragTarget     = signal<string | null>(null);
  readonly contextMenu    = signal<{ x: number; y: number; row: DocumentFile | null; folder: string | null } | null>(null);
  readonly marquee        = signal<{ left: number; top: number; width: number; height: number } | null>(null);

  // The sidebar's persistent folder tree — deliberately independent of
  // `curFolder`/`treeData`. Keyed by parent path ('' = the record's root);
  // presence of a key means that level has been fetched (even if empty), so
  // a branch the user has never expanded stays un-fetched rather than
  // reloading every time the main pane's selection changes (that reload-on-
  // navigate was the sidebar-mirrors-content bug). Drilling into a folder
  // via the main pane only ever *adds* to this map/set (see `revealInTree`)
  // — it's cleared wholesale only when the component moves to a different
  // record (`resetFolderTree`).
  private readonly folderChildren = signal<Map<string, FolderNode[]>>(new Map());
  /** Files cached per folder path — same keying as `folderChildren` ('' = record root). */
  private readonly folderFiles = signal<Map<string, DocumentFile[]>>(new Map());
  readonly expandedFolders = signal<Set<string>>(new Set());
  private readonly loadingFolderPaths = new Set<string>();

  private selectionAnchor = -1;
  private marqueeOrigin: { x: number; y: number; host: HTMLElement; additive: boolean; initial: Set<string> } | null = null;
  private readonly pipeline = new UploadPipeline(this.fileSvc);
  private readonly newDocumentInput = viewChild<ElementRef<HTMLInputElement>>('newDocumentInput');
  private uploadTargetFolder: string | null = null;
  private queue: File[] = [];

  constructor() {
    this.destroyRef.onDestroy(() => this.pipeline.cancel());

    // Signal inputs don't fire `ngOnChanges` — this is the reactive
    // replacement, seeding local nav state from the inputs both on first
    // render and whenever a host (e.g. navigating to a different record's
    // form without this component being destroyed/recreated) changes them.
    // `untracked` so writing the local nav signals here doesn't fold them
    // into this effect's own dependency set — only the three inputs should.
    effect(() => {
      const entityName = this.entityName();
      const recordId   = this.recordId();
      const folder      = this.folder();
      untracked(() => {
        const scopedFolder = entityName && recordId ? folder : null;
        this.curEntity.set(entityName);
        this.curRecordId.set(recordId);
        this.curRecordName.set(null);
        this.curFolder.set(scopedFolder);
        this.resetFolderTree();
        if (entityName && recordId) this.revealInTree(scopedFolder);
        this.load();
      });
    });
  }

  // ── Derived view state ───────────────────────────────────────────────────

  readonly crumbs = computed(() => {
    const out: Crumb[] = [];
    if (this.entityName() === null) {
      out.push({ label: 'Documents', entity: null, recordId: null, recordName: null, folder: null });
    }
    const entity = this.curEntity();
    if (entity) out.push({ label: entity, entity, recordId: null, recordName: null, folder: null });
    const recordId = this.curRecordId();
    const recordName = this.curRecordName();
    if (recordId) out.push({ label: recordName ?? recordId, entity, recordId, recordName, folder: null });
    const folder = this.curFolder();
    if (folder) {
      let acc = '';
      for (const seg of folder.split('/')) {
        acc = acc ? `${acc}/${seg}` : seg;
        out.push({ label: seg, entity, recordId, recordName, folder: acc });
      }
    }
    return out;
  });

  readonly tiles = computed<BrowserTile[]>(() => {
    const data = this.treeData();
    if (!data) return [];
    if (data.entities.length) {
      return data.entities.map(e => ({
        key: e.entity_name, label: e.display_name, count: e.document_count, kind: 'entity' as const, raw: e,
        created_at: null as string | null,
      }));
    }
    if (data.records.length) {
      return data.records.map(r => ({
        key: r.record_id, label: r.display_name, count: r.document_count, kind: 'record' as const, raw: r,
        created_at: null as string | null,
      }));
    }
    const base = data.folders.map(f => ({
      path: f.folder, label: f.folder.split('/').pop() ?? f.folder, count: f.document_count, created_at: f.created_at,
    }));
    return this.normalizeFolders(base).map(n => ({
      key: n.path, label: n.label, count: n.count, kind: 'folder' as const, created_at: n.created_at ?? null,
    }));
  });

  readonly rows = computed(() => this.treeData()?.files ?? []);

  readonly rowHeight = DOCUMENT_ROW_HEIGHT_PX;

  /** Tiles first, then the in-flight upload row, then the files — the same order the list always had. */
  readonly listItems = computed<MainListItem[]>(() => {
    const items: MainListItem[] = this.filteredTiles().map(tile => ({ kind: 'tile', key: `tile:${tile.key}`, tile }));
    const upload = this.uploadState();
    if (upload === 'uploading' || upload === 'processing') items.push({ kind: 'busy', key: 'busy' });
    this.visibleRows().forEach((row, index) => items.push({ kind: 'file', key: `file:${row.id}`, row, index }));
    return items;
  });

  trackListItem(_: number, item: MainListItem): string { return item.key; }

  readonly filteredTiles = computed(() => {
    const tiles = [...this.tiles()];
    const column = this.sortColumn();
    const direction = this.sortDirection() === 'asc' ? 1 : -1;
    if (column === 'size') {
      return tiles.sort((a, b) => (a.count - b.count) * direction);
    }
    if (column === 'created_at' || column === 'modified_at') {
      // Entity/record tiles carry no date (only real folders do); they sort
      // by name within the dateless group rather than colliding at '' for
      // every unrelated tile.
      return tiles.sort((a, b) => {
        const av = a.created_at ?? '';
        const bv = b.created_at ?? '';
        if (av === bv) return a.label.localeCompare(b.label, undefined, { numeric: true, sensitivity: 'base' });
        return av.localeCompare(bv, undefined, { numeric: true, sensitivity: 'base' }) * direction;
      });
    }
    return tiles.sort((a, b) => a.label.localeCompare(b.label, undefined, { numeric: true, sensitivity: 'base' }) * direction);
  });

  /** Returns a stable, naturally sorted folder list for both browser views. */
  private normalizeFolders(base: FolderNode[]): FolderNode[] {
    const map = new Map<string, FolderNode>(base.map(n => [n.path, n]));
    return Array.from(map.values()).sort((a, b) =>
      a.label.localeCompare(b.label, undefined, { numeric: true, sensitivity: 'base' }));
  }

  // ── Sidebar folder tree ──────────────────────────────────────────────────

  canShowFolderTree(): boolean { return !!(this.curEntity() && this.curRecordId()); }

  /** Children already fetched for `parentPath` (`null` = the record's root). */
  childrenOf(parentPath: string | null): FolderNode[] {
    const base = this.folderChildren().get(parentPath ?? '') ?? [];
    return this.normalizeFolders(base);
  }

  private isFolderLoaded(parentPath: string | null): boolean {
    return this.folderChildren().has(parentPath ?? '');
  }

  isExpanded(path: string): boolean { return this.expandedFolders().has(path); }

  toggleExpand(path: string): void {
    const expanded = this.expandedFolders();
    const next = new Set(expanded);
    if (expanded.has(path)) {
      next.delete(path);
    } else {
      next.add(path);
      if (!this.isFolderLoaded(path)) this.loadFolderChildren(path);
    }
    this.expandedFolders.set(next);
  }

  selectTreeFolder(node: FolderNode): void {
    this.curFolder.set(node.path);
    this.revealInTree(node.path);
    this.load();
  }

  treeTile(node: FolderNode): { key: string; label: string; count: number; kind: 'folder'; created_at: string | null } {
    return { key: node.path, label: node.label, count: node.count, kind: 'folder', created_at: node.created_at ?? null };
  }

  private loadFolderChildren(parentPath: string | null): void {
    const key = parentPath ?? '';
    if (this.loadingFolderPaths.has(key)) return;
    const entityName = this.curEntity();
    const recordId   = this.curRecordId();
    if (!entityName || !recordId) return;
    this.loadingFolderPaths.add(key);
    const params: Record<string, string> = { entity_name: entityName, record_id: recordId };
    if (parentPath) params['folder'] = parentPath;
    this.api.get<TreeResponse>('/api/v1/documents/tree', params).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: data => {
        const nodes: FolderNode[] = data.folders.map(f => ({
          path: f.folder, label: f.folder.split('/').pop() ?? f.folder, count: f.document_count,
        }));
        this.folderChildren.update(map => { const next = new Map(map); next.set(key, nodes); return next; });
        // Also cache the files at this level so the sidebar tree can show them.
        this.folderFiles.update(map => { const next = new Map(map); next.set(key, data.files ?? []); return next; });
        this.loadingFolderPaths.delete(key);
      },
      error: () => { this.loadingFolderPaths.delete(key); },
    });
  }

  /** Files already fetched for `parentPath` in the sidebar tree (`null` = record root). */
  filesOf(parentPath: string | null): DocumentFile[] {
    return this.folderFiles().get(parentPath ?? '') ?? [];
  }

  private resetFolderTree(): void {
    this.folderChildren.set(new Map());
    this.folderFiles.set(new Map());
    this.expandedFolders.set(new Set());
    this.loadingFolderPaths.clear();
  }

  /**
   * Loads and expands every ancestor of `folder` so it's visible in the
   * sidebar tree, without touching any other branch — the tree-equivalent
   * of a Windows Explorer sidebar revealing the active folder rather than
   * replacing its contents (D-36x follow-up fix: the sidebar used to just
   * re-render `tiles()`, so it mirrored whatever level the main pane was
   * on instead of staying a stable hierarchy).
   */
  private revealInTree(folder: string | null): void {
    if (!this.isFolderLoaded(null)) this.loadFolderChildren(null);
    if (!folder) return;
    const segments = folder.split('/');
    const toExpand = new Set(this.expandedFolders());
    let acc = '';
    for (let i = 0; i < segments.length; i++) {
      acc = acc ? `${acc}/${segments[i]}` : segments[i];
      if (i < segments.length - 1) toExpand.add(acc);
      if (!this.isFolderLoaded(acc)) this.loadFolderChildren(acc);
    }
    this.expandedFolders.set(toExpand);
  }

  /**
   * Re-fetches whichever already-loaded tree level `path` lives in, so a
   * document count the main pane just changed (upload/move/copy/delete)
   * doesn't go stale in the sidebar. A no-op for a level the user never
   * expanded — it'll fetch fresh the first time it's revealed.
   */
  private refreshTreeLevel(path: string | null): void {
    if (path === null || path === '') { if (this.isFolderLoaded(null)) this.loadFolderChildren(null); return; }
    const idx = path.lastIndexOf('/');
    const parent = idx === -1 ? null : path.slice(0, idx);
    if (this.isFolderLoaded(parent)) this.loadFolderChildren(parent);
  }

  readonly visibleRows = computed(() => {
    const rows = [...this.rows()];
    const column = this.sortColumn();
    const direction = this.sortDirection() === 'asc' ? 1 : -1;
    return rows.sort((a, b) => {
      if (column === 'size') {
        const as = a.size_bytes ?? -1;
        const bs = b.size_bytes ?? -1;
        return (as - bs) * direction;
      }
      let av = '';
      let bv = '';
      if (column === 'name') {
        av = a.name;
        bv = b.name;
      } else if (column === 'created_at') {
        av = a.created_at ?? '';
        bv = b.created_at ?? '';
      } else if (column === 'modified_at') {
        av = a.modified_at ?? a.created_at ?? '';
        bv = b.modified_at ?? b.created_at ?? '';
      }
      return av.localeCompare(bv, undefined, { numeric: true, sensitivity: 'base' }) * direction;
    });
  });

  /** Only once we're scoped to one record's own folder — the root/entity/record-list levels never accept an upload. */
  readonly canUploadHere = computed(() => !!(this.curEntity() && this.curRecordId() && this.curFolder()));

  curFolderValue(): string | null { return this.curFolder(); }

  goToRecordRoot(): void {
    this.curFolder.set(null);
    this.clearSelection();
    this.load();
  }

  openRootMenu(event: MouseEvent): void {
    event.preventDefault(); event.stopPropagation();
    this.contextMenu.set({ x: event.clientX, y: event.clientY, row: null, folder: null });
  }

  sortBy(column: SortColumn): void {
    if (this.sortColumn() === column) this.sortDirection.update(value => value === 'asc' ? 'desc' : 'asc');
    else { this.sortColumn.set(column); this.sortDirection.set('asc'); }
  }

  sortIcon(column: SortColumn): string {
    if (this.sortColumn() !== column) return 'las la-sort';
    return this.sortDirection() === 'asc' ? 'las la-sort-up' : 'las la-sort-down';
  }

  /** No `file` key and not a mirrored row — the two-phase create's PATCH never landed. */
  isFailed(row: DocumentFile): boolean { return !row.file && !row.source_field; }

  /** `la-file-*` icon (+ tint class) for a row's extension, or the failed-row icon — see `EXTENSION_ICONS`. */
  fileIconClasses(row: DocumentFile): string {
    if (this.isFailed(row)) return 'la-exclamation-triangle';
    const dot = row.name.lastIndexOf('.');
    const ext = dot > 0 ? row.name.slice(dot + 1).toLowerCase() : '';
    const { icon, tint } = EXTENSION_ICONS[ext] ?? { icon: 'la-file-alt', tint: '' };
    return tint ? `${icon} ${tint}` : icon;
  }

  /** Icon glyph only, no extension tint. */
  fileIconGlyph(row: DocumentFile): string {
    return this.fileIconClasses(row).split(' ')[0];
  }

  formatDate(value: string | null | undefined): string {
    if (!value) return '--';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? '--' : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' }).format(date);
  }

  formatSize(bytes: number | null | undefined): string {
    if (bytes == null || isNaN(bytes)) return '--';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  }

  clearSelection(): void { this.selectedIds.set(new Set()); this.selectionAnchor = -1; }

  onRowKeydown(event: KeyboardEvent, row: DocumentFile, index: number): void {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    event.preventDefault();
    this.selectRow(event, row, index);
  }

  selectRow(event: MouseEvent | KeyboardEvent, row: DocumentFile, index: number): void {
    event.stopPropagation();
    const next = new Set(this.selectedIds());
    if (event.shiftKey) {
      // Shift is intentionally additive: it never clears the existing set.
      next.add(row.id);
    } else if (event.ctrlKey || event.metaKey) {
      if (next.has(row.id)) {
        next.delete(row.id);
      } else {
        next.add(row.id);
      }
    } else {
      next.clear(); next.add(row.id);
    }
    this.selectedIds.set(next);
    this.selectionAnchor = index;
    this.contextMenu.set(null);
  }

  openRowMenu(event: MouseEvent, row: DocumentFile, index: number): void {
    event.preventDefault(); event.stopPropagation();
    if (!this.selectedIds().has(row.id)) {
      this.selectedIds.set(new Set([row.id]));
      this.selectionAnchor = index;
    }
    this.contextMenu.set({ x: event.clientX, y: event.clientY, row, folder: null });
  }

  openFolderMenu(event: MouseEvent, tile: ReturnType<typeof this.tiles>[number]): void {
    event.preventDefault(); event.stopPropagation();
    this.contextMenu.set({ x: event.clientX, y: event.clientY, row: null, folder: tile.kind === 'folder' ? tile.key : null });
  }

  openBackgroundMenu(event: MouseEvent): void {
    event.preventDefault(); event.stopPropagation();
    this.contextMenu.set({ x: event.clientX, y: event.clientY, row: null, folder: this.curFolder() });
  }

  closeContextMenu(): void { this.contextMenu.set(null); }

  @HostListener('document:keydown.escape')
  onEscape(): void { this.closeContextMenu(); this.clearSelection(); }

  startRowDrag(event: DragEvent, row: DocumentFile): void {
    if (!this.selectedIds().has(row.id)) this.selectedIds.set(new Set([row.id]));
    event.dataTransfer?.setData('application/x-attome-documents', [...this.selectedIds()].join(','));
    if (event.dataTransfer) event.dataTransfer.effectAllowed = 'move';
  }

  onFolderDragOver(event: DragEvent, key: string): void {
    if (!event.dataTransfer?.types.includes('application/x-attome-documents')) return;
    event.preventDefault(); event.stopPropagation(); this.dragTarget.set(key);
    event.dataTransfer.dropEffect = 'move';
  }

  dropIntoFolder(event: DragEvent, tile: ReturnType<typeof this.tiles>[number]): void {
    event.preventDefault(); event.stopPropagation(); this.dragTarget.set(null);
    if (tile.kind !== 'folder') return;
    const ids = new Set((event.dataTransfer?.getData('application/x-attome-documents') ?? '').split(',').filter(Boolean));
    this.moveDocuments(ids, tile.key);
  }

  canChangeSelection(): boolean {
    return this.rows().some(row => this.selectedIds().has(row.id) && !row.source_field);
  }

  canRenameSelection(): boolean {
    return this.rows().filter(row => this.selectedIds().has(row.id) && !row.source_field).length === 1;
  }

  canCreateFolder(): boolean {
    return !!(this.curEntity() && this.curRecordId());
  }

  pasteTarget(): string | null { return this.contextMenu()?.folder ?? this.curFolder(); }

  addNewDocument(): void {
    const target = this.pasteTarget();
    if (!target) return;
    this.uploadTargetFolder = target;
    this.closeContextMenu();
    this.newDocumentInput()?.nativeElement.click();
  }

  async addNewFolder(): Promise<void> {
    if (!this.canCreateFolder()) return;
    const base = this.contextMenu()?.folder ?? this.curFolder() ?? '';
    this.closeContextMenu();
    const name = await this.dialogSvc.prompt({
      title: 'New Folder',
      placeholder: 'Folder name',
      confirmText: 'Create Folder',
      validator: (val: string) => {
        if (!val.trim()) return 'Folder name cannot be empty.';
        if (val.includes('/') || val.includes('\\')) return 'Folder name cannot contain slashes.';
        return null;
      },
    });
    if (!name) return;
    const folderName = name.trim();
    const targetFolder = base ? `${base}/${folderName}` : folderName;
    const entityName = this.curEntity();
    const recordId = this.curRecordId();
    if (!entityName || !recordId) return;
    this.busy.set(true);
    this.api.post<{ id: string; folder: string }>('/api/v1/documents/folders', {
      entity_name: entityName, record_id: recordId, folder: targetFolder,
    }).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: () => {
        this.busy.set(false);
        this.refreshTreeLevel(targetFolder);
        this.load();
      },
      error: (err: unknown) => {
        this.busy.set(false);
        const message = typeof err === 'object' && err !== null && 'message' in err
          ? String((err as { message: unknown }).message)
          : 'Could not save the folder.';
        this.dialogSvc.error({ title: 'Create Folder Failed', message });
      },
    });
  }

  onNewDocumentsSelected(files: FileList | null): void {
    if (!files?.length || !this.uploadTargetFolder) return;
    this.curFolder.set(this.uploadTargetFolder);
    this.uploadTargetFolder = null;
    this.onFilesSelected(files);
  }

  cutSelection(): void {
    if (!this.canChangeSelection()) return;
    this.clipboardIds.set(new Set(this.selectedIds())); this.clipboardMode.set('cut'); this.closeContextMenu();
  }

  copySelection(): void {
    if (!this.canChangeSelection()) return;
    this.clipboardIds.set(new Set(this.selectedIds())); this.clipboardMode.set('copy'); this.closeContextMenu();
  }

  pasteIntoMenuFolder(): void {
    const target = this.contextMenu()?.folder ?? this.curFolder();
    if (target && this.clipboardMode() === 'cut') this.moveDocuments(this.clipboardIds(), target);
    else if (target && this.clipboardMode() === 'copy') this.copyDocuments(this.clipboardIds(), target);
    this.closeContextMenu();
  }

  private copyDocuments(ids: Set<string>, folder: string): void {
    const entityName = this.curEntity(), recordId = this.curRecordId();
    const rows = this.rows().filter(row => ids.has(row.id) && !row.source_field);
    if (!entityName || !recordId || !rows.length) return;
    this.busy.set(true);
    Promise.all(rows.map(row => new Promise<void>((resolve, reject) =>
      this.entitySvc.create(DOCUMENT_ENTITY, {
        name: row.name, file: row.file, entity_name: entityName, record_id: recordId, folder,
      }).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({ next: () => resolve(), error: reject })
    ))).then(() => {
      this.busy.set(false); this.clipboardIds.set(new Set()); this.clipboardMode.set(null); this.clearSelection();
      this.refreshTreeLevel(folder);
      this.load();
    }).catch(() => {
      this.busy.set(false);
      this.dialogSvc.error({ title: 'Copy Failed', message: 'Some documents could not be copied.' });
      this.load();
    });
  }

  async renameSelected(): Promise<void> {
    const row = this.rows().find(candidate => this.selectedIds().has(candidate.id));
    if (!row || row.source_field) return;
    this.closeContextMenu();
    const name = await this.dialogSvc.prompt({
      title: 'Rename document',
      value: row.name,
      confirmText: 'Rename',
      selectStem: true,
      validator: (val: string) => {
        if (!val.trim()) return 'Document name cannot be empty.';
        return null;
      },
    });
    if (!name || name === row.name) return;
    this.busy.set(true);
    this.entitySvc.update(DOCUMENT_ENTITY, row.id, { name }, row.row_version ?? 0).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: () => {
        this.busy.set(false);
        this.load();
      },
      error: (err: unknown) => {
        this.busy.set(false);
        const message = typeof err === 'object' && err !== null && 'message' in err
          ? String((err as { message: unknown }).message)
          : 'Could not rename the document.';
        this.dialogSvc.error({
          title: 'Rename Failed',
          message: message || 'Could not rename the document.',
        });
      },
    });
  }

  async deleteSelection(): Promise<void> {
    const rows = this.rows().filter(row => this.selectedIds().has(row.id) && !row.source_field);
    if (!rows.length) return;
    this.closeContextMenu();
    const confirmed = await this.dialogSvc.confirm({
      title: 'Delete Document' + (rows.length === 1 ? '' : 's'),
      message: `Are you sure you want to delete ${rows.length} selected document${rows.length === 1 ? '' : 's'}? This action cannot be undone.`,
      variant: 'danger',
      confirmText: 'Delete',
    });
    if (!confirmed) return;
    this.busy.set(true);
    Promise.all(rows.map(row => new Promise<void>((resolve, reject) =>
      this.entitySvc.delete(DOCUMENT_ENTITY, row.id).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({ next: () => resolve(), error: reject })
    ))).then(() => {
      this.busy.set(false);
      this.clearSelection();
      this.refreshTreeLevel(this.curFolder());
      this.load();
    }).catch(() => {
      this.busy.set(false);
      this.dialogSvc.error({
        title: 'Delete Failed',
        message: 'Some documents could not be deleted.',
      });
      this.load();
    });
  }

  private moveDocuments(ids: Set<string>, folder: string): void {
    const rows = this.rows().filter(row => ids.has(row.id) && !row.source_field);
    if (!rows.length || folder === this.curFolder()) return;
    const sourceFolder = this.curFolder();
    this.busy.set(true);
    Promise.all(rows.map(row => new Promise<void>((resolve, reject) =>
      this.entitySvc.update(DOCUMENT_ENTITY, row.id, { folder }, row.row_version ?? 0).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({ next: () => resolve(), error: reject })
    ))).then(() => {
      this.busy.set(false);
      this.clipboardIds.set(new Set());
      this.clipboardMode.set(null);
      this.clearSelection();
      this.refreshTreeLevel(sourceFolder);
      this.refreshTreeLevel(folder);
      this.load();
    }).catch(() => {
      this.busy.set(false);
      this.dialogSvc.error({
        title: 'Move Failed',
        message: 'Some documents could not be moved.',
      });
      this.load();
    });
  }

  startMarquee(event: PointerEvent): void {
    const target = event.target as HTMLElement;
    if (event.button !== 0 || target.closest('.xdf-row, button, input')) return;
    const host = event.currentTarget as HTMLElement;
    const rect = host.getBoundingClientRect();
    this.marqueeOrigin = {
      x: event.clientX - rect.left, y: event.clientY - rect.top, host,
      additive: event.shiftKey, initial: new Set(this.selectedIds()),
    };
    if (!event.shiftKey) this.selectedIds.set(new Set());
    host.setPointerCapture(event.pointerId);
  }

  @HostListener('document:pointermove', ['$event'])
  onMarqueeMove(event: PointerEvent): void {
    const origin = this.marqueeOrigin;
    if (!origin) return;
    const hostRect = origin.host.getBoundingClientRect();
    const x = event.clientX - hostRect.left, y = event.clientY - hostRect.top;
    const box = { left: Math.min(origin.x, x), top: Math.min(origin.y, y), width: Math.abs(x - origin.x), height: Math.abs(y - origin.y) };
    this.marquee.set(box);
    const selected = origin.additive ? new Set(origin.initial) : new Set<string>();
    for (const element of Array.from(origin.host.querySelectorAll<HTMLElement>('[data-document-id]'))) {
      const rect = element.getBoundingClientRect();
      const local = { left: rect.left - hostRect.left, top: rect.top - hostRect.top, right: rect.right - hostRect.left, bottom: rect.bottom - hostRect.top };
      if (box.left <= local.right && box.left + box.width >= local.left && box.top <= local.bottom && box.top + box.height >= local.top) {
        selected.add(element.dataset['documentId']!);
      }
    }
    this.selectedIds.set(selected);
  }

  @HostListener('document:pointerup')
  endMarquee(): void { this.marqueeOrigin = null; this.marquee.set(null); }

  // ── Navigation ────────────────────────────────────────────────────────────

  enter(tile: ReturnType<typeof this.tiles>[number]): void {
    if (tile.kind === 'entity') {
      this.curEntity.set(tile.key);
    } else if (tile.kind === 'record') {
      this.curRecordId.set(tile.key);
      this.curRecordName.set(tile.label);
      this.curFolder.set(''); // enter the record's root — folders() below normalizes '' to the top level
      this.resetFolderTree();
      this.revealInTree('');
    } else {
      this.curFolder.set(tile.key);
      this.revealInTree(tile.key);
    }
    this.load();
  }

  goTo(crumb: { entity: string | null; recordId: string | null; recordName: string | null; folder: string | null }): void {
    this.curEntity.set(crumb.entity);
    this.curRecordId.set(crumb.recordId);
    this.curRecordName.set(crumb.recordName);
    this.curFolder.set(crumb.folder);
    this.load();
  }

  // ── Data load ─────────────────────────────────────────────────────────────

  private load(): void {
    this.loading.set(true);
    this.error.set(null);
    const params: Record<string, string> = {};
    const entityName = this.curEntity();
    const recordId   = this.curRecordId();
    const folder      = this.curFolder();
    if (entityName) params['entity_name'] = entityName;
    if (recordId)   params['record_id']   = recordId;
    if (folder)      params['folder']      = folder;

    this.api.get<TreeResponse>('/api/v1/documents/tree', params).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: data => {
        this.treeData.set(data);
        this.loadedOnce.set(true);
        this.loading.set(false);
      },
      error: () => {
        this.error.set('Could not load documents.');
        this.loading.set(false);
      },
    });
  }

  // ── Download / remove ────────────────────────────────────────────────────

  download(row: DocumentFile): void {
    this.downloadingId.set(row.id);
    this.fileSvc.getDownloadUrl(DOCUMENT_ENTITY, row.id, 'file').pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: res => {
        this.downloadingId.set(null);
        window.open(res.download_url, '_blank', 'noopener');
      },
      error: () => { this.downloadingId.set(null); },
    });
  }

  remove(row: DocumentFile): void {
    this.busy.set(true);
    this.entitySvc.delete(DOCUMENT_ENTITY, row.id).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: () => { this.busy.set(false); this.refreshTreeLevel(this.curFolder()); this.load(); },
      error: () => { this.busy.set(false); },
    });
  }

  // ── Upload (drag/drop, paste, browse) ────────────────────────────────────

  onDragOver(event: DragEvent): void { event.preventDefault(); this.dragging.set(true); }
  onDragLeave(event: DragEvent): void { event.preventDefault(); this.dragging.set(false); }

  onDrop(event: DragEvent): void {
    event.preventDefault();
    this.dragging.set(false);
    this.onFilesSelected(event.dataTransfer?.files ?? null);
  }

  onPaste(event: ClipboardEvent): void {
    const files = event.clipboardData?.files;
    if (files?.length) {
      event.preventDefault();
      this.onFilesSelected(files);
    }
  }

  onFilesSelected(files: FileList | null): void {
    if (!files?.length) return;
    this.queue.push(...Array.from(files));
    if (this.uploadState() === 'idle') void this.processQueue();
  }

  private async processQueue(): Promise<void> {
    const entityName = this.curEntity();
    const recordId   = this.curRecordId();
    const folder      = this.curFolder();
    if (!entityName || !recordId || !folder) { this.queue = []; return; }

    while (this.queue.length) {
      const file = this.queue.shift()!;
      this.uploadingName.set(file.name);
      this.uploadState.set('uploading');
      this.uploadProgress.set(0);
      this.uploadMessage.set(null);

      try {
        // Two-phase create — see the class doc comment for why an upload
        // session can't be requested before the row exists.
        const created = await new Promise<EntityRecordResponse>((resolve, reject) => {
          this.entitySvc.create(DOCUMENT_ENTITY, {
            name: file.name, entity_name: entityName, record_id: recordId, folder,
          }).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({ next: resolve, error: reject });
        });

        const result = await this.pipeline.run(
          { entityName: DOCUMENT_ENTITY, recordId: created.id, fieldName: 'file' },
          file,
          {
            onPhase:    phase   => { this.uploadState.set(phase); },
            onProgress: percent => { this.uploadProgress.set(percent); },
          },
        );

        if (result.kind === 'clean') {
          await new Promise<void>((resolve, reject) => {
            this.entitySvc.update(DOCUMENT_ENTITY, created.id, { file: result.finalKey }, 0)
              .pipe(takeUntilDestroyed(this.destroyRef)).subscribe({ next: () => resolve(), error: reject });
          });
        } else {
          // Upload didn't complete — leave the empty row soft-deletable by
          // the user rather than silently deleting it ourselves; surfacing
          // the failure is more honest than hiding a row the user did try
          // to create.
          this.uploadMessage.set(`${file.name}: ${result.message}`);
        }
      } catch {
        this.uploadState.set('error');
        this.uploadMessage.set(`${file.name}: upload failed.`);
      }
    }

    this.queue = [];
    if (this.uploadState() !== 'error') this.uploadState.set('idle');
    this.refreshTreeLevel(this.curFolder());
    this.load();
  }
}
