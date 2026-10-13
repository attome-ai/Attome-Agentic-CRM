import {
  ChangeDetectionStrategy, Component, HostListener, computed, effect, inject, input, output, signal,
} from '@angular/core';
import { NgTemplateOutlet } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiError } from '@attome/base';
import { ContentAdminService, PageSummary } from '../../../services/content-admin.service';

/**
 * The "PAGES" sidebar — a search box + editorial hierarchy tree. Reused by
 * both the pages landing screen (`ContentPageListComponent`) and the
 * per-page editor (`ContentPageEditorComponent`), so the two never drift.
 *
 * Deliberately drag-free (v1 scope): reparenting a page is an explicit
 * "Move" action on its context menu, not drag-and-drop — keeps this
 * component far smaller than `DocumentFolderBrowserComponent`'s tree, which
 * needs drag/drop for a much higher-frequency operation (filing documents).
 */
@Component({
  selector: 'attome-content-page-tree',
  standalone: true,
  imports: [FormsModule, NgTemplateOutlet],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls: ['./content-page-tree.component.css'],
  templateUrl: './content-page-tree.component.html',
})
export class ContentPageTreeComponent {
  /** Every list/search this tree performs is scoped to this space. */
  readonly spaceId = input.required<string>();
  /** Currently-open page, if any — highlighted in the tree. */
  readonly selectedId = input<string | null>(null);
  readonly pageSelected = output<PageSummary>();
  /** Fires after a create/delete/move so a host page can refresh its own state. */
  readonly treeChanged = output<void>();

  private readonly svc = inject(ContentAdminService);

  readonly error = signal<string | null>(null);
  readonly searchInput = signal('');
  readonly searchQuery = signal('');
  readonly searchResults = signal<PageSummary[]>([]);

  readonly expandedIds = signal<Set<string>>(new Set());
  private readonly childrenByParent = signal<Map<string | null, PageSummary[]>>(new Map());
  readonly loadedRoot = computed(() => this.childrenByParent().has(null));
  private readonly loadingParents = new Set<string | null>();
  private searchDebounce: ReturnType<typeof setTimeout> | null = null;

  readonly menu = signal<{ x: number; y: number; page: PageSummary } | null>(null);

  constructor() {
    // Reruns whenever `spaceId` changes (a host screen switching the
    // selected space) and resets everything scoped to the previous space —
    // `effect()`, not a bare constructor call, so it reruns on later changes
    // too, not just the first render.
    effect(() => {
      this.spaceId();
      this.childrenByParent.set(new Map());
      this.expandedIds.set(new Set());
      this.loadingParents.clear();
      this.searchInput.set('');
      this.searchQuery.set('');
      this.loadChildren(null);
    });
  }

  childrenOf(parentId: string | null): PageSummary[] {
    return this.childrenByParent().get(parentId) ?? [];
  }

  isExpanded(id: string): boolean {
    return this.expandedIds().has(id);
  }

  toggleExpand(id: string): void {
    const next = new Set(this.expandedIds());
    if (next.has(id)) {
      next.delete(id);
    } else {
      next.add(id);
      if (!this.childrenByParent().has(id)) this.loadChildren(id);
    }
    this.expandedIds.set(next);
  }

  select(page: PageSummary): void {
    this.pageSelected.emit(page);
  }

  onSearchChange(value: string): void {
    this.searchInput.set(value);
    if (this.searchDebounce) clearTimeout(this.searchDebounce);
    this.searchDebounce = setTimeout(() => {
      const query = value.trim();
      this.searchQuery.set(query);
      if (!query) return;
      this.svc.searchPages(this.spaceId(), query).subscribe({
        next: results => this.searchResults.set(results),
        error: (e: ApiError) => this.error.set(e.message),
      });
    }, 250);
  }

  private loadChildren(parentId: string | null): void {
    if (this.loadingParents.has(parentId)) return;
    this.loadingParents.add(parentId);
    this.svc.listPages(this.spaceId(), parentId ?? undefined).subscribe({
      next: pages => {
        this.childrenByParent.update(map => {
          const next = new Map(map);
          next.set(parentId, pages);
          return next;
        });
        this.loadingParents.delete(parentId);
      },
      error: (e: ApiError) => {
        this.error.set(e.message);
        this.loadingParents.delete(parentId);
      },
    });
  }

  /** Re-fetches one already-loaded level — used after a create/move/delete
   *  so the tree reflects it without a full reload. */
  refreshLevel(parentId: string | null): void {
    this.loadChildren(parentId);
  }

  openMenu(event: MouseEvent, page: PageSummary): void {
    event.preventDefault();
    event.stopPropagation();
    this.menu.set({ x: event.clientX, y: event.clientY, page });
  }

  closeMenu(): void {
    this.menu.set(null);
  }

  @HostListener('document:click')
  onDocumentClick(): void {
    this.closeMenu();
  }

  startMove(page: PageSummary): void {
    this.closeMenu();
    const targetId = prompt(
      `Move "${page.title}" under which page id? Leave blank for the top level.`,
      page.parent_page_id ?? '',
    );
    if (targetId === null) return;
    this.svc.movePage(page.id, targetId.trim() || null).subscribe({
      next: () => {
        this.refreshLevel(page.parent_page_id);
        this.refreshLevel(targetId.trim() || null);
        this.treeChanged.emit();
      },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  remove(page: PageSummary): void {
    this.closeMenu();
    if (!confirm(`Delete "${page.title}"? This does not delete its child pages.`)) return;
    this.svc.deletePage(page.id).subscribe({
      next: () => {
        this.refreshLevel(page.parent_page_id);
        this.treeChanged.emit();
      },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }
}
