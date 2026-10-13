import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { ApiError } from '@attome/base';
import {
  Block, BlockKind, ContentAdminService, PageDetail, PageStats, PageSummary,
} from '../../../services/content-admin.service';
import { ContentBlockViewComponent } from '@attome/xrm/content/view';
import { ContentPageTreeComponent } from '../../tree/content-page-tree/content-page-tree.component';

interface BlockTypeInfo { kind: BlockKind; label: string; icon: string; description: string; category: string; }

/** The block library — mirrors `attome_content::model::BlockKind` exactly. */
const BLOCK_TYPES: BlockTypeInfo[] = [
  { kind: 'heading', label: 'Heading', icon: 'la-heading', description: 'Page titles and section headings.', category: 'Basic' },
  { kind: 'rich_text', label: 'Rich text', icon: 'la-align-left', description: 'Paragraphs, links and formatting.', category: 'Basic' },
  { kind: 'alert', label: 'Alert', icon: 'la-exclamation-circle', description: 'Contextual notices and messages.', category: 'Basic' },
  { kind: 'image', label: 'Image', icon: 'la-image', description: 'Responsive image block.', category: 'Media' },
  { kind: 'columns', label: 'Columns', icon: 'la-columns', description: 'Build multi-column layouts.', category: 'Layout' },
  { kind: 'data_table', label: 'Data table', icon: 'la-table', description: 'Static or query-backed records.', category: 'Data' },
  { kind: 'chart', label: 'Chart', icon: 'la-chart-bar', description: 'Visualize metrics and query results.', category: 'Data' },
  { kind: 'form', label: 'Form', icon: 'la-wpforms', description: 'Create or update records.', category: 'Forms' },
  { kind: 'component', label: 'Component', icon: 'la-cube', description: 'Reusable application component.', category: 'Advanced' },
];

function defaultProps(kind: BlockKind): Record<string, unknown> {
  switch (kind) {
    case 'heading':    return { text: 'New heading', level: 2 };
    case 'rich_text':  return { html: '<p>New paragraph.</p>' };
    case 'alert':      return { message: 'Notice.', variant: 'info' };
    case 'image':      return { src: '', alt: '' };
    case 'columns':    return { columns: [{ blocks: [] }, { blocks: [] }] };
    case 'data_table':
    case 'chart':      return { query_id: '' };
    case 'form':       return { entity: '', fields: [], submit_label: 'Submit' };
    case 'component':  return { component_key: 'cta-banner' };
  }
}

function newBlock(kind: BlockKind): Block {
  return { id: crypto.randomUUID(), kind, props: defaultProps(kind) };
}

type LibraryTarget = 'canvas' | { columnsBlockId: string; columnIndex: number };

@Component({
  selector: 'attome-content-page-editor',
  standalone: true,
  imports: [FormsModule, RouterLink, ContentPageTreeComponent, ContentBlockViewComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls: ['../../../../styles/admin-page.css', './content-page-editor.component.css'],
  templateUrl: './content-page-editor.component.html',
})
export class ContentPageEditorComponent {
  private readonly svc = inject(ContentAdminService);
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);

  readonly allowedComponents = ['cta-banner', 'pricing-table', 'testimonial-grid', 'newsletter-signup'];

  readonly loading = signal(true);
  readonly loadError = signal<string | null>(null);
  readonly page = signal<PageDetail | null>(null);
  readonly blocks = signal<Block[]>([]);
  readonly selectedBlockId = signal<string | null>(null);
  readonly inspectorTab = signal<'content' | 'appearance' | 'data'>('content');
  readonly previewMode = signal(false);

  readonly saving = signal(false);
  readonly publishing = signal(false);
  readonly statusMessage = signal<string | null>(null);
  readonly saveError = signal<string | null>(null);

  readonly library = signal<LibraryTarget | null>(null);
  private canvasInsertAfter: number | null = null;
  librarySearch = '';

  readonly columnsEditorFor = signal<string | null>(null);

  readonly showSettings = signal(false);
  readonly savingSettings = signal(false);
  readonly settingsError = signal<string | null>(null);
  settingsTitle = '';
  settingsUrlPath = '';
  settingsSeoTitle = '';
  settingsSeoDescription = '';
  /** M37 Phase 2 (D-452) — ISO date string (`YYYY-MM-DD`) or `''` for "not set". */
  settingsReviewBy = '';
  readonly savingReviewBy = signal(false);
  readonly reviewByError = signal<string | null>(null);
  readonly stats = signal<PageStats | null>(null);
  /** Whether the currently-loaded page is past its own `review_by` —
   *  computed client-side from the same date the settings panel edits,
   *  since `page()` already has it and a round trip isn't needed just to
   *  render a badge. */
  readonly isStale = computed(() => {
    const p = this.page();
    if (!p?.review_by) return false;
    return p.review_by < new Date().toISOString().slice(0, 10);
  });

  /** Currently-related pages, kept as full objects (not just ids) so their
   *  titles render even when the search box is empty. */
  private readonly relatedSelectedPages = signal<PageSummary[]>([]);
  private readonly relatedSearchResults = signal<PageSummary[]>([]);
  readonly relatedSelectedIds = computed(() => new Set(this.relatedSelectedPages().map(p => p.id)));
  readonly relatedCandidates = computed(() => {
    const seen = new Set<string>();
    const merged: PageSummary[] = [];
    for (const p of [...this.relatedSelectedPages(), ...this.relatedSearchResults()]) {
      if (seen.has(p.id)) continue;
      seen.add(p.id);
      merged.push(p);
    }
    return merged;
  });
  readonly relatedError = signal<string | null>(null);
  readonly savingRelated = signal(false);
  relatedSearch = '';
  private relatedSearchDebounce: ReturnType<typeof setTimeout> | null = null;

  readonly selectedBlock = computed(() =>
    this.blocks().find(b => b.id === this.selectedBlockId()) ?? null);

  constructor() {
    this.route.paramMap.subscribe(params => {
      const id = params.get('id');
      if (id) this.load(id);
    });
  }

  private load(id: string): void {
    this.loading.set(true);
    this.loadError.set(null);
    this.selectedBlockId.set(null);
    this.svc.getPage(id).subscribe({
      next: p => {
        this.page.set(p);
        this.blocks.set(p.blocks_draft);
        this.loading.set(false);
      },
      error: (e: ApiError) => {
        this.loadError.set(e.message);
        this.loading.set(false);
      },
    });
  }

  goTo(id: string): void {
    void this.router.navigate(['/xrm/admin/content/pages', id]);
  }

  labelFor(kind: BlockKind): string {
    return BLOCK_TYPES.find(t => t.kind === kind)?.label ?? kind;
  }

  selectBlock(id: string): void {
    this.selectedBlockId.set(id);
    this.inspectorTab.set('content');
  }

  strProp(block: Block, key: string): string {
    const v = block.props[key];
    return typeof v === 'string' ? v : '';
  }

  numProp(block: Block, key: string, fallback: number): number {
    const v = block.props[key];
    return typeof v === 'number' ? v : fallback;
  }

  fieldsProp(block: Block): string {
    const v = block.props['fields'];
    return Array.isArray(v) ? v.join(', ') : '';
  }

  setFieldsProp(blockId: string, value: string): void {
    const fields = value.split(',').map(s => s.trim()).filter(Boolean);
    this.setProp(blockId, 'fields', fields);
  }

  setProp(blockId: string, key: string, value: unknown): void {
    this.blocks.update(list => list.map(b =>
      b.id === blockId ? { ...b, props: { ...b.props, [key]: value } } : b));
  }

  duplicateBlock(index: number): void {
    this.blocks.update(list => {
      const copy: Block = { ...list[index], id: crypto.randomUUID() };
      const next = [...list];
      next.splice(index + 1, 0, copy);
      return next;
    });
  }

  removeBlock(index: number): void {
    const removed = this.blocks()[index];
    this.blocks.update(list => list.filter((_, i) => i !== index));
    if (this.selectedBlockId() === removed?.id) this.selectedBlockId.set(null);
  }

  columnsOf(blockId: string): { blocks: Block[] }[] {
    const block = this.blocks().find(b => b.id === blockId);
    const raw = block?.props['columns'];
    return Array.isArray(raw) ? (raw as { blocks: Block[] }[]) : [];
  }

  removeColumnBlock(blockId: string, columnIndex: number, blockIndex: number): void {
    this.blocks.update(list => list.map(b => {
      if (b.id !== blockId) return b;
      const columns = [...(b.props['columns'] as { blocks: Block[] }[])];
      columns[columnIndex] = { blocks: columns[columnIndex].blocks.filter((_, i) => i !== blockIndex) };
      return { ...b, props: { ...b.props, columns } };
    }));
  }

  openLibrary(target: LibraryTarget, insertAfter?: number): void {
    this.canvasInsertAfter = insertAfter ?? null;
    this.librarySearch = '';
    this.library.set(target);
  }

  closeLibrary(): void {
    this.library.set(null);
  }

  filteredBlockTypes(target: LibraryTarget): BlockTypeInfo[] {
    const query = this.librarySearch.trim().toLowerCase();
    // Columns cannot themselves contain a columns block — a one-level-deep
    // layout is enough for this UI and avoids unbounded nesting complexity.
    const pool = target === 'canvas' ? BLOCK_TYPES : BLOCK_TYPES.filter(t => t.kind !== 'columns');
    if (!query) return pool;
    return pool.filter(t => t.label.toLowerCase().includes(query) || t.description.toLowerCase().includes(query));
  }

  pickBlockType(kind: BlockKind): void {
    const target = this.library();
    const block = newBlock(kind);
    if (target === 'canvas') {
      this.blocks.update(list => {
        const next = [...list];
        const at = this.canvasInsertAfter === null ? next.length : this.canvasInsertAfter + 1;
        next.splice(at, 0, block);
        return next;
      });
      this.selectBlock(block.id);
    } else if (target) {
      this.blocks.update(list => list.map(b => {
        if (b.id !== target.columnsBlockId) return b;
        const columns = [...(b.props['columns'] as { blocks: Block[] }[])];
        columns[target.columnIndex] = { blocks: [...columns[target.columnIndex].blocks, block] };
        return { ...b, props: { ...b.props, columns } };
      }));
    }
    this.closeLibrary();
  }

  saveDraft(): void {
    const page = this.page();
    if (!page) return;
    this.saving.set(true);
    this.saveError.set(null);
    this.statusMessage.set(null);
    this.svc.updatePage(page.id, { blocks: this.blocks() }, page.row_version).subscribe({
      next: updated => {
        this.page.set(updated);
        this.saving.set(false);
        this.statusMessage.set('Draft saved.');
      },
      error: (e: ApiError) => {
        this.saving.set(false);
        this.saveError.set(e.message);
      },
    });
  }

  publish(): void {
    const page = this.page();
    if (!page) return;
    // Publish acts on whatever's already saved server-side, so save the
    // current draft first — otherwise a "Publish" click right after an edit
    // would publish the previous draft, silently dropping the edit.
    this.publishing.set(true);
    this.saveError.set(null);
    this.svc.updatePage(page.id, { blocks: this.blocks() }, page.row_version).subscribe({
      next: updated => {
        this.page.set(updated);
        this.svc.publishPage(page.id).subscribe({
          next: () => {
            this.publishing.set(false);
            this.statusMessage.set('Published.');
            this.load(page.id);
          },
          error: (e: ApiError) => {
            this.publishing.set(false);
            this.saveError.set(e.message);
          },
        });
      },
      error: (e: ApiError) => {
        this.publishing.set(false);
        this.saveError.set(e.message);
      },
    });
  }

  openSettings(): void {
    const p = this.page();
    if (!p) return;
    this.settingsTitle = p.title;
    this.settingsUrlPath = p.url_path;
    this.settingsSeoTitle = p.seo_title ?? '';
    this.settingsSeoDescription = p.seo_description ?? '';
    this.settingsReviewBy = p.review_by ?? '';
    this.reviewByError.set(null);
    this.settingsError.set(null);
    this.showSettings.set(true);

    this.stats.set(null);
    this.svc.pageStats(p.id).subscribe({
      next: s => this.stats.set(s),
      // Non-fatal: the stats panel just stays empty. A caller who cannot
      // reach analytics should not be blocked from editing the page.
      error: () => this.stats.set(null),
    });

    this.relatedSearch = '';
    this.relatedSearchResults.set([]);
    this.relatedError.set(null);
    this.svc.relatedPages(p.id).subscribe({
      next: related => this.relatedSelectedPages.set(related),
      error: (e: ApiError) => this.relatedError.set(e.message),
    });
  }

  saveSettings(): void {
    const p = this.page();
    if (!p) return;
    this.savingSettings.set(true);
    this.settingsError.set(null);
    this.svc.updatePage(p.id, {
      title: this.settingsTitle,
      url_path: this.settingsUrlPath,
      seo_title: this.settingsSeoTitle,
      seo_description: this.settingsSeoDescription,
    }, p.row_version).subscribe({
      next: updated => {
        this.page.set(updated);
        this.savingSettings.set(false);
        this.showSettings.set(false);
      },
      error: (e: ApiError) => {
        this.savingSettings.set(false);
        this.settingsError.set(e.message);
      },
    });
  }

  /** M37 Phase 2 (D-452) — a separate save from `saveSettings` (its own
   *  endpoint, `PATCH .../review-by`), so setting a review date does not
   *  require also touching title/url_path/SEO fields in the same request. */
  saveReviewBy(): void {
    const p = this.page();
    if (!p) return;
    this.savingReviewBy.set(true);
    this.reviewByError.set(null);
    this.svc.setReviewBy(p.id, this.settingsReviewBy || null, p.row_version).subscribe({
      next: updated => {
        this.page.set(updated);
        this.savingReviewBy.set(false);
      },
      error: (e: ApiError) => {
        this.savingReviewBy.set(false);
        this.reviewByError.set(e.message);
      },
    });
  }

  onRelatedSearchChange(): void {
    const p = this.page();
    if (!p) return;
    if (this.relatedSearchDebounce) clearTimeout(this.relatedSearchDebounce);
    const query = this.relatedSearch.trim();
    if (!query) {
      this.relatedSearchResults.set([]);
      return;
    }
    this.relatedSearchDebounce = setTimeout(() => {
      this.svc.searchPages(p.content_space_id, query).subscribe({
        next: results => this.relatedSearchResults.set(results.filter(r => r.id !== p.id)),
        error: (e: ApiError) => this.relatedError.set(e.message),
      });
    }, 250);
  }

  toggleRelated(id: string): void {
    if (this.relatedSelectedIds().has(id)) {
      this.relatedSelectedPages.update(list => list.filter(p => p.id !== id));
      return;
    }
    const candidate = this.relatedCandidates().find(p => p.id === id);
    if (candidate) this.relatedSelectedPages.update(list => [...list, candidate]);
  }

  saveRelated(): void {
    const p = this.page();
    if (!p) return;
    this.savingRelated.set(true);
    this.relatedError.set(null);
    this.svc.setRelatedPages(p.id, [...this.relatedSelectedIds()]).subscribe({
      next: related => {
        this.relatedSelectedPages.set(related);
        this.savingRelated.set(false);
      },
      error: (e: ApiError) => {
        this.savingRelated.set(false);
        this.relatedError.set(e.message);
      },
    });
  }
}
