import { ChangeDetectionStrategy, Component, computed, inject, signal, viewChild } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { ApiError } from '@attome/base';
import { ContentAdminService, ContentSpace, ContentTemplate, PageSummary } from '../../../services/content-admin.service';
import { ContentPageTreeComponent } from '../../tree/content-page-tree/content-page-tree.component';

/**
 * `/xrm/admin/content/pages` — the Content Management landing screen: a
 * space selector, that space's page tree, and a "New Page" flow. Selecting
 * or creating a page navigates into `ContentPageEditorComponent`
 * (`/xrm/admin/content/pages/:id`), which embeds this same tree as its own
 * left sidebar.
 */
@Component({
  selector: 'attome-content-page-list',
  standalone: true,
  imports: [FormsModule, RouterLink, ContentPageTreeComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls: ['../../../../styles/admin-page.css', './content-page-list.component.css'],
  templateUrl: './content-page-list.component.html',
})
export class ContentPageListComponent {
  private readonly svc = inject(ContentAdminService);
  private readonly router = inject(Router);

  private readonly tree = viewChild(ContentPageTreeComponent);

  readonly spaces = signal<ContentSpace[]>([]);
  readonly spacesLoading = signal(true);
  readonly spacesError = signal<string | null>(null);
  readonly selectedSpaceId = signal<string | null>(null);

  private readonly allowedTemplateIds = signal<Set<string>>(new Set());
  private readonly allTemplates = signal<ContentTemplate[]>([]);
  readonly spaceTemplates = computed(() => {
    const allowed = this.allowedTemplateIds();
    return this.allTemplates().filter(t => allowed.has(t.id));
  });

  readonly creating = signal(false);
  readonly creatingBusy = signal(false);
  readonly formError = signal<string | null>(null);
  newTitle = '';
  newUrlPath = '';
  newTemplateId: string | null = null;
  private urlPathTouched = false;

  constructor() {
    this.svc.listSpaces().subscribe({
      next: spaces => {
        this.spaces.set(spaces);
        this.spacesLoading.set(false);
        if (spaces.length > 0) this.onSpaceChange(spaces[0].id);
      },
      error: (e: ApiError) => {
        this.spacesLoading.set(false);
        this.spacesError.set(e.message);
      },
    });
    this.svc.listTemplates().subscribe({ next: templates => this.allTemplates.set(templates) });
  }

  onSpaceChange(spaceId: string): void {
    this.selectedSpaceId.set(spaceId);
    this.creating.set(false);
    this.loadAllowedTemplates(spaceId);
  }

  private loadAllowedTemplates(spaceId: string): void {
    this.svc.spaceTemplates(spaceId).subscribe({
      next: ids => this.allowedTemplateIds.set(new Set(ids)),
      error: () => this.allowedTemplateIds.set(new Set()),
    });
  }

  onTitleChange(title: string): void {
    this.newTitle = title;
    if (this.urlPathTouched) return;
    const slug = title.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
    this.newUrlPath = slug ? `/${slug}` : '';
  }

  onUrlPathChange(path: string): void {
    this.newUrlPath = path;
    this.urlPathTouched = true;
  }

  create(): void {
    const spaceId = this.selectedSpaceId();
    if (!spaceId || !this.newTitle.trim() || !this.newUrlPath.trim()) return;
    this.creatingBusy.set(true);
    this.formError.set(null);
    this.svc.createPage({
      content_space_id: spaceId,
      title: this.newTitle.trim(),
      url_path: this.newUrlPath.trim(),
      template_id: this.newTemplateId,
    }).subscribe({
      next: page => {
        this.creatingBusy.set(false);
        this.creating.set(false);
        this.newTitle = '';
        this.newUrlPath = '';
        this.newTemplateId = null;
        this.urlPathTouched = false;
        this.tree()?.refreshLevel(null);
        void this.router.navigate(['/xrm/admin/content/pages', page.id]);
      },
      error: (e: ApiError) => {
        this.creatingBusy.set(false);
        this.formError.set(e.message);
      },
    });
  }

  open(page: PageSummary): void {
    void this.router.navigate(['/xrm/admin/content/pages', page.id]);
  }
}
