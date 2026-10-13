import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal, untracked } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ChoicePillComponent } from '@attome/xrm/core/generic/components';
import { EntityService } from '../services/entity.service';

interface TagCategoryRow {
  id: string;
  name: string;
  color: string | null;
}

interface TagItemRow {
  id: string;
  category_id: string;
  created_at: string;
}

/**
 * Drop-in "Tags" section for any record form — generic across every entity,
 * same polymorphic `entity_name`/`record_id` pair `note`/
 * `communication`/`audit_consent` already use (`attome-api`'s `tag_seed`
 * doc comment). `tag_item` is a many-to-many link (category, record) —
 * it carries no name of its own — so applying a tag here is choosing an
 * existing `tag_category` from a select and creating the join row, not
 * navigating to a full create form: the generic form's "+ New" would surface
 * the raw `entity_name`/`record_id` text fields as freely-editable inputs,
 * which is both the wrong UX for this panel (99% of applications happen
 * here, not through the `tag_item` admin list) and a real footgun — a
 * mistyped `record_id` silently creates a tag attached to the wrong record.
 * This panel sets both from its own `entityName`/`recordId` inputs instead,
 * so they are never hand-typed.
 */
@Component({
  selector: 'xrm-tags-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [CommonModule, FormsModule, ChoicePillComponent],
  styleUrls: ['./tags-panel.component.css'],
  templateUrl: './tags-panel.component.html',
})
export class TagsPanelComponent {
  readonly entityName = input.required<string>();
  readonly recordId = input.required<string>();

  private readonly entityService = inject(EntityService);

  readonly loading = signal(true);
  readonly saving = signal(false);
  readonly errorMessage = signal<string | null>(null);

  readonly categories = signal<TagCategoryRow[]>([]);
  readonly appliedTags = signal<TagItemRow[]>([]);

  selectedCategoryId = '';

  private readonly categoryById = computed(
    () => new Map(this.categories().map(c => [c.id, c])),
  );

  /** Categories not already applied to this record — the only ones worth offering. */
  readonly availableCategories = computed(() => {
    const applied = new Set(this.appliedTags().map(t => t.category_id));
    return this.categories().filter(c => !applied.has(c.id));
  });

  constructor() {
    effect(() => {
      const e = this.entityName();
      const r = this.recordId();
      untracked(() => {
        if (e && r) this.load();
      });
    });
  }

  load(): void {
    this.loading.set(true);
    this.errorMessage.set(null);
    this.entityService.list('tag_category', {
      sorts: [{ field: 'name', dir: 'asc' }],
      limit: 200,
    }).subscribe({
      next: res => {
        this.categories.set(res.data.map(item => {
          const raw = item.data as Record<string, unknown>;
          return {
            id: item.id,
            name: String(raw['name'] || ''),
            color: (raw['color'] as string | undefined) || null,
          };
        }));
        this.fetchApplied();
      },
      error: () => this.fetchApplied(),
    });
  }

  private fetchApplied(): void {
    this.entityService.list('tag_item', {
      filters: [
        { field: 'entity_name', op: 'eq', value: this.entityName() },
        { field: 'record_id', op: 'eq', value: this.recordId() },
      ],
      limit: 200,
    }).subscribe({
      next: res => {
        this.appliedTags.set(res.data.map(item => ({
          id: item.id,
          category_id: String((item.data as Record<string, unknown>)['category_id'] || ''),
          created_at: item.created_at || '',
        })));
        this.loading.set(false);
      },
      error: err => {
        this.appliedTags.set([]);
        this.loading.set(false);
        this.errorMessage.set(err?.message || 'Failed to load tags.');
      },
    });
  }

  categoryName(categoryId: string): string {
    return this.categoryById().get(categoryId)?.name ?? 'Unknown category';
  }

  categoryColor(categoryId: string): string | null {
    return this.categoryById().get(categoryId)?.color ?? null;
  }

  addTag(): void {
    const categoryId = this.selectedCategoryId;
    if (!categoryId || this.saving()) return;

    this.saving.set(true);
    this.errorMessage.set(null);
    this.entityService.create('tag_item', {
      category_id: categoryId,
      entity_name: this.entityName(),
      record_id: this.recordId(),
    }).subscribe({
      next: () => {
        this.selectedCategoryId = '';
        this.saving.set(false);
        this.fetchApplied();
      },
      error: err => {
        this.saving.set(false);
        this.errorMessage.set(err?.message || 'Failed to add tag.');
      },
    });
  }

  removeTag(tag: TagItemRow): void {
    const previous = this.appliedTags();
    this.appliedTags.set(previous.filter(t => t.id !== tag.id));
    this.entityService.delete('tag_item', tag.id).subscribe({
      error: () => {
        this.errorMessage.set('Failed to remove tag.');
        this.appliedTags.set(previous);
      },
    });
  }
}
