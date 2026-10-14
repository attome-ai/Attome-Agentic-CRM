import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiError, ApiService, TranslatePipe } from '@attome/base';

import { entityFormRoute, entityListRoute } from '../services/entity-url.utils';

/** `tags::TaggedRecord`. */
export interface TaggedRecord {
  entity: string;
  record_id: string;
  label: string | null;
}

/**
 * B4-T4: every record carrying a tag, across entities, that the caller may
 * read (the server leaves out the rest), grouped by entity; each group links
 * to that entity's list filtered by the tag.
 */
@Component({
  selector: 'xrm-tag-page',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, TranslatePipe],
  template: `
    <section class="tp">
      <h2>{{ 'recordTags.pageTitle' | translate }}</h2>
      @if (error(); as message) { <p class="tp-error" role="alert">{{ message }}</p> }
      @if (groups().length === 0 && !error()) {
        <p class="tp-muted">{{ 'recordTags.pageEmpty' | translate }}</p>
      }
      @for (group of groups(); track group.entity) {
        <section class="tp-group" [attr.data-entity]="group.entity">
          <h3>
            <a [routerLink]="listRoute(group.entity)" [queryParams]="{ tag: tagId() }">{{ group.entity }}</a>
            <span class="tp-count">{{ group.records.length }}</span>
          </h3>
          <ul>
            @for (r of group.records; track r.record_id) {
              <li><a [routerLink]="formRoute(r.entity)" [queryParams]="{ id: r.record_id }">{{ r.label || r.record_id }}</a></li>
            }
          </ul>
        </section>
      }
    </section>
  `,
  styles: [`
    :host { display: block; }
    .tp { display: flex; flex-direction: column; gap: 0.75rem; }
    .tp h2, .tp h3 { margin-block: 0; }
    .tp-group ul { margin-block: 0.25rem; padding-inline-start: 1.25rem; }
    .tp-count { margin-inline-start: 0.5rem; color: var(--color-text-secondary); font-size: 0.875rem; }
    .tp-muted { color: var(--color-text-secondary); }
    .tp-error { color: var(--color-danger); }
  `],
})
export class TagPageComponent {
  private readonly api = inject(ApiService);

  /** From the route, `/xrm/tags/:tagId`. */
  readonly tagId = input.required<string>();
  readonly records = signal<TaggedRecord[]>([]);
  readonly error = signal<string | null>(null);
  readonly groups = computed(() => {
    const byEntity = new Map<string, TaggedRecord[]>();
    for (const r of this.records()) byEntity.set(r.entity, [...(byEntity.get(r.entity) ?? []), r]);
    return [...byEntity.entries()].map(([entity, records]) => ({ entity, records }));
  });

  constructor() {
    effect(() => {
      const id = this.tagId();
      this.api.get<{ items: TaggedRecord[] }>(`/api/v1/tags/${encodeURIComponent(id)}/records`).subscribe({
        next: page => { this.error.set(null); this.records.set(page.items); },
        error: (e: ApiError) => this.error.set(e.message),
      });
    });
  }

  listRoute(entity: string): string[] { return entityListRoute(entity); }
  formRoute(entity: string): string[] { return entityFormRoute(entity); }
}
