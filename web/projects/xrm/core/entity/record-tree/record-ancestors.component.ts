import { ChangeDetectionStrategy, Component, effect, inject, input, signal, untracked } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiService, TranslatePipe } from '@attome/base';

import { entityFormRoute } from '../services/entity-url.utils';

/** One step of a record's path up its tree. */
export interface AncestorStep {
  id: string;
  label: string;
}

/** `GET /api/v1/{entity}/{id}/ancestors` rows, nearest first. */
interface AncestorRow {
  id: string;
  data: Record<string, unknown>;
}

/** The fields a record's name is read from, in order. */
const NAME_FIELDS = ['name', 'title', 'full_name', 'display_name', 'subject'];

/** A record's display name: its first name-like text field, else its id's start. */
export function recordLabel(row: AncestorRow): string {
  for (const field of NAME_FIELDS) {
    const value = row.data?.[field];
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return row.id.slice(0, 8);
}

/**
 * A17-T5: where a record sits in its entity's tree, root first, each step a
 * link to that record. Shows nothing for an entity without a hierarchy (the
 * route answers 422) or a record at the root.
 */
@Component({
  selector: 'xrm-record-ancestors',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, TranslatePipe],
  template: `
    @if (steps().length) {
      <nav class="ra" [attr.aria-label]="'recordTree.path' | translate" data-ancestors>
        @for (step of steps(); track step.id) {
          <a class="ra-step" [routerLink]="formRoute()" [queryParams]="{ id: step.id }">{{ step.label }}</a>
          <span class="ra-sep" aria-hidden="true">›</span>
        }
      </nav>
    }
  `,
  styles: [`
    .ra { display: flex; flex-wrap: wrap; align-items: center; gap: 0.25rem; font-size: 0.8125rem; }
    .ra-step { color: var(--color-text-secondary); text-decoration: none; }
    .ra-step:hover { text-decoration: underline; }
    .ra-sep { color: var(--color-text-secondary); }
    :host-context([dir="rtl"]) .ra-sep { transform: scaleX(-1); }
  `],
})
export class RecordAncestorsComponent {
  private readonly api = inject(ApiService);

  readonly entity = input.required<string>();
  readonly recordId = input.required<string>();
  readonly steps = signal<AncestorStep[]>([]);

  constructor() {
    effect(() => {
      const entity = this.entity();
      const id = this.recordId();
      untracked(() => this.load(entity, id));
    });
  }

  formRoute(): unknown[] {
    return entityFormRoute(this.entity());
  }

  private load(entity: string, id: string): void {
    this.steps.set([]);
    this.api.get<{ items: AncestorRow[] }>(
      `/api/v1/${encodeURIComponent(entity)}/${encodeURIComponent(id)}/ancestors`,
    ).subscribe({
      // Nearest first from the server; a path reads from the root.
      next: page => this.steps.set([...page.items].reverse().map(row => ({ id: row.id, label: recordLabel(row) }))),
      // An entity without a tree, or no access: no path to show.
      error: () => this.steps.set([]),
    });
  }
}
