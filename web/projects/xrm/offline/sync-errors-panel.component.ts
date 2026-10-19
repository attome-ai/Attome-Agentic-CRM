import { ChangeDetectionStrategy, Component, computed, input, output } from '@angular/core';
import { RouterLink } from '@angular/router';
import { TranslatePipe } from '@attome/base';
import { SyncProblem } from './sync.service';

/** Where a failed change opens, split for `routerLink`. */
export interface ErrorLink {
  path: string;
  query: Record<string, string>;
}

/**
 * The link for a failed change: the server's record link; for a record
 * created offline (never on the server), the same form marked as the local
 * draft. Pure.
 */
export function errorLink(problem: SyncProblem): ErrorLink {
  const raw = problem.result.link ?? `/xrm/entity/${problem.op.entity}/form?id=${problem.op.id}`;
  const [path, search = ''] = raw.split('?');
  const query: Record<string, string> = {};
  new URLSearchParams(search).forEach((v, k) => (query[k] = v));
  if (problem.op.kind === 'create') query['offline'] = 'draft';
  return { path, query };
}

/**
 * B18-T9: after a sync, the changes the server refused (no privilege, a
 * validation or duplicate rule, or a change waiting on one of those), each
 * with its reason and a link to the record.
 */
@Component({
  selector: 'xrm-offline-sync-errors',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, TranslatePipe],
  template: `
    @if (rejected().length) {
      <section class="se-panel" data-testid="offline-sync-errors" aria-labelledby="se-title">
        <h2 id="se-title" class="se-title">{{ 'offline.errors.title' | translate }}</h2>
        <ul class="se-list">
          @for (p of rejected(); track p.result.client_op_id) {
            <li class="se-item" data-testid="offline-sync-error">
              <span class="se-entity">{{ p.op.entity }}</span>
              <span class="se-message">{{ p.result.message || p.result.code }}</span>
              <a class="se-link" [routerLink]="link(p).path" [queryParams]="link(p).query"
                 data-testid="offline-sync-error-link">{{ 'offline.errors.open' | translate }}</a>
              <button type="button" class="se-dismiss" (click)="dismissed.emit(p)">
                {{ 'offline.errors.dismiss' | translate }}
              </button>
            </li>
          }
        </ul>
      </section>
    }
  `,
  styles: [`
    .se-panel { display: flex; flex-direction: column; gap: 0.5rem; padding-block: 0.75rem; padding-inline: 1rem;
      border: 1px solid var(--color-border); border-radius: 8px; background: var(--color-surface); }
    .se-title { margin: 0; font-size: 1rem; }
    .se-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.375rem; }
    .se-item { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: baseline; }
    .se-entity { font-weight: 600; }
    .se-message { flex: 1 1 12rem; color: var(--color-danger); overflow-wrap: anywhere; }
    .se-link { color: var(--color-accent); }
    .se-dismiss { border: 1px solid var(--color-border); border-radius: 6px; background: var(--color-surface);
      color: inherit; padding-block: 0.125rem; padding-inline: 0.5rem; cursor: pointer; }
  `],
})
export class SyncErrorsPanelComponent {
  readonly problems = input.required<SyncProblem[]>();
  readonly dismissed = output<SyncProblem>();

  readonly rejected = computed(() => this.problems().filter(p => p.result.status === 'rejected'));

  link(problem: SyncProblem): ErrorLink {
    return errorLink(problem);
  }
}
