import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal } from '@angular/core';
import { ApiError, SdkService, TranslatePipe, WORKSPACE_HEADER, WORKSPACE_ROUTES } from '@attome/base';

import type { ChecklistItem } from './develop-start.component';

/** One planned operation (`PlannedOp` in the publish preview). */
export interface ReviewOp {
  op: string;
  action: string;
  target: Record<string, unknown>;
  reason?: string;
  risky: boolean;
}

/** `GET /api/v1/admin/workspaces/{id}/publish`, the parts this screen reads. */
export interface ReviewPreview {
  workspace: string;
  operations: number;
  conflicts: unknown[];
  plan: { changesets: { phases: { operations: ReviewOp[] }[] }[]; applicable: boolean } | null;
  publishable: boolean;
}

export interface EntityChecklist {
  entity: string;
  ready: boolean;
  items: ChecklistItem[];
}

export type OpKind = 'entities' | 'fields' | 'screens' | 'access' | 'processes' | 'labels' | 'other';

const KINDS: readonly OpKind[] = ['entities', 'fields', 'screens', 'access', 'processes', 'labels', 'other'];

/** Which group a changeset operation belongs to. Pure. */
export function opKind(op: string): OpKind {
  if (op.endsWith('_entity')) return 'entities';
  if (op.includes('field') || op.includes('relationship')) return 'fields';
  if (op.includes('view') || op.includes('query') || op.includes('form')) return 'screens';
  if (op.includes('role') || op.includes('privilege')) return 'access';
  if (op.includes('state') || op.includes('flow') || op.includes('rule')) return 'processes';
  if (op.includes('label')) return 'labels';
  return 'other';
}

/** The plan's operations grouped by kind, empty groups dropped. Pure. */
export function groupOps(preview: ReviewPreview): { kind: OpKind; ops: ReviewOp[] }[] {
  const all = (preview.plan?.changesets ?? []).flatMap(c => c.phases.flatMap(p => p.operations));
  return KINDS
    .map(kind => ({ kind, ops: all.filter(o => opKind(o.op) === kind) }))
    .filter(g => g.ops.length > 0);
}

/** The entities the draft touches, in first-seen order. Pure. */
export function draftEntities(preview: ReviewPreview): string[] {
  const out: string[] = [];
  for (const g of groupOps(preview)) {
    for (const o of g.ops) {
      const e = o.target['entity'];
      if (typeof e === 'string' && e && !out.includes(e)) out.push(e);
    }
  }
  return out;
}

/** What an operation changes, for its line. Pure. */
export function opTarget(op: ReviewOp): string {
  return Object.values(op.target).filter(v => typeof v === 'string').join(' · ');
}

/**
 * AD4-T2 — one screen to review a whole draft app before it goes live: the
 * workspace's changes against live (the publish preview) grouped by kind,
 * the checklist (T1-T2) of every entity the draft touches, read inside the
 * workspace, and the publish. A builder's publish may wait for the owner's
 * review (T1-T3); the screen says so.
 */
@Component({
  selector: 'xrm-app-review',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styleUrls: ['../../../styles/admin-page.css'],
  styles: [`
    .ar { display: grid; gap: 1rem; }
    .ar-card { border: 1px solid var(--color-border, currentColor); border-radius: 8px; padding: 1rem; display: grid; gap: .5rem; }
    .ar-list { list-style: none; padding: 0; margin: 0; display: grid; gap: .25rem; }
    .ar-risky { font-weight: 600; }
  `],
  template: `
    <section>
      <header class="page-header">
        <div>
          <h2>{{ 'dataModel.reviewTitle' | translate }}</h2>
          <p class="subtitle">{{ 'dataModel.reviewSubtitle' | translate }}</p>
        </div>
      </header>
      @if (error(); as e) { <p role="alert">{{ e }}</p> }
      @if (preview(); as p) {
        <div class="ar">
          <article class="ar-card" data-testid="ar-changes">
            <h3>{{ 'dataModel.reviewChanges' | translate: { n: p.operations } }}</h3>
            @if (p.conflicts.length) {
              <p role="alert" data-testid="ar-conflicts">{{ 'dataModel.reviewConflicts' | translate: { n: p.conflicts.length } }}</p>
            }
            @for (g of groups(); track g.kind) {
              <h4>{{ kindKey(g.kind) | translate }} ({{ g.ops.length }})</h4>
              <ul class="ar-list" [attr.data-kind]="g.kind">
                @for (o of g.ops; track $index) {
                  <li [class.ar-risky]="o.risky">
                    <bdi dir="ltr">{{ o.op }}</bdi> — <bdi dir="ltr">{{ target(o) }}</bdi>
                    @if (o.reason) { <span> ({{ o.reason }})</span> }
                  </li>
                }
              </ul>
            }
            @if (!groups().length) { <p>{{ 'dataModel.reviewNothing' | translate }}</p> }
          </article>
          <article class="ar-card" data-testid="ar-checklist">
            <h3>{{ 'dataModel.checklistTitle' | translate }}</h3>
            <p>{{ (open() ? 'dataModel.checklistOpenItems' : 'dataModel.checklistReady') | translate: { n: open() } }}</p>
            @for (e of checklist(); track e.entity) {
              <h4><bdi dir="ltr">{{ e.entity }}</bdi></h4>
              <ul class="ar-list">
                @for (i of e.items; track i.area) {
                  <li [attr.data-area]="i.area" [attr.data-done]="i.done">
                    <i [class]="i.done ? 'las la-check' : 'las la-times'" aria-hidden="true"></i>
                    {{ 'dataModel.area_' + i.area | translate }}: {{ i.detail }}
                    @if (!i.done) { <a [href]="i.fix">{{ 'dataModel.fixIt' | translate }}</a> }
                  </li>
                }
              </ul>
            }
          </article>
          <article class="ar-card" data-testid="ar-publish">
            @if (outcome(); as o) {
              <p role="status" data-testid="ar-outcome">{{ (o === 'in_review' ? 'dataModel.reviewWaiting' : 'dataModel.reviewPublished') | translate }}</p>
            } @else {
              @if (open()) { <p>{{ 'dataModel.reviewOpenWarning' | translate }}</p> }
              <button type="button" data-testid="ar-publish-button" (click)="publish()" [disabled]="busy() || !p.publishable">
                {{ 'dataModel.reviewPublish' | translate }}</button>
            }
          </article>
        </div>
      }
    </section>
  `,
})
export class AppReviewComponent {
  private readonly sdk = inject(SdkService);

  /** The workspace holding the draft (route `develop/review/:id`). */
  readonly id = input('');

  readonly preview = signal<ReviewPreview | null>(null);
  readonly checklist = signal<EntityChecklist[]>([]);
  readonly error = signal<string | null>(null);
  readonly busy = signal(false);
  readonly outcome = signal<'published' | 'in_review' | null>(null);

  readonly groups = computed(() => {
    const p = this.preview();
    return p ? groupOps(p) : [];
  });
  readonly open = computed(() =>
    this.checklist().reduce((n, e) => n + e.items.filter(i => i.required && !i.done).length, 0));

  constructor() {
    effect(() => {
      const id = this.id();
      if (id) this.load(id);
    });
  }

  kindKey(kind: OpKind): string {
    return `dataModel.kind_${kind}`;
  }

  target(op: ReviewOp): string {
    return opTarget(op);
  }

  load(id: string): void {
    this.error.set(null);
    this.sdk.get<ReviewPreview>(`${WORKSPACE_ROUTES}/${id}/publish`).subscribe({
      next: p => {
        this.preview.set(p);
        const entities = draftEntities(p);
        if (!entities.length) {
          this.checklist.set([]);
          return;
        }
        // Read inside the workspace: the draft's entities are not live yet.
        this.sdk.get<EntityChecklist[]>('/api/v1/admin/checklist', {
          query: { entities: entities.join(',') },
          headers: { [WORKSPACE_HEADER]: id },
        }).subscribe({
          next: c => this.checklist.set(c),
          error: (e: ApiError) => this.error.set(e.message),
        });
      },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  /** Publishes; a builder's publish answers `in_review` (T1-T3). */
  publish(): void {
    const id = this.id();
    if (!id) return;
    this.busy.set(true);
    this.error.set(null);
    this.sdk.post<{ status?: string }>(`${WORKSPACE_ROUTES}/${id}/publish`, { body: {} }).subscribe({
      next: r => {
        this.busy.set(false);
        this.outcome.set(r?.status === 'in_review' ? 'in_review' : 'published');
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(e.message);
      },
    });
  }
}
