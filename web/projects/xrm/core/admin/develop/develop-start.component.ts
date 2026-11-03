import { DOCUMENT } from '@angular/common';
import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, SdkService, TranslatePipe, WORKSPACE_ROUTES, WorkspaceState } from '@attome/base';

interface Named {
  id: string;
  name: string;
}

interface WorkspaceRow extends Named {
  status: string;
  last_used_at: string;
}

interface Page<T> {
  items: T[];
}

/** What `model.app.plan` answers before it is confirmed. */
interface AppPlan {
  written_plan: string[];
  steps?: unknown[];
}

/** The most recent workspaces the screen lists. */
const RECENT = 6;

/** Workspaces still open, most recently used first. Pure. */
export function recentWorkspaces(rows: readonly WorkspaceRow[], limit = RECENT): WorkspaceRow[] {
  return rows
    .filter(w => w.status === 'open')
    .sort((a, b) => Date.parse(b.last_used_at) - Date.parse(a.last_used_at))
    .slice(0, limit);
}

/**
 * T1-T1 — the Develop start screen: start an app three ways from one place.
 * A blank app makes a Develop workspace and enters it (T5); describing the
 * app asks the building agent for a written plan (`model.app.plan`, AD4-T1)
 * and, once confirmed, its building steps; the template gallery lists the
 * installed apps and flow templates; recent work lists the open workspaces
 * to go back into.
 */
@Component({
  selector: 'xrm-develop-start',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  styleUrls: ['../../../styles/admin-page.css'],
  styles: [`
    .ds { display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit, minmax(16rem, 1fr)); }
    .ds-card { border: 1px solid var(--color-border, currentColor); border-radius: 8px; padding: 1rem; display: grid; gap: .5rem; align-content: start; }
    .ds-card textarea { inline-size: 100%; min-block-size: 5rem; }
    .ds-list { list-style: none; padding: 0; margin: 0; display: grid; gap: .25rem; }
  `],
  template: `
    <section>
      <header class="page-header">
        <div>
          <h2>{{ 'dataModel.developTitle' | translate }}</h2>
          <p class="subtitle">{{ 'dataModel.developSubtitle' | translate }}</p>
        </div>
      </header>
      @if (error(); as e) { <p role="alert">{{ e }}</p> }
      <div class="ds">
        <article class="ds-card" data-testid="ds-blank">
          <h3>{{ 'dataModel.blankApp' | translate }}</h3>
          <label>{{ 'dataModel.appName' | translate }}
            <input data-testid="ds-name" [ngModel]="name()" (ngModelChange)="name.set($event)" maxlength="100" />
          </label>
          <button type="button" data-testid="ds-start-blank" (click)="startBlank()" [disabled]="busy() || !name().trim()">
            {{ 'dataModel.startBlank' | translate }}</button>
        </article>
        <article class="ds-card" data-testid="ds-describe">
          <h3>{{ 'dataModel.describeApp' | translate }}</h3>
          <textarea data-testid="ds-description" [ngModel]="description()" (ngModelChange)="description.set($event)"></textarea>
          <button type="button" data-testid="ds-plan" (click)="plan(false)" [disabled]="busy() || !description().trim()">
            {{ 'dataModel.planApp' | translate }}</button>
          @if (written(); as lines) {
            <ol data-testid="ds-written">
              @for (line of lines; track $index) { <li>{{ line }}</li> }
            </ol>
            <button type="button" data-testid="ds-confirm" (click)="plan(true)" [disabled]="busy()">
              {{ 'dataModel.confirmPlan' | translate }}</button>
          }
          @if (steps() !== null) {
            <p data-testid="ds-steps">{{ 'dataModel.planSteps' | translate: { n: steps() } }}</p>
          }
        </article>
        <article class="ds-card" data-testid="ds-templates">
          <h3>{{ 'dataModel.templates' | translate }}</h3>
          <ul class="ds-list">
            @for (a of apps(); track a.id) { <li>{{ a.name }}</li> }
            @for (t of templates(); track t.id) { <li>{{ t.name }}</li> }
          </ul>
          @if (!apps().length && !templates().length) { <p>{{ 'dataModel.noTemplates' | translate }}</p> }
        </article>
        <article class="ds-card" data-testid="ds-recent">
          <h3>{{ 'dataModel.recentWork' | translate }}</h3>
          <ul class="ds-list">
            @for (w of recent(); track w.id) {
              <li><button type="button" data-testid="ds-enter" (click)="enter(w)">{{ w.name }}</button></li>
            }
          </ul>
          @if (!recent().length) { <p>{{ 'dataModel.noRecent' | translate }}</p> }
        </article>
      </div>
    </section>
  `,
})
export class DevelopStartComponent {
  private readonly sdk = inject(SdkService);
  private readonly workspaces = inject(WorkspaceState);
  private readonly document = inject(DOCUMENT);

  readonly name = signal('');
  readonly description = signal('');
  readonly written = signal<string[] | null>(null);
  readonly steps = signal<number | null>(null);
  readonly apps = signal<Named[]>([]);
  readonly templates = signal<Named[]>([]);
  readonly recent = signal<WorkspaceRow[]>([]);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);

  constructor() {
    this.sdk.get<Page<WorkspaceRow>>(WORKSPACE_ROUTES, { query: { page_size: 100 } }).subscribe({
      next: page => this.recent.set(recentWorkspaces(page.items)),
      error: () => this.recent.set([]),
    });
    this.sdk.get<Page<Named>>('/api/v1/admin/apps', { query: { page_size: 50 } }).subscribe({
      next: page => this.apps.set(page.items),
      error: () => this.apps.set([]),
    });
    this.sdk.get<Page<Named>>('/api/v1/admin/model/flow_template', { query: { page_size: 50 } }).subscribe({
      next: page => this.templates.set(page.items),
      error: () => this.templates.set([]),
    });
  }

  /** A blank app: a new Develop workspace without records, entered at once. */
  startBlank(): void {
    this.busy.set(true);
    this.error.set(null);
    this.sdk.post<WorkspaceRow>(WORKSPACE_ROUTES, {
      body: { name: this.name().trim(), data: { mode: 'none' } },
    }).subscribe({
      next: made => {
        this.busy.set(false);
        this.enter(made);
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(e.message);
      },
    });
  }

  enter(workspace: Named): void {
    this.workspaces.enter({ id: workspace.id, name: workspace.name });
    try {
      this.document.defaultView?.location.reload();
    } catch {
      // No reload where there is no window (tests).
    }
  }

  /** The building agent's written plan, then, once confirmed, its steps. */
  plan(confirmed: boolean): void {
    this.busy.set(true);
    this.error.set(null);
    this.sdk.post<{ result: AppPlan }>('/api/v1/actions/model.app.plan/invoke', {
      body: { args: { description: this.description().trim(), confirmed } },
    }).subscribe({
      next: outcome => {
        this.busy.set(false);
        this.written.set(outcome.result.written_plan);
        this.steps.set(confirmed ? (outcome.result.steps ?? []).length : null);
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(e.message);
      },
    });
  }
}
