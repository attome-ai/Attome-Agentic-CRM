import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { ApiError, ApiService, LangService, TranslatePipe } from '@attome/base';
import { switchMap } from 'rxjs';

import { DefinitionListItem, WorkflowAdminService } from '../services/workflow-admin.service';

/** `ObjectSummaryView` of a flow template. */
export interface TemplateSummary {
  id: string;
  name: string;
  app: string;
  state: string;
}

/** One template parameter (`attome_model::kinds::flow_template`). */
export interface TemplateParameter {
  name: string;
  type: 'entity' | 'attribute' | 'user' | 'users' | 'text' | 'number';
  label_en?: string;
  label_ar?: string;
  default?: unknown;
}

export interface TemplateDoc {
  description_en?: string;
  description_ar?: string;
  parameters?: TemplateParameter[];
  graph?: unknown;
}

interface Issue { path: string; code: string; message: string }

/** Templates whose name or description contains the search text. */
export function filterTemplates(
  items: TemplateSummary[], docs: Record<string, TemplateDoc>, search: string,
): TemplateSummary[] {
  const q = search.trim().toLowerCase();
  if (!q) return items;
  return items.filter(t => {
    const doc = docs[t.id];
    return [t.name, doc?.description_en ?? '', doc?.description_ar ?? '']
      .some(text => text.toLowerCase().includes(q));
  });
}

/** The typed argument for a parameter from the text a person typed. */
export function argumentOf(p: TemplateParameter, raw: string): unknown {
  const text = raw.trim();
  switch (p.type) {
    case 'number': return text === '' ? undefined : Number(text);
    case 'users': return text === '' ? undefined : text.split(',').map(s => s.trim()).filter(Boolean);
    default: return text === '' ? undefined : text;
  }
}

/** The commands that save `graph` as a new template's document. */
export function templateCommands(description: string, graph: unknown, parameters: TemplateParameter[]): unknown[] {
  return [
    { op: 'set', path: '/description_en', value: description },
    { op: 'set', path: '/parameters', value: parameters },
    { op: 'set', path: '/graph', value: graph },
  ];
}

/** A template object name from what a person typed: lowercase letters, digits and underscores. */
export function templateSlug(name: string): string {
  const slug = name.trim().toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
  return /^[a-z]/.test(slug) ? slug.slice(0, 60) : `template_${slug}`.slice(0, 60);
}

const MODEL = '/api/v1/admin/model/flow_template';

/**
 * Flow templates (roadmap M6-T4): search the published templates, fill in a
 * template's parameters and start a draft flow from it, or save an existing
 * flow as a template. The filled graph is checked by the server
 * (`instantiate`) and saved as an ordinary draft, which the editor opens.
 */
@Component({
  selector: 'xrm-workflow-template-gallery',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  template: `
    <section class="tg">
      <h3>{{ 'flowTemplates.title' | translate }}</h3>
      <p class="tg-muted">{{ 'flowTemplates.intro' | translate }}</p>
      @if (error(); as message) { <p class="tg-error" role="alert">{{ message }}</p> }
      <input type="search" [(ngModel)]="search" [attr.aria-label]="'flowTemplates.search' | translate"
             [placeholder]="'flowTemplates.search' | translate" (ngModelChange)="searchText.set($event)" />
      <div class="tg-grid">
        @for (t of shown(); track t.id) {
          <button type="button" class="tg-card" [class.tg-selected]="selected()?.id === t.id"
                  [attr.data-template]="t.id" (click)="select(t)">
            <strong>{{ t.name }}</strong>
            <span class="tg-muted">{{ describe(t.id) }}</span>
          </button>
        } @empty {
          <p class="tg-muted">{{ 'flowTemplates.none' | translate }}</p>
        }
      </div>

      @if (selected(); as t) {
        <form class="tg-form" (ngSubmit)="start()" data-start>
          <h4>{{ t.name }}</h4>
          @for (p of parameters(); track p.name) {
            <label>{{ labelOf(p) }} <span class="tg-muted">({{ 'flowTemplates.types.' + p.type | translate }})</span>
              <input [name]="'arg-' + p.name" [(ngModel)]="args[p.name]" dir="auto" /></label>
          }
          <label>{{ 'flowTemplates.flowName' | translate }}
            <input name="flow-name" [(ngModel)]="flowName" required /></label>
          <label>{{ 'flowTemplates.logicalname' | translate }}
            <input name="flow-logicalname" [(ngModel)]="flowLogicalname" dir="ltr" required /></label>
          @for (i of issues(); track i.path) { <p class="tg-error">{{ i.path }}: {{ i.message }}</p> }
          <button type="submit" [disabled]="busy()">{{ 'flowTemplates.start' | translate }}</button>
        </form>
      }

      <form class="tg-form" (ngSubmit)="saveAsTemplate()" data-save>
        <h4>{{ 'flowTemplates.saveTitle' | translate }}</h4>
        <label>{{ 'flowTemplates.fromFlow' | translate }}
          <select name="from-flow" [(ngModel)]="fromFlowId">
            @for (d of flows(); track d.id) { <option [value]="d.id">{{ d.name }}</option> }
          </select></label>
        <label>{{ 'flowTemplates.templateName' | translate }}
          <input name="template-name" [(ngModel)]="templateName" required /></label>
        <label>{{ 'flowTemplates.description' | translate }}
          <input name="template-description" [(ngModel)]="templateDescription" /></label>
        <button type="submit" [disabled]="busy() || !fromFlowId || !templateName.trim()">{{ 'flowTemplates.save' | translate }}</button>
      </form>
    </section>
  `,
  styles: [`
    :host { display: block; }
    .tg { display: flex; flex-direction: column; gap: 0.5rem; }
    .tg h3 { margin-block: 0; font-size: 1rem; }
    .tg-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(14rem, 1fr)); gap: 0.5rem; }
    .tg-card { display: flex; flex-direction: column; gap: 0.25rem; text-align: start; padding: 0.5rem;
      border: 1px solid var(--color-border); background: none; cursor: pointer; }
    .tg-selected { border-color: var(--color-primary); }
    .tg-form { display: flex; flex-direction: column; gap: 0.375rem; padding-block-start: 0.5rem;
      border-block-start: 1px solid var(--color-border); }
    .tg-form label { display: flex; flex-direction: column; gap: 0.125rem; }
    .tg-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .tg-error { color: var(--color-danger); }
  `],
})
export class WorkflowTemplateGalleryComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly workflows = inject(WorkflowAdminService);
  private readonly lang = inject(LangService);
  private readonly router = inject(Router);

  readonly items = signal<TemplateSummary[]>([]);
  readonly docs = signal<Record<string, TemplateDoc>>({});
  readonly searchText = signal('');
  readonly selected = signal<TemplateSummary | null>(null);
  readonly issues = signal<Issue[]>([]);
  readonly flows = signal<DefinitionListItem[]>([]);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  readonly shown = computed(() => filterTemplates(this.items(), this.docs(), this.searchText()));
  readonly parameters = computed(() => {
    const t = this.selected();
    return (t && this.docs()[t.id]?.parameters) || [];
  });

  search = '';
  args: Record<string, string> = {};
  flowName = '';
  flowLogicalname = '';
  fromFlowId = '';
  templateName = '';
  templateDescription = '';

  ngOnInit(): void {
    this.api.get<{ items: TemplateSummary[] }>(MODEL, { page_size: '200' }).subscribe({
      next: page => {
        const published = page.items.filter(t => t.state === 'published');
        this.items.set(published);
        for (const t of published) this.loadDoc(t.id);
      },
      error: (e: ApiError) => this.error.set(e.message),
    });
    this.workflows.listDefinitions(true).subscribe({
      next: flows => this.flows.set(flows),
      error: () => undefined,
    });
  }

  private loadDoc(id: string): void {
    this.api.get<{ doc: TemplateDoc }>(`${MODEL}/${id}`).subscribe({
      next: v => this.docs.update(all => ({ ...all, [id]: v.doc })),
      error: () => undefined,
    });
  }

  describe(id: string): string {
    const doc = this.docs()[id];
    return (this.lang.current() === 'ar' ? doc?.description_ar : doc?.description_en) ?? doc?.description_en ?? '';
  }

  labelOf(p: TemplateParameter): string {
    return (this.lang.current() === 'ar' ? p.label_ar : p.label_en) || p.name;
  }

  select(t: TemplateSummary): void {
    this.selected.set(t);
    this.issues.set([]);
    this.args = {};
    this.flowName = t.name;
    this.flowLogicalname = '';
  }

  start(): void {
    const t = this.selected();
    if (!t) return;
    const args: Record<string, unknown> = {};
    for (const p of this.parameters()) {
      const value = argumentOf(p, this.args[p.name] ?? '');
      if (value !== undefined) args[p.name] = value;
    }
    this.busy.set(true);
    this.error.set(null);
    this.api.post<{ graph: unknown; issues: Issue[] }>(`${MODEL}/${t.id}/instantiate`, { args }).subscribe({
      next: filled => {
        if (filled.issues.length > 0) {
          this.busy.set(false);
          this.issues.set(filled.issues);
          return;
        }
        this.workflows.createDefinition({ logicalname: this.flowLogicalname.trim(), name: this.flowName.trim() })
          .pipe(switchMap(def => this.workflows.createVersion(def.id, { graph: filled.graph })))
          .subscribe({
            next: version => {
              this.busy.set(false);
              void this.router.navigate(['/xrm/workflow/definitions', version.definition_id, 'versions', version.id]);
            },
            error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
          });
      },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  /** Saves the chosen flow's newest version as a published template with no parameters. */
  saveAsTemplate(): void {
    const flowId = this.fromFlowId;
    if (!flowId || !this.templateName.trim()) return;
    this.busy.set(true);
    this.error.set(null);
    const id = crypto.randomUUID();
    this.workflows.getDefinition(flowId).pipe(
      switchMap(def => {
        const newest = [...def.versions].sort((a, b) => b.version_number - a.version_number)[0];
        return this.workflows.getVersion(flowId, newest.id);
      }),
      switchMap(version => this.api.post<unknown>(`${MODEL}/${id}/commands`, {
        base_hash: '', name: templateSlug(this.templateName),
        commands: templateCommands(this.templateDescription.trim() || this.templateName.trim(), version.graph, []),
      })),
      switchMap(() => this.api.post<unknown>(`${MODEL}/${id}/publish`, {})),
    ).subscribe({
      next: () => {
        this.busy.set(false);
        this.items.update(all => [...all, { id, name: templateSlug(this.templateName), app: '', state: 'published' }]);
        this.loadDoc(id);
        this.templateName = '';
        this.templateDescription = '';
      },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }
}
