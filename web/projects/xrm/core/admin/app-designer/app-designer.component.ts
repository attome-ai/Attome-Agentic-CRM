import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal, untracked, viewChild } from '@angular/core';
import { Router, RouterLink } from '@angular/router';
import { ApiError, ApiService, LangService, TranslatePipe } from '@attome/base';
import { CanvasComponent, valueAt } from '@attome/xrm/canvas';
import type { EditCommand } from '@attome/xrm/canvas';
import { ModelService } from '@attome/xrm/model';
import type { ObjectSummary } from '@attome/xrm/model';
import {
  AppDoc, AppNode, AppSettings, ITEM_KINDS, ItemKind, Navigation, groupNode, groupsOf, itemNode, navProblems, navigationOf,
  saveCommands, toCanvas, uuidv7,
} from './app-design.model';

/** The model kinds an item can be picked from (the others are added by id). */
export const PICKABLE_KINDS = ['form', 'page', 'dashboard', 'report', 'flow'] as const;

/** One object the palette offers. */
export interface SourceObject {
  kind: ItemKind;
  id: string;
  name: string;
}

/** One line of the dependency map: what an item opens, and what that reads. */
export interface Dependency {
  item: string;
  kind: string;
  target: string;
  /** The objects the target references (a form's entity and attributes, ...). */
  uses: string[];
}

interface ReferenceView {
  kind?: string;
  id?: string;
  name?: string | null;
  target_kind?: string;
  target_id?: string;
  target_name?: string | null;
}

const KIND_KEYS: Record<ItemKind, string> = {
  view: 'appDesigner.kinds.view', form: 'appDesigner.kinds.form', dashboard: 'appDesigner.kinds.dashboard',
  page: 'appDesigner.kinds.page', report: 'appDesigner.kinds.report', flow: 'appDesigner.kinds.flow', url: 'appDesigner.kinds.url',
};
const PROBLEM_KEYS = {
  noTarget: 'appDesigner.problems.noTarget', badUrl: 'appDesigner.problems.badUrl', duplicate: 'appDesigner.problems.duplicate',
} as const;

/**
 * A21-T3: the app designer, at `/xrm/admin/apps/:id/design`. An app's
 * navigation (A21-T1) on the shared canvas (Y14-T1): groups and their items,
 * moved, renamed in the property panel and undone like any canvas edit. The
 * palette lists the forms, pages, dashboards, reports and flows the person
 * may see; drag one onto the canvas, or click it, to add it to the selected
 * group; views and links are added by id or address. The settings panel
 * holds the app's name, icon, colours, languages and time zone; simple mode
 * hides the advanced options (who sees an item, badges, colours). The
 * dependency map lists what each item opens and what that reads. Saving
 * writes the draft (its whole menu, landing pages and settings) against the
 * draft's content hash; publishing makes it the app people use.
 */
@Component({
  selector: 'xrm-app-designer',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [CanvasComponent, RouterLink, TranslatePipe],
  templateUrl: './app-designer.component.html',
  styleUrl: './app-designer.component.css',
})
export class AppDesignerComponent {
  private readonly model = inject(ModelService);
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);
  private readonly router = inject(Router);
  private readonly canvas = viewChild(CanvasComponent);
  /** The id a new app is saved under. */
  private readonly freshId = uuidv7();

  /** The navigation object (route parameter); `new` starts one. */
  readonly id = input.required<string>();

  readonly kinds = ITEM_KINDS;
  readonly kindKeys = KIND_KEYS;
  readonly problemKeys = PROBLEM_KEYS;

  readonly initial = signal<AppDoc | null>(null);
  readonly current = signal<AppDoc | null>(null);
  readonly before = signal<Partial<Navigation>>({});
  readonly landing = signal<Navigation['landing']>([]);
  readonly settings = signal<AppSettings>({});
  readonly name = signal('');
  readonly hash = signal('');
  readonly savedVersion = signal<number | null>(null);
  readonly published = signal<number | null>(null);
  readonly selectedPath = signal<string | null>(null);
  readonly sources = signal<SourceObject[]>([]);
  readonly sourceFilter = signal('');
  readonly byIdKind = signal<ItemKind>('view');
  readonly byIdValue = signal('');
  readonly byIdLabel = signal('');
  readonly dependencies = signal<Dependency[]>([]);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);

  readonly simple = computed(() => this.settings().simple === true);
  readonly groups = computed(() => {
    const doc = this.current();
    return doc ? groupsOf(doc) : [];
  });
  readonly problems = computed(() => navProblems(this.groups()));
  readonly shownSources = computed(() => {
    const q = this.sourceFilter().trim().toLowerCase();
    return q ? this.sources().filter(s => s.name.toLowerCase().includes(q)) : this.sources();
  });

  constructor() {
    effect(() => {
      const id = this.id();
      untracked(() => this.load(id));
    });
    this.loadSources();
  }

  valueOf(event: Event): string {
    return (event.target as HTMLInputElement | HTMLSelectElement).value;
  }

  onChanged(doc: unknown): void {
    this.current.set(doc as AppDoc);
  }

  onSelect(paths: string[]): void {
    this.selectedPath.set(paths.at(-1) ?? null);
  }

  setSetting(change: Partial<AppSettings>): void {
    this.settings.update(s => ({ ...s, ...change }));
  }

  toggleLanguage(lang: 'en' | 'ar'): void {
    const langs = this.settings().languages ?? [];
    this.setSetting({ languages: langs.includes(lang) ? langs.filter(l => l !== lang) : [...langs, lang] });
  }

  pickKind(event: Event): void {
    const value = this.valueOf(event);
    const kind = ITEM_KINDS.find(k => k === value);
    if (kind) this.byIdKind.set(kind);
  }

  addGroup(): void {
    const doc = this.current();
    if (!doc) return;
    const length = (doc.root.children ?? []).length;
    const label = `${this.lang.translate('appDesigner.newGroup')} ${length + 1}`;
    this.exec({ op: 'add', path: '/root/children/-', value: groupNode(label) }, `/root/children/${length}`);
  }

  /** Adds an item opening `source` to the selected group (a new group when there is none). */
  addSource(source: SourceObject): void {
    this.addItem(itemNode(source.name, source.kind, source.id));
  }

  /** Adds an item by id (a view) or address (a link). */
  addById(): void {
    const kind = this.byIdKind();
    const value = this.byIdValue().trim();
    const label = this.byIdLabel().trim() || value;
    if (!value) return;
    this.addItem(kind === 'url' ? itemNode(label, 'url', '', value) : itemNode(label, kind, value));
    this.byIdValue.set('');
    this.byIdLabel.set('');
  }

  dragSource(event: DragEvent, source: SourceObject): void {
    event.dataTransfer?.setData('application/x-attome-source', JSON.stringify(source));
  }

  dropSource(event: DragEvent): void {
    const raw = event.dataTransfer?.getData('application/x-attome-source');
    if (!raw) return;
    event.preventDefault();
    try {
      this.addSource(JSON.parse(raw) as SourceObject);
    } catch {
      // Not one of ours: the canvas's own drag handles it.
    }
  }

  save(_commands: EditCommand[] = []): void {
    const doc = this.current();
    if (!doc || this.busy()) return;
    const name = this.settings().name?.trim() || this.name().trim();
    if (!name) {
      this.error.set(this.lang.translate('appDesigner.nameNeeded'));
      return;
    }
    const nav = navigationOf(doc, this.landing(), this.settings());
    this.busy.set(true);
    this.error.set(null);
    const isNew = !this.hash();
    this.model.saveDraft('navigation', this.objectId(), this.hash(), isNew ? name : null, saveCommands(nav, this.before()))
      .subscribe({
        next: saved => {
          this.busy.set(false);
          this.hash.set(saved.content_hash);
          this.savedVersion.set(saved.version_no);
          this.before.set(nav);
          if (this.id() === 'new') this.router.navigate(['/xrm', 'admin', 'apps', saved.id, 'design']);
        },
        error: (e: ApiError) => {
          this.busy.set(false);
          this.error.set(e.status === 409 ? this.lang.translate('appDesigner.conflict') : this.lang.errorText(e));
        },
      });
  }

  publish(): void {
    if (!this.hash() || this.busy()) return;
    this.busy.set(true);
    this.model.publish('navigation', this.objectId()).subscribe({
      next: v => {
        this.busy.set(false);
        this.published.set(v.version_no);
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(this.lang.errorText(e));
      },
    });
  }

  /** Lists what each item opens and, for a model object, what it reads. */
  mapDependencies(): void {
    const lines: Dependency[] = this.groups().flatMap(g => g.items.map(i => ({
      item: `${g.label}/${i.label}`, kind: i.kind, target: i.kind === 'url' ? i.url ?? '' : i.target ?? '', uses: [],
    })));
    this.dependencies.set(lines);
    lines.forEach((line, index) => {
      if (!(PICKABLE_KINDS as readonly string[]).includes(line.kind) || !line.target) return;
      this.api.get<{ items: ReferenceView[] }>(
        `/api/v1/admin/model/${encodeURIComponent(line.kind)}/${encodeURIComponent(line.target)}/references`,
        { page_size: '100' },
      ).subscribe({
        next: page => {
          const uses = (page.items ?? []).map(r => {
            const kind = r.target_kind ?? r.kind ?? '';
            const name = r.target_name ?? r.name ?? r.target_id ?? r.id ?? '';
            return kind ? `${kind}: ${name}` : String(name);
          });
          this.dependencies.update(all => all.map((d, i) => (i === index ? { ...d, uses } : d)));
        },
        // An object the person may not read keeps an empty line.
        error: () => undefined,
      });
    });
  }

  private objectId(): string {
    return this.id() === 'new' ? this.freshId : this.id();
  }

  private addItem(node: AppNode): void {
    const doc = this.current();
    if (!doc) return;
    let list = this.targetList(doc);
    if (!list) {
      this.addGroup();
      const after = this.current();
      if (!after) return;
      list = `/root/children/${(after.root.children ?? []).length - 1}/children`;
    }
    const at = this.current() ?? doc;
    const length = (valueAt(at, list) as unknown[]).length;
    this.exec({ op: 'add', path: `${list}/-`, value: node }, `${list}/${length}`);
  }

  /** The selected group's items, or the selected item's group's; none when nothing is selected. */
  private targetList(doc: AppDoc): string | null {
    const path = this.selectedPath();
    if (!path) {
      const groups = doc.root.children ?? [];
      return groups.length ? `/root/children/${groups.length - 1}/children` : null;
    }
    let node: AppNode | null = null;
    try {
      node = valueAt(doc, path) as AppNode;
    } catch {
      return null;
    }
    if (node.type === 'group') return `${path}/children`;
    if (node.type === 'item') return path.slice(0, path.lastIndexOf('/'));
    return null;
  }

  private exec(command: EditCommand, select?: string): void {
    this.canvas()?.exec(command, select);
  }

  private loadSources(): void {
    for (const kind of PICKABLE_KINDS) {
      this.model.objects(kind, 1).subscribe({
        next: page => this.sources.update(all => [
          ...all.filter(s => s.kind !== kind),
          ...(page.items ?? []).map((o: ObjectSummary) => ({ kind, id: o.id, name: o.name })),
        ]),
        // A kind the person may not list is simply not offered.
        error: () => undefined,
      });
    }
  }

  private load(id: string): void {
    this.error.set(null);
    if (id === 'new') {
      const nav: Navigation = { groups: [{ label: this.lang.translate('appDesigner.firstGroup'), items: [] }] };
      this.start(nav, '', '');
      return;
    }
    this.model.object('navigation', id).subscribe({
      next: v => this.start((v.doc ?? { groups: [] }) as Navigation, v.content_hash, v.name),
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }

  private start(nav: Navigation, hash: string, name: string): void {
    const doc = toCanvas(nav);
    this.initial.set(doc);
    this.current.set(doc);
    this.before.set(nav);
    this.landing.set(nav.landing ?? []);
    this.settings.set({ ...(nav.settings ?? {}) });
    this.hash.set(hash);
    this.name.set(name);
  }
}
