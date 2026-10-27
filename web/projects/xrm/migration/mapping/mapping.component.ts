import { ChangeDetectionStrategy, Component, OnInit, computed, inject, input, signal } from '@angular/core';
import { ApiError, LangService, TranslatePipe } from '@attome/base';

import {
  AttributeMapping, CREATE_TYPES, EntityMapping, MapAction, MappingDoc, MigrationWave, ModelMapping, ModelMappingService,
  counts, merges, withAttribute, withEntity, withUser,
} from './model-mapping';

/**
 * A24-T3: a migration project's model mapping as a table. Each source
 * entity, then each of its fields, says what it becomes here: mapped onto
 * an existing entity or attribute, created, or skipped. A field's target
 * can be renamed, two fields pointed at one attribute (a merge, marked),
 * and a created field's type changed. Without a mapping yet, the source's
 * model (as its connector describes it, a JSON file or text) is drafted
 * into one by the server. Save keeps the edits; the problems the server
 * finds come back with them.
 */
@Component({
  selector: 'xrm-model-mapping',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  templateUrl: './mapping.component.html',
  styleUrl: './mapping.component.css',
})
export class MappingComponent implements OnInit {
  private readonly service = inject(ModelMappingService);
  private readonly lang = inject(LangService);

  /** The migration project (the route's `:id`). */
  readonly id = input.required<string>();

  readonly doc = signal<MappingDoc | null>(null);
  readonly mapping = signal<ModelMapping | null>(null);
  readonly dirty = signal(false);
  readonly loading = signal(true);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  readonly sourceText = signal('');
  /** The integration system to read the source model from. */
  readonly system = signal('');
  /** A24-T4: the project's waves, newest first. */
  readonly waves = signal<MigrationWave[]>([]);
  readonly waveKeys: Readonly<Record<MigrationWave['kind'], string>> = {
    full: 'modelMapping.wave.full',
    catch_up: 'modelMapping.wave.catchUp',
    cut_over: 'modelMapping.wave.cutOver',
  };
  readonly waveStatusKeys: Readonly<Record<MigrationWave['status'], string>> = {
    queued: 'modelMapping.wave.queued',
    running: 'modelMapping.wave.running',
    loaded: 'modelMapping.wave.loaded',
    failed: 'modelMapping.wave.failed',
    rolled_back: 'modelMapping.wave.rolledBack',
  };
  /** A wave is queued or running: another cannot start. */
  readonly waveBusy = computed(() => this.waves().some(w => w.status === 'queued' || w.status === 'running'));

  readonly actions: readonly MapAction[] = ['map', 'create', 'skip'];
  readonly types = CREATE_TYPES;
  readonly actionKeys: Readonly<Record<MapAction, string>> = {
    map: 'modelMapping.action.map',
    create: 'modelMapping.action.create',
    skip: 'modelMapping.action.skip',
  };
  readonly counts = computed(() => {
    const m = this.mapping();
    return m ? counts(m) : { map: 0, create: 0, skip: 0 };
  });

  ngOnInit(): void {
    this.service.get(this.id()).subscribe({
      next: doc => this.show(doc),
      error: (e: ApiError) => {
        this.loading.set(false);
        if (e.status !== 404) this.error.set(this.lang.errorText(e));
      },
    });
  }

  /** A24-T4: reloads the waves. */
  loadWaves(): void {
    this.service.waves(this.id()).subscribe({ next: page => this.waves.set(page.items), error: () => this.waves.set([]) });
  }

  /** A24-T4: queues the next wave from the named system. */
  startWave(cutOver: boolean): void {
    const system = this.system().trim();
    if (!system || this.busy() || this.dirty()) return;
    this.busy.set(true);
    this.service.startWave(this.id(), system, cutOver).subscribe({
      next: wave => {
        this.busy.set(false);
        this.waves.update(all => [wave, ...all]);
      },
      error: (e: ApiError) => this.fail(e),
    });
  }

  private show(doc: MappingDoc): void {
    this.doc.set(doc);
    this.mapping.set(doc.mapping);
    this.dirty.set(false);
    this.loading.set(false);
    this.busy.set(false);
    this.error.set(null);
    this.loadWaves();
  }

  private fail(e: ApiError): void {
    this.busy.set(false);
    this.error.set(e.status === 409 ? this.lang.translate('modelMapping.conflict') : this.lang.errorText(e));
  }

  merged(entity: EntityMapping): Set<string> {
    return merges(entity);
  }

  onSourceText(event: Event): void {
    this.sourceText.set((event.target as HTMLTextAreaElement).value);
  }

  onSourceFile(event: Event): void {
    const file = (event.target as HTMLInputElement).files?.[0];
    if (!file) return;
    file.text().then(text => this.sourceText.set(text), () => this.error.set(this.lang.translate('modelMapping.unreadable')));
  }

  onSystem(event: Event): void {
    this.system.set((event.target as HTMLInputElement).value);
  }

  /** Reads the source model from the named system into the text, ready to draft. */
  describe(): void {
    const system = this.system().trim();
    if (!system || this.busy()) return;
    this.busy.set(true);
    this.error.set(null);
    this.service.describe(this.id(), system).subscribe({
      next: res => {
        this.busy.set(false);
        this.sourceText.set(JSON.stringify(res.source_model, null, 2));
      },
      error: (e: ApiError) => this.fail(e),
    });
  }

  /** Drafts a mapping from the source model typed or loaded. */
  draft(): void {
    let model: unknown;
    try {
      model = JSON.parse(this.sourceText());
    } catch {
      this.error.set(this.lang.translate('modelMapping.notJson'));
      return;
    }
    const source = (model as { source_model?: unknown }).source_model ?? model;
    this.busy.set(true);
    this.service.draft(this.id(), source).subscribe({ next: doc => this.show(doc), error: (e: ApiError) => this.fail(e) });
  }

  setEntityAction(e: number, event: Event): void {
    this.edit(m => withEntity(m, e, { action: (event.target as HTMLSelectElement).value as MapAction }));
  }

  setEntityTarget(e: number, event: Event): void {
    this.edit(m => withEntity(m, e, { target: (event.target as HTMLInputElement).value.trim() }));
  }

  setAction(e: number, a: number, event: Event): void {
    this.edit(m => withAttribute(m, e, a, { action: (event.target as HTMLSelectElement).value as MapAction }));
  }

  setTarget(e: number, a: number, event: Event): void {
    this.edit(m => withAttribute(m, e, a, { target: (event.target as HTMLInputElement).value.trim() }));
  }

  setType(e: number, a: number, event: Event): void {
    this.edit(m => withAttribute(m, e, a, { field_type: (event.target as HTMLSelectElement).value, type_mismatch: false }));
  }

  setUser(u: number, event: Event): void {
    this.edit(m => withUser(m, u, (event.target as HTMLInputElement).value));
  }

  private edit(change: (m: ModelMapping) => ModelMapping): void {
    const m = this.mapping();
    if (!m) return;
    this.mapping.set(change(m));
    this.dirty.set(true);
  }

  save(): void {
    const m = this.mapping();
    const doc = this.doc();
    if (!m || !doc || this.busy()) return;
    this.busy.set(true);
    this.service.save(this.id(), m, doc.row_version).subscribe({ next: d => this.show(d), error: (e: ApiError) => this.fail(e) });
  }

  /** Back to the mapping as last saved. */
  revert(): void {
    const doc = this.doc();
    if (!doc) return;
    this.mapping.set(doc.mapping);
    this.dirty.set(false);
  }

  choiceSummary(a: AttributeMapping): string {
    const unmatched = a.choices.filter(c => c.target === null).length;
    return this.lang.translate('modelMapping.choices', { count: a.choices.length, unmatched });
  }
}
