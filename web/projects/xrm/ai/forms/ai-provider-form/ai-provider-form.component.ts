import { ChangeDetectionStrategy, Component, DestroyRef, computed, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ReactiveFormsModule } from '@angular/forms';
import { catchError, from, map, mergeMap, of, toArray } from 'rxjs';
import { ApiService, LangService, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import {
  FieldInputComponent, XrmBaseFormComponent, EngineFormBase, XrmTabDirective, recordTabDefs,
} from '@attome/xrm/core/entity';
import type { EntityRecordResponse, XrmFormTabDef } from '@attome/xrm/core/entity';
import type { FieldSchema } from '@attome/xrm';

/** One model as the provider reported it — `attome_ai::provider_models::DiscoveredModel`. */
interface DiscoveredModel {
  id:            string;
  display_name:  string | null;
}

interface FetchModelsResponse {
  provider_id:   string;
  api_protocol:  string;
  models:        DiscoveredModel[];
}

interface SetCredentialResponse {
  provider_id:   string;
  secret_last4:  string | null;
}

/**
 * Hand-coded form for `ai_provider`, scaffolded from platform-bundles/attome-ai-provider.json's
 * "synthesized (no authored layout)" layout by scripts/bundle-to-form-component.mjs. Same
 * field-rendering approach as the generic dispatcher (<attome-field-input> per
 * schema field), but its own component/template — edit freely; re-running
 * the generator only overwrites this file with --force.
 *
 * Tab/section/field grouping below mirrors the bundle's layout at
 * generation time. The bundle JSON remains the source of truth for the
 * entity/fields themselves (schema, validation, choices) — only the form's
 * *presentation* moved to hand-written code.
 *
 * Two things here are NOT ordinary schema fields, because neither can be:
 *
 * - **API key.** Never an entity column (it would be selectable by any stored
 *   query). It is written through `POST …/providers/{id}/credential`, stored
 *   envelope-encrypted in `ai_provider_credential`, and never returned —
 *   so this form can show "configured", and the last four characters right
 *   after a save, but can never populate the input with the current value.
 * - **Models.** `POST …/providers/{id}/models/fetch` asks the provider itself
 *   what it offers. The result is a *shortlist to choose from*, not an
 *   automatic import: the operator ticks the models they want and this form
 *   creates those AI Model rows, which start at `approval_status = pending`
 *   under the D-435/D-491 gate.
 *
 * The key is submitted by the form's own Save (after the record, so a create
 * has an id to attach it to). Model fetching needs a saved record, so that
 * panel tells the operator to save first.
 */
@Component({
  selector:   'attome-ai-provider-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ReactiveFormsModule, TranslatePipe, XrmBaseFormComponent, XrmTabDirective, FieldInputComponent],
  styleUrls:  ['../../../styles/xrm-form.css', './ai-provider-form.component.css'],
  templateUrl: './ai-provider-form.component.html',
})
export class AiProviderFormComponent extends EngineFormBase {
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);
  /** Not `destroyRef`: the base class already owns a private member of that name. */
  private readonly lifetime = inject(DestroyRef);

  protected override defineTabs(): XrmFormTabDef[] {
    return [
      { id: 'details', label: 'Details', icon: 'las la-list-alt' },
      // D-773: the platform record tabs, rendered by <xrm-base-form>.
      ...recordTabDefs(this.name(), key => this.lang.translate(key)),
    ];
  }

  /** Looks up loaded schema fields by logicalname, in this form's fixed layout order. */
  protected fieldsIn(names: string[]): FieldSchema[] {
    const all = this.schema()?.fields ?? [];
    return names.map(n => all.find(f => f.name === n)).filter((f): f is FieldSchema => !!f);
  }

  // ---- API key -----------------------------------------------------------

  readonly apiKey     = signal('');
  readonly savingKey  = signal(false);
  readonly keyError   = signal<string | null>(null);
  /** Set from the save response; `null` until this session stores a key. */
  readonly keyLast4   = signal<string | null>(null);

  /**
   * Whether a key is already stored. Read from `credential_ref` on the loaded
   * record rather than from a dedicated GET: the reference is the only part of
   * the credential an API may disclose, and its presence is exactly the
   * question this badge answers.
   */
  readonly keyConfigured = computed(() => {
    const value = this.record?.data?.['credential_ref'];
    return typeof value === 'string' && value.trim().length > 0;
  });

  /**
   * The header Save button must light up for a typed key too: on a pristine
   * record the base rule ("nothing changed, nothing to save") would otherwise
   * leave a key the operator just pasted with no way to submit it.
   */
  override readonly canSave = computed(() =>
    !this.saving() && (!this.isEdit() || this.dirty() || this.apiKey().trim().length > 0));

  /**
   * One Save for the whole form. The key is not a schema field (see the class
   * comment), so it travels on its own request: a pristine record with only a
   * key typed skips the pointless record PUT, and everything else saves the
   * record first and stores the key once the record exists (`onSaved`).
   */
  override save(): void {
    if (this.isEdit() && !this.dirty() && this.apiKey().trim()) {
      if (!this.canSave()) { return; }
      this.beginSave();
      this.storeKey(this.id()!, ok => {
        this.completeSave();
        if (ok) { this.confirmSaved(); }
      });
      return;
    }
    super.save();
  }

  protected override onSaved(record: EntityRecordResponse): void {
    // Start the key request before the base class navigates a create to the
    // new record's route: it is bound to the record's own id, not to `id()`.
    if (this.apiKey().trim()) { this.storeKey(record.id); }
    super.onSaved(record);
  }

  private storeKey(id: string, done?: (ok: boolean) => void): void {
    const key = this.apiKey().trim();
    if (!key || this.savingKey()) { return; }

    this.savingKey.set(true);
    this.keyError.set(null);
    this.api.post<SetCredentialResponse>(`/api/v1/admin/ai/providers/${id}/credential`, { api_key: key })
      .subscribe({
        next: result => {
          this.keyLast4.set(result.secret_last4);
          // Clear the input as soon as the key is stored: leaving a live
          // secret sitting in a DOM input for the rest of the session is
          // exactly the exposure the write-only endpoint exists to avoid.
          this.apiKey.set('');
          this.savingKey.set(false);
          done?.(true);
        },
        error: (err: ApiError) => {
          // The key stays in the input so the operator can retry; the record
          // itself may already have saved.
          this.keyError.set(err.message || 'Could not save the API key.');
          this.savingKey.set(false);
          done?.(false);
        },
      });
  }

  // ---- Model discovery ---------------------------------------------------

  readonly fetchingModels = signal(false);
  readonly models         = signal<DiscoveredModel[] | null>(null);
  readonly modelsError    = signal<string | null>(null);

  fetchModels(): void {
    const id = this.id();
    if (!id || this.fetchingModels()) { return; }

    this.fetchingModels.set(true);
    this.modelsError.set(null);
    this.api.post<FetchModelsResponse>(`/api/v1/admin/ai/providers/${id}/models/fetch`, {})
      .subscribe({
        next: result => {
          this.models.set(result.models);
          this.selected.set(new Set());
          this.addModelsResult.set(null);
          this.addModelsError.set(null);
          this.fetchingModels.set(false);
          this.loadAddedModels(id);
        },
        error: err => {
          // A 422 here is the ordinary, actionable case (no Base URL, no API
          // protocol, external provider disabled, the provider refused), so
          // the server's own message is shown rather than a generic one.
          this.models.set(null);
          this.modelsError.set((err as ApiError).message || 'Could not reach this provider.');
          this.fetchingModels.set(false);
        },
      });
  }

  // ---- Adding fetched models as AI Model records --------------------------

  /** Provider model ids the operator ticked. */
  readonly selected = signal<ReadonlySet<string>>(new Set());
  /** Models this provider already has a catalog record for; `null` until known. */
  readonly addedModelIds = signal<ReadonlySet<string> | null>(null);
  readonly addingModels = signal(false);
  readonly addModelsError = signal<string | null>(null);
  readonly addModelsResult = signal<{ added: number; failed: number } | null>(null);

  /** Ticked models that are not already catalogued. */
  private readonly pending = computed(() => {
    const added = this.addedModelIds();
    return (this.models() ?? []).filter(m => this.selected().has(m.id) && !added?.has(m.id));
  });
  readonly selectedCount = computed(() => this.pending().length);
  private readonly selectable = computed(() =>
    (this.models() ?? []).filter(m => !this.addedModelIds()?.has(m.id)));
  readonly allSelected = computed(() =>
    this.selectable().length > 0 && this.selectedCount() === this.selectable().length);
  readonly someSelected = computed(() => this.selectedCount() > 0 && !this.allSelected());
  /** Disabled until the existing catalog is known, so a re-add cannot duplicate. */
  readonly canAddModels = computed(() =>
    !this.addingModels() && this.addedModelIds() !== null && this.selectedCount() > 0);

  isAdded(modelId: string): boolean {
    return this.addedModelIds()?.has(modelId) ?? false;
  }

  toggleModel(modelId: string, checked: boolean): void {
    const next = new Set(this.selected());
    if (checked) { next.add(modelId); } else { next.delete(modelId); }
    this.selected.set(next);
  }

  toggleAll(checked: boolean): void {
    this.selected.set(checked ? new Set(this.selectable().map(m => m.id)) : new Set());
  }

  private loadAddedModels(providerId: string): void {
    this.addedModelIds.set(null);
    this.svc.list('ai_model', {
      filters: [{ field: 'provider_ref', op: 'eq', value: providerId }],
      limit: 200,
    }).pipe(takeUntilDestroyed(this.lifetime)).subscribe({
      next: res => this.addedModelIds.set(
        new Set(res.data.map(r => String(r.data['provider_model_id'] ?? '')))),
      error: (err: ApiError) => this.addModelsError.set(
        err.message || 'Could not check which models are already added.'),
    });
  }

  /**
   * Creates one AI Model record per ticked model, through the ordinary entity
   * API so every field rule and audit event applies. They start
   * `approval_status = pending` (D-435/D-491): adding a model to the catalog
   * does not let any action invoke it. Bounded concurrency; one failure does
   * not stop the rest, and the summary says how many landed.
   */
  addSelectedModels(): void {
    const providerId = this.id();
    const chosen = this.pending();
    if (!providerId || !chosen.length || this.addingModels()) { return; }

    this.addingModels.set(true);
    this.addModelsError.set(null);
    this.addModelsResult.set(null);
    from(chosen).pipe(
      mergeMap(m => this.svc.create('ai_model', {
        name:              m.display_name || m.id,
        provider_ref:      providerId,
        provider_model_id: m.id,
        approval_status:   'pending',
        model_type:        /embed/i.test(m.id) ? 'embedding' : 'chat',
      }).pipe(
        map(() => ({ id: m.id, error: null as string | null })),
        catchError((err: ApiError) => of({ id: m.id, error: err.message || 'failed' })),
      ), 4),
      toArray(),
      takeUntilDestroyed(this.lifetime),
    ).subscribe(results => {
      const done = results.filter(r => r.error === null).map(r => r.id);
      const failed = results.filter(r => r.error !== null);
      this.addedModelIds.set(new Set([...(this.addedModelIds() ?? []), ...done]));
      this.selected.set(new Set([...this.selected()].filter(id => !done.includes(id))));
      this.addModelsResult.set({ added: done.length, failed: failed.length });
      if (failed.length) {
        this.addModelsError.set(
          `${failed.length} of ${results.length} could not be added: ${failed[0].error}`);
      }
      this.addingModels.set(false);
    });
  }
}
