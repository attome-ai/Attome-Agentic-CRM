import { ChangeDetectionStrategy, Component, computed, inject, OnInit, signal } from '@angular/core';
import { ApiError, ApiService, LangService, TranslatePipe } from '@attome/base';
import { ModelService } from '@attome/xrm/model';
import type { ModelCommand, ObjectSummary } from '@attome/xrm/model';
import { catchError, forkJoin, map, of, switchMap } from 'rxjs';
import type { Observable } from 'rxjs';

import { AdminService } from '../data/services/admin.service';
import type { AttributeMeta, EntityMeta } from '../data/services/admin.service';

/** The on/off switches (attome_model::kinds::entity_settings::BOOL_SWITCHES). */
export const BOOL_SWITCHES = [
  'activities', 'notes', 'attachments', 'attribute_history', 'search', 'duplicate_detection', 'offline', 'ai',
] as const;
export type BoolSwitch = typeof BOOL_SWITCHES[number];
export const AUDIT_LEVELS = ['off', 'changes', 'full'] as const;
export const PRESETS = ['light', 'standard', 'full'] as const;

/** One entity's settings document (the `entity_settings` kind). */
export interface EntitySettingsDoc {
  entity?: string;
  preset?: string;
  switches?: Record<string, boolean | string>;
}

export interface EffectiveSetting { value: boolean | string; source: 'preset' | 'set_here' }

/**
 * A preset's value for every switch — the same table as the server's
 * `preset_values`. Pure.
 */
export function presetValues(preset: string): Record<string, boolean | string> {
  const on: readonly string[] = preset === 'light'
    ? ['notes', 'search']
    : preset === 'full'
      ? BOOL_SWITCHES
      : ['activities', 'notes', 'attachments', 'search', 'duplicate_detection'];
  const out: Record<string, boolean | string> = {};
  for (const name of BOOL_SWITCHES) out[name] = on.includes(name);
  out['audit_level'] = preset === 'light' ? 'off' : preset === 'full' ? 'full' : 'changes';
  return out;
}

/** Every switch's value and where it came from, as the server's `effective`. Pure. */
export function effective(doc: EntitySettingsDoc | null): Record<string, EffectiveSetting> {
  const out: Record<string, EffectiveSetting> = {};
  for (const [name, value] of Object.entries(presetValues(doc?.preset ?? 'standard'))) {
    out[name] = { value, source: 'preset' };
  }
  for (const [name, value] of Object.entries(doc?.switches ?? {})) {
    if (name in out) out[name] = { value, source: 'set_here' };
  }
  return out;
}

/** The edit commands that turn `before` into `after` (a new object starts from `{}`). Pure. */
export function settingsCommands(entityId: string, before: EntitySettingsDoc | null, after: EntitySettingsDoc): ModelCommand[] {
  const commands: ModelCommand[] = [];
  if (!before) commands.push({ op: 'set', path: '/entity', value: entityId });
  if ((before?.preset ?? null) !== (after.preset ?? null)) {
    commands.push({ op: 'set', path: '/preset', value: after.preset ?? 'standard' });
  }
  const switches = after.switches ?? {};
  if (JSON.stringify(before?.switches ?? {}) !== JSON.stringify(switches)) {
    commands.push({ op: 'set', path: '/switches', value: switches });
  }
  return commands;
}

/** Attribute counts per sensitivity label, most sensitive first. Pure. */
export function labelCounts(attributes: AttributeMeta[]): { label: string; count: number }[] {
  const order = ['secret', 'health', 'financial', 'personal', 'internal', 'public'];
  const counts = new Map<string, number>();
  for (const a of attributes) {
    const label = String((a as { sensitivity?: string }).sensitivity ?? 'internal');
    counts.set(label, (counts.get(label) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([label, count]) => ({ label, count }))
    .sort((x, y) => order.indexOf(x.label) - order.indexOf(y.label));
}

/** A UUIDv7 for a new settings object. */
function newId(now = Date.now()): string {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16));
  let ts = now;
  for (let i = 5; i >= 0; i--) {
    bytes[i] = ts % 256;
    ts = Math.floor(ts / 256);
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

interface SettingsObject { id: string; hash: string; doc: EntitySettingsDoc }
interface RetentionRule { name: string; entity_logicalname: string; period_days: number; action: string; is_active: boolean }
interface LegalHold { id: string; entity_logicalname: string; matter_reference: string }

/**
 * A31-T5 — the entity settings page: one entity's switches (a preset and
 * per-switch overrides, each with what it costs to keep on), its
 * data-protection card (labels, encryption, retention, holds) and a table
 * comparing every entity's effective settings.
 */
@Component({
  selector: 'xrm-entity-settings',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styleUrls: ['../config-admin.css'],
  template: `
    <section class="config-admin" data-entity-settings>
      <h2>{{ 'entitySettings.title' | translate }}</h2>
      <p class="config-intro">{{ 'entitySettings.intro' | translate }}</p>
      @if (error(); as e) { <p class="config-error" role="alert">{{ e }}</p> }
      @if (loading()) {
        <p class="config-state">{{ 'entitySettings.loading' | translate }}</p>
      } @else {
        <label class="config-field">
          <span>{{ 'entitySettings.entity' | translate }}</span>
          <select data-entity-pick [value]="selected() ?? ''" (change)="select($any($event.target).value)">
            <option value="">{{ 'entitySettings.pick' | translate }}</option>
            @for (e of entities(); track e.id) { <option [value]="e.id">{{ e.name }}</option> }
          </select>
        </label>

        @if (selected(); as id) {
          <div class="config-card" data-settings-editor>
            <h3>{{ 'entitySettings.switches' | translate }}</h3>
            <label class="config-field">
              <span>{{ 'entitySettings.preset' | translate }}</span>
              <select data-preset [value]="draft().preset ?? 'standard'" (change)="setPreset($any($event.target).value)">
                @for (p of presets; track p) { <option [value]="p">{{ 'entitySettings.presets.' + p | translate }}</option> }
              </select>
            </label>
            <table class="config-table">
              <thead>
                <tr>
                  <th scope="col">{{ 'entitySettings.switch' | translate }}</th>
                  <th scope="col">{{ 'entitySettings.value' | translate }}</th>
                  <th scope="col">{{ 'entitySettings.cost' | translate }}</th>
                </tr>
              </thead>
              <tbody>
                @for (name of boolSwitches; track name) {
                  <tr [attr.data-switch]="name">
                    <th scope="row">{{ 'entitySettings.names.' + name | translate }}</th>
                    <td>
                      <input type="checkbox" [checked]="draftEffective()[name].value === true"
                             (change)="setSwitch(name, $any($event.target).checked)" />
                      @if (draftEffective()[name].source === 'set_here') {
                        <span class="config-badge" data-set-here>{{ 'entitySettings.setHere' | translate }}</span>
                      }
                    </td>
                    <td class="config-note">{{ 'entitySettings.costs.' + name | translate }}</td>
                  </tr>
                }
                <tr data-switch="audit_level">
                  <th scope="row">{{ 'entitySettings.names.audit_level' | translate }}</th>
                  <td>
                    <select [value]="draftEffective()['audit_level'].value" (change)="setSwitch('audit_level', $any($event.target).value)">
                      @for (l of auditLevels; track l) { <option [value]="l">{{ 'entitySettings.audit.' + l | translate }}</option> }
                    </select>
                  </td>
                  <td class="config-note">{{ 'entitySettings.costs.audit_level' | translate }}</td>
                </tr>
              </tbody>
            </table>
            <div class="config-actions">
              <button type="button" data-save [disabled]="busy() || !dirty()" (click)="save(id)">{{ 'entitySettings.save' | translate }}</button>
              @if (saved()) { <span class="config-state" data-saved>{{ 'entitySettings.saved' | translate }}</span> }
            </div>
          </div>

          <div class="config-card" data-protection>
            <h3>{{ 'entitySettings.protection' | translate }}</h3>
            <h4>{{ 'entitySettings.labels' | translate }}</h4>
            <ul>
              @for (l of labels(); track l.label) {
                <li [attr.data-label]="l.label">{{ 'entitySettings.label.' + l.label | translate }} <strong>{{ l.count }}</strong></li>
              }
            </ul>
            <h4>{{ 'entitySettings.encryption' | translate }}</h4>
            <p class="config-note">{{ 'entitySettings.encryptionNote' | translate }}</p>
            <h4>{{ 'entitySettings.retention' | translate }}</h4>
            @let rules = retention();
            @if (rules === null) {
              <p class="config-note" data-retention-hidden>{{ 'entitySettings.notVisible' | translate }}</p>
            } @else if (!rules.length) {
              <p class="config-note" data-retention-none>{{ 'entitySettings.noRetention' | translate }}</p>
            } @else {
              <ul>
                @for (r of rules; track r.name) {
                  <li data-retention-rule>{{ 'entitySettings.retentionRule' | translate: { name: r.name, days: r.period_days, action: r.action } }}</li>
                }
              </ul>
            }
            <h4>{{ 'entitySettings.holds' | translate }}</h4>
            @let activeHolds = holds();
            @if (activeHolds === null) {
              <p class="config-note">{{ 'entitySettings.notVisible' | translate }}</p>
            } @else {
              <p class="config-note" data-holds>{{ 'entitySettings.holdCount' | translate: { count: activeHolds.length } }}</p>
            }
          </div>
        }

        <h3>{{ 'entitySettings.compare' | translate }}</h3>
        <div class="table-wrap">
          <table class="config-table" data-compare>
            <thead>
              <tr>
                <th scope="col">{{ 'entitySettings.entity' | translate }}</th>
                <th scope="col">{{ 'entitySettings.preset' | translate }}</th>
                @for (name of boolSwitches; track name) { <th scope="col">{{ 'entitySettings.names.' + name | translate }}</th> }
                <th scope="col">{{ 'entitySettings.names.audit_level' | translate }}</th>
              </tr>
            </thead>
            <tbody>
              @for (row of compareRows(); track row.id) {
                <tr [attr.data-compare-row]="row.logicalname">
                  <th scope="row">{{ row.name }}</th>
                  <td>{{ 'entitySettings.presets.' + row.preset | translate }}</td>
                  @for (name of boolSwitches; track name) {
                    <td [attr.data-on]="row.values[name].value === true">{{ (row.values[name].value === true ? 'entitySettings.on' : 'entitySettings.off') | translate }}</td>
                  }
                  <td>{{ 'entitySettings.audit.' + row.values['audit_level'].value | translate }}</td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      }
    </section>
  `,
})
export class EntitySettingsComponent implements OnInit {
  private readonly admin = inject(AdminService);
  private readonly model = inject(ModelService);
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);

  readonly boolSwitches = BOOL_SWITCHES;
  readonly auditLevels = AUDIT_LEVELS;
  readonly presets = PRESETS;

  readonly loading = signal(true);
  readonly busy = signal(false);
  readonly saved = signal(false);
  readonly error = signal<string | null>(null);
  readonly entities = signal<EntityMeta[]>([]);
  /** Settings objects by entity id. */
  readonly objects = signal<Record<string, SettingsObject>>({});
  readonly selected = signal<string | null>(null);
  readonly draft = signal<EntitySettingsDoc>({});
  readonly attributes = signal<AttributeMeta[]>([]);
  /** `null` when the caller may not read retention rules. */
  readonly retention = signal<RetentionRule[] | null>([]);
  /** `null` when the caller may not read legal holds. */
  readonly holds = signal<LegalHold[] | null>([]);

  readonly draftEffective = computed(() => effective(this.draft()));
  readonly labels = computed(() => labelCounts(this.attributes()));
  readonly dirty = computed(() => {
    const id = this.selected();
    if (!id) return false;
    return settingsCommands(id, this.objects()[id]?.doc ?? null, this.draft()).length > 0;
  });
  readonly compareRows = computed(() => this.entities().map(e => {
    const doc = this.objects()[e.id]?.doc ?? null;
    return { id: e.id, name: e.name, logicalname: e.logicalname, preset: doc?.preset ?? 'standard', values: effective(doc) };
  }));

  ngOnInit(): void {
    forkJoin({
      entities: this.admin.listEntities(),
      objects: this.loadObjects(),
    }).subscribe({
      next: ({ entities, objects }) => {
        this.entities.set([...entities].sort((a, b) => a.name.localeCompare(b.name)));
        this.objects.set(objects);
        this.loading.set(false);
      },
      error: (e: ApiError) => {
        this.error.set(this.lang.errorText(e));
        this.loading.set(false);
      },
    });
  }

  /** Every published or draft settings object, keyed by the entity it names. */
  private loadObjects(): Observable<Record<string, SettingsObject>> {
    return this.api.getAllPages<ObjectSummary>('/api/v1/admin/model/entity_settings').pipe(
      switchMap(summaries => summaries.length
        ? forkJoin(summaries.map(s => this.model.object('entity_settings', s.id).pipe(
          map(v => ({ id: s.id, hash: v.content_hash, doc: (v.doc ?? {}) as EntitySettingsDoc })),
        )))
        : of([] as SettingsObject[])),
      map(list => {
        const out: Record<string, SettingsObject> = {};
        for (const o of list) if (o.doc.entity) out[o.doc.entity] = o;
        return out;
      }),
    );
  }

  select(id: string): void {
    this.saved.set(false);
    this.selected.set(id || null);
    if (!id) return;
    const doc = this.objects()[id]?.doc;
    this.draft.set(doc ? { ...doc, switches: { ...(doc.switches ?? {}) } } : {});
    const entity = this.entities().find(e => e.id === id);
    this.admin.getEntity(id).subscribe({
      next: detail => this.attributes.set(detail.attributes),
      error: () => this.attributes.set([]),
    });
    this.api.getAllPages<RetentionRule>('/api/v1/admin/retention/rules').pipe(catchError(() => of(null)))
      .subscribe(rules => this.retention.set(rules ? rules.filter(r => r.entity_logicalname === entity?.logicalname) : null));
    this.api.getAllPages<LegalHold>('/api/v1/admin/legal-holds').pipe(catchError(() => of(null)))
      .subscribe(holds => this.holds.set(holds ? holds.filter(h => h.entity_logicalname === entity?.logicalname) : null));
  }

  setPreset(preset: string): void {
    this.saved.set(false);
    this.draft.update(d => ({ ...d, preset }));
  }

  /** A switch set here; set back to its preset's value, it is dropped. */
  setSwitch(name: string, value: boolean | string): void {
    this.saved.set(false);
    this.draft.update(d => {
      const switches = { ...(d.switches ?? {}) };
      if (presetValues(d.preset ?? 'standard')[name] === value) delete switches[name];
      else switches[name] = value;
      return { ...d, switches };
    });
  }

  save(entityId: string): void {
    const existing = this.objects()[entityId] ?? null;
    const commands = settingsCommands(entityId, existing?.doc ?? null, this.draft());
    if (!commands.length || this.busy()) return;
    const objectId = existing?.id ?? newId();
    const name = this.entities().find(e => e.id === entityId)?.logicalname ?? entityId;
    this.busy.set(true);
    this.error.set(null);
    this.model.saveDraft('entity_settings', objectId, existing?.hash ?? '', existing ? null : name, commands).pipe(
      switchMap(draft => this.model.publish('entity_settings', objectId).pipe(map(() => draft))),
    ).subscribe({
      next: draft => {
        this.busy.set(false);
        this.saved.set(true);
        const doc = { ...this.draft(), entity: entityId };
        this.objects.update(o => ({ ...o, [entityId]: { id: objectId, hash: draft.content_hash, doc } }));
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(this.lang.errorText(e));
      },
    });
  }
}
