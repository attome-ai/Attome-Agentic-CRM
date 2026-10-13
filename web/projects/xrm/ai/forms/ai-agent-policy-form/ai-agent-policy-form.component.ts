import {
  ChangeDetectionStrategy, Component, DestroyRef, effect, inject, signal, untracked,
} from '@angular/core';
import { ReactiveFormsModule, type FormGroup } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { LangService } from '@attome/base';
import {
  FieldInputComponent, XrmBaseFormComponent, EngineFormBase, XrmTabDirective, recordTabDefs,
} from '@attome/xrm/core/entity';
import type { XrmFormTabDef } from '@attome/xrm/core/entity';
import type { FieldSchema } from '@attome/xrm';
import { CapabilityPickerComponent } from '../../components/capability-picker/capability-picker.component';
import { AiActionsService, type ActionSummary } from '../../services/ai-actions.service';
import { AdminAiService, parseJsonIdArray } from '../../services/admin-ai.service';
import type { CapabilityPackRow, KnowledgeSourceRow } from '../../services/admin-ai.service';

/**
 * Hand-written form for `ai_agent_policy` (C6, D-556) — an agent's ceiling,
 * budgets and grants, plus the three reference sets that feed the allow-list
 * term of the conjunction.
 *
 * **The null-versus-`[]` distinction is the point of this screen (I-16).** Two
 * controls here are tri-state — `allowed_action_ids` and
 * `knowledge_source_refs` — and in both cases:
 *
 *   `null`   the policy does *not narrow* by a list; the ceiling and the other
 *          constraints are what bound the session.
 *   `[]`     the policy grants **nothing** (or permits no retrieval).
 *
 * They are written by the explicit "restrict to the selected list" toggles and
 * are never collapsed into each other anywhere in this class — no `?? []`, no
 * `|| []`, no defaulting of one to the other in either direction. Collapsing
 * them the `[]`-to-`null` way would silently widen a policy an operator
 * deliberately narrowed to nothing, which is why the invariant has its own
 * acceptance rows (A-44…A-46).
 *
 * This form writes metadata and nothing else. It never claims to enforce
 * anything: the licence, the caller's privileges, the ceiling and the gate all
 * run per invocation, on the server, whatever is ticked here.
 */
@Component({
  selector: 'attome-ai-agent-policy-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [
    ReactiveFormsModule, RouterLink, XrmBaseFormComponent, XrmTabDirective, FieldInputComponent,
    CapabilityPickerComponent,
  ],
  styleUrls: ['../../../styles/xrm-form.css', './ai-agent-policy-form.component.css'],
  templateUrl: './ai-agent-policy-form.component.html',
})
export class AiAgentPolicyFormComponent extends EngineFormBase {
  private readonly lang = inject(LangService);
  private readonly actionsSvc = inject(AiActionsService);
  private readonly adminAi = inject(AdminAiService);
  private readonly viewDestroyRef = inject(DestroyRef);

  // ── Capabilities (allowed_action_ids) ─────────────────────────────────────
  /** The live action catalogue, exactly as `GET /api/v1/actions` returned it. */
  readonly actions = signal<ActionSummary[]>([]);
  readonly catalogueLoaded = signal(false);
  /**
   * The ticks the picker shows. While the restriction toggle is OFF this is a
   * *staged* selection, deliberately not the control's value: the control is
   * `null` until the operator turns the toggle on.
   */
  readonly actionSelection = signal<string[]>([]);
  /** True when `allowed_action_ids` is an array — including `[]`. */
  readonly restrictActions = signal(false);

  // ── Capability packs (capability_pack_refs) ───────────────────────────────
  readonly packs = signal<CapabilityPackRow[]>([]);
  readonly packsLoaded = signal(false);
  /** The referenced pack ids; mirrors the control's JSON array (no tri-state). */
  readonly packSelection = signal<string[]>([]);

  // ── Knowledge sources (knowledge_source_refs) ─────────────────────────────
  readonly sources = signal<KnowledgeSourceRow[]>([]);
  readonly sourcesLoaded = signal(false);
  readonly sourceSelection = signal<string[]>([]);
  /** True when `knowledge_source_refs` is an array — including `[]`. */
  readonly restrictSources = signal(false);

  /**
   * The policy's `risk_ceiling` as the control currently holds it, fed by the
   * form's own `valueChanges` because the select is rendered by
   * `<attome-field-input>` (this form cannot bind its change event directly). The
   * picker greys out rows above it.
   */
  readonly riskCeiling = signal<string | null>(null);

  constructor() {
    super();
    // The controls only exist once the schema has landed and the record is
    // patched in asynchronously, so every piece of derived state follows the
    // FormGroup's own emissions rather than a one-shot read taken too early.
    effect(() => {
      const fg = this.form();
      untracked(() => this.bindForm(fg));
    });

    this.actionsSvc.listActions().pipe(takeUntilDestroyed(this.viewDestroyRef)).subscribe({
      // An empty catalogue is the expected answer on a deployment that has not
      // licensed AI, has the kill switch off, or where this caller holds no
      // action privileges — not an error, and never a reason to invent rows.
      next: (actions) => {
        this.actions.set(actions);
        this.catalogueLoaded.set(true);
      },
      error: () => this.catalogueLoaded.set(true),
    });
    this.adminAi.listCapabilityPacks().pipe(takeUntilDestroyed(this.viewDestroyRef)).subscribe({
      next: (packs) => {
        this.packs.set(packs);
        this.packsLoaded.set(true);
      },
      error: () => this.packsLoaded.set(true),
    });
    this.adminAi.listKnowledgeSources().pipe(takeUntilDestroyed(this.viewDestroyRef)).subscribe({
      next: (sources) => {
        this.sources.set(sources);
        this.sourcesLoaded.set(true);
      },
      error: () => this.sourcesLoaded.set(true),
    });
  }

  protected override defineTabs(): XrmFormTabDef[] {
    return [
      { id: 'general', label: 'General', icon: 'las la-list-alt' },
      // D-773: the platform record tabs, rendered by <xrm-base-form>.
      ...recordTabDefs(this.name(), key => this.lang.translate(key)),
    ];
  }

  /** Looks up loaded schema fields by logicalname, in this form's fixed layout order. */
  protected fieldsIn(names: string[]): FieldSchema[] {
    const all = this.schema()?.fields ?? [];
    return names.map(n => all.find(f => f.name === n)).filter((f): f is FieldSchema => !!f);
  }

  // ── Capabilities ──────────────────────────────────────────────────────────

  /**
   * The restriction toggle for `allowed_action_ids`.
   *
   * ON writes the selected array — which may legitimately be `[]`, "this policy
   * grants nothing". OFF writes `null`, "this policy is not narrowed by an
   * allow-list", so the ceiling and the other constraints are what bound a
   * session started under it.
   */
  onRestrictActionsChange(on: boolean): void {
    this.restrictActions.set(on);
    // Wire form: 'allowed_action_ids' is a real multi-choice column, so the ON
    // branch writes the array itself — NOT JSON.stringify, unlike the two text
    // columns on this form (knowledge_source_refs, capability_pack_refs).
    this.writeControl('allowed_action_ids', on ? [...this.actionSelection()] : null);
  }

  /** The picker ticked or unticked an action. */
  onActionSelectionChange(ids: string[]): void {
    this.actionSelection.set(ids);
    // Toggle OFF: the control stays `null` on purpose. The ticks are a staged
    // preference the operator can come back to, NOT the policy's value, and
    // writing them here would turn "not narrowed" into a list nobody chose.
    if (!this.restrictActions()) return;
    this.writeControl('allowed_action_ids', ids);
  }

  // ── Capability packs ──────────────────────────────────────────────────────

  /** The reference list, where nothing selected is `null` ("no pack contributes"). */
  onPackToggle(id: string, event: Event): void {
    const next = toggle(this.packSelection(), id, event);
    this.packSelection.set(next);
    // No tri-state here: a pack list has no "unrestricted" reading — absent and
    // empty both contribute no ids — so "nothing selected" is written as the
    // `null` the JSON-list columns use for absent.
    this.writeControl('capability_pack_refs', next.length ? JSON.stringify(next) : null);
  }

  /**
   * A pack's `action_ids` is a JSON string (or absent). Both mean "this pack
   * contributes no ids", so collapsing them for a *count* loses nothing — the
   * values this class must never collapse are the policy's own tri-state fields.
   */
  packActionCount(pack: CapabilityPackRow): number {
    const ids = parseJsonIdArray(pack.action_ids);
    return ids === null ? 0 : ids.length;
  }

  // ── Knowledge sources ─────────────────────────────────────────────────────

  /**
   * The restriction toggle for `knowledge_source_refs` — the same rule as
   * `allowed_action_ids`, deliberately spelled out again rather than folded
   * into a shared helper: a shared helper is exactly where an `?? []` would
   * eventually appear, and the two fields carry different copy.
   *
   * ON writes the selected ids serialised as a JSON **string** — this column is
   * `text`, not a multi-choice — and `"[]"` is a real posture ("no knowledge
   * retrieval"), distinct from the OFF branch's `null` ("no narrowing from this
   * policy"). Neither branch may ever produce the other's value (I-16).
   */
  onRestrictSourcesChange(on: boolean): void {
    this.restrictSources.set(on);
    // Wire form: 'knowledge_source_refs' is a TEXT column holding a JSON array,
    // so the ON branch serialises — a raw array is invalid for it. OFF stays
    // `null` ("no narrowing from this policy"), never `[]`. (The capability
    // pack refs below take the same text form; allowed_action_ids is the one
    // that does not — see onRestrictActionsChange.)
    this.writeControl('knowledge_source_refs', on ? JSON.stringify([...this.sourceSelection()]) : null);
  }

  /** A source was ticked or unticked. */
  onSourceSelectionChange(id: string, event: Event): void {
    const next = toggle(this.sourceSelection(), id, event);
    this.sourceSelection.set(next);
    // Toggle OFF: keep the ticks staged, leave the control `null`.
    if (!this.restrictSources()) return;
    this.writeControl('knowledge_source_refs', JSON.stringify(next));
  }

  // ── Control plumbing ──────────────────────────────────────────────────────

  /**
   * Writes a renderer-owned control.
   *
   * `value` is `string | string[] | null` because the three fields differ:
   * `allowed_action_ids` is a multi-choice column and takes the array itself,
   * while `capability_pack_refs` and `knowledge_source_refs` are text columns
   * that take a JSON **string** — and, in the tri-state pair's case, `null`.
   * Nothing here normalises one into the other.
   *
   * `markAsDirty()` comes **first**: the base class refreshes its `dirty`
   * signal from the `valueChanges` emission, so the flag has to be set before
   * the write emits — otherwise an edit that only touched one of these pickers
   * would leave the Update button disabled on a genuinely changed policy.
   */
  private writeControl(name: string, value: string | string[] | null): void {
    const ctrl = this.form().get(name);
    if (!ctrl) return;
    ctrl.markAsDirty();
    ctrl.setValue(value);
  }

  private bindForm(fg: FormGroup): void {
    this.readState(fg.value as Record<string, unknown>);
    fg.valueChanges.pipe(takeUntilDestroyed(this.viewDestroyRef)).subscribe((value) => {
      this.readState(value as Record<string, unknown>);
    });
  }

  /**
   * Re-derives the picker state from the form's own value. Everything it reads
   * is the control's value — never a stored copy — so a load, a save's
   * `patchValue`, a 409 reload and the operator's own edits all land here the
   * same way.
   */
  private readState(value: Record<string, unknown>): void {
    const ceiling = value['risk_ceiling'];
    this.riskCeiling.set(typeof ceiling === 'string' ? ceiling : null);

    // allowed_action_ids — an array (INCLUDING []) means the toggle is on and
    // the checkboxes show exactly that array; null/absent means the toggle is
    // off and the checkboxes keep whatever the operator had staged.
    //
    // In *create* mode the base class defaults this multi-choice control to
    // [], so a new policy opens with the restriction ON and nothing granted —
    // the fail-closed reading, and the honest one: [] is what that control
    // holds and what saving would store. The operator turns the toggle off to
    // state "not narrowed by a list" instead, which writes null.
    const allowed = parseJsonIdArray(value['allowed_action_ids']);
    if (allowed === null) {
      this.restrictActions.set(false);
      // actionSelection is deliberately NOT reset: with the toggle off the
      // policy is not narrowed by a list, and the ticks are preserved so that
      // turning the toggle back on does not lose them.
    } else {
      this.restrictActions.set(true);
      this.actionSelection.set(allowed);
    }

    // capability_pack_refs — no tri-state. Absent and [] both mean "no pack
    // contributes", so the display collapses them; nothing is ever written
    // from here, so a collapse cannot round-trip back to the server.
    const packs = parseJsonIdArray(value['capability_pack_refs']);
    this.packSelection.set(packs === null ? [] : packs);

    // knowledge_source_refs — the second tri-state field, same rule as above:
    // an array (including []) is "restricted", null/absent is "not narrowed".
    const sources = parseJsonIdArray(value['knowledge_source_refs']);
    if (sources === null) {
      this.restrictSources.set(false);
    } else {
      this.restrictSources.set(true);
      this.sourceSelection.set(sources);
    }
  }
}

/** The next id list after a checkbox change, read from the input's own state. */
function toggle(current: string[], id: string, event: Event): string[] {
  const input = event.target as HTMLInputElement | null;
  if (!input?.checked) return current.filter((x) => x !== id);
  return current.includes(id) ? current : [...current, id];
}
