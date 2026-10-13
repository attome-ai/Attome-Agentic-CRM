import { ChangeDetectionStrategy, Component, computed, input, output } from '@angular/core';
import type { ActionSummary } from '../../services/ai-actions.service';

/**
 * The three risk tiers, in the order the gate ranks them (and the order a
 * picker must present them in — an operator reading a policy's grants top to
 * bottom is reading them in increasing blast radius).
 */
const RISK_ORDER = ['Read', 'Reversible', 'Consequential'] as const;

interface RiskGroup {
  risk: string;
  /** True for the Consequential tier, which never auto-executes for an agent. */
  fourEyes: boolean;
  rows: ActionSummary[];
}

/**
 * Ranks a risk tier name, case-insensitively: `ActionSummary.risk` is the
 * catalogue's `Read` | `Reversible` | `Consequential` while a policy's
 * `risk_ceiling` choice arrives lower-cased, and the two are compared to
 * decide which rows sit above the ceiling. `null` for anything unrecognised —
 * never a guessed rank, because a guessed rank would either grey out an id
 * that is genuinely allowed or fail to grey out one that is not.
 */
function rankOf(risk: string | null | undefined): number | null {
  switch (risk?.trim().toLowerCase()) {
    case 'read': return 0;
    case 'reversible': return 1;
    case 'consequential': return 2;
    default: return null;
  }
}

/**
 * The capability picker: the action catalogue (`GET /api/v1/actions` via
 * `AiActionsService`) grouped by risk tier, one checkbox per action id, shared
 * by the capability-pack form and the agent-policy form.
 *
 * It is deliberately a dumb view: it renders the selection it is handed and
 * emits the next one. Every decision about *what the selection means* — above
 * all the null-versus-`[]` distinction of the policy's `allowed_action_ids`
 * (I-16) — belongs to the form that owns the control, because only that form
 * knows which value it is writing.
 *
 * It never removes a row for being above the ceiling or out of reach: a policy
 * may legitimately grant an id its own ceiling refuses (the union is what an
 * operator means to express), and hiding the row would make that impossible to
 * see, let alone express.
 */
@Component({
  selector: 'xrm-capability-picker',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [],
  styleUrls: ['./capability-picker.component.css'],
  templateUrl: './capability-picker.component.html',
})
export class CapabilityPickerComponent {
  /** The catalogue, as `GET /api/v1/actions` reported it. */
  readonly actions = input<ActionSummary[]>([]);
  /** The action ids currently ticked. */
  readonly selected = input<string[]>([]);
  /** False while the catalogue is still in flight, so "empty" is never a flash. */
  readonly loaded = input(false);
  /**
   * The policy's `risk_ceiling` (its lower-cased choice value), or null when
   * no ceiling applies — the capability-pack form has none, so nothing is
   * greyed out there.
   */
  readonly ceiling = input<string | null>(null);
  /**
   * True while the enclosing form is keeping a selection the control does NOT
   * hold — the policy form's "restrict to the selected list" toggle is off, so
   * the rows read as a preserved preference rather than a live grant.
   */
  readonly dimmed = input(false);
  /** Prefix for this instance's DOM ids, so two pickers on one page stay distinct. */
  readonly idPrefix = input('capability');
  /** The next selection. The form writes it (or `null`) to its control. */
  readonly selectionChange = output<string[]>();

  readonly groups = computed<RiskGroup[]>(() => {
    const all = this.actions();
    return RISK_ORDER
      .map((risk) => ({
        risk: risk as string,
        fourEyes: risk === 'Consequential',
        rows: all.filter((a) => a.risk === risk),
      }))
      // A tier with nothing in it renders no heading: on an unlicensed
      // deployment the picker is one empty state, and three empty headings
      // would read as "these exist but you cannot see them".
      .filter((g) => g.rows.length > 0);
  });

  readonly total = computed(() => this.actions().length);

  private readonly ceilingRank = computed(() => rankOf(this.ceiling()));

  isSelected(id: string): boolean {
    return this.selected().includes(id);
  }

  /**
   * True when this row's risk sits above the policy's ceiling. The row stays
   * selectable — the ceiling refuses at dispatch, not here — and is labelled
   * so an operator can see both facts at once.
   */
  isAboveCeiling(risk: string): boolean {
    const ceiling = this.ceilingRank();
    const rank = rankOf(risk);
    return ceiling !== null && rank !== null && rank > ceiling;
  }

  /** Reads the checkbox's own state rather than assuming the click inverted it. */
  toggleFrom(actionId: string, event: Event): void {
    const input = event.target as HTMLInputElement | null;
    this.toggle(actionId, !!input?.checked);
  }

  private toggle(actionId: string, checked: boolean): void {
    const current = this.selected();
    const next = checked
      ? (current.includes(actionId) ? current : [...current, actionId])
      : current.filter((id) => id !== actionId);
    this.selectionChange.emit(next);
  }
}
