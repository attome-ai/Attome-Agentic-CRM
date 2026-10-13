import { Injectable } from '@angular/core';
import { Observable, Subject } from 'rxjs';

// M26 (Dashboard) gap-fill — the Angular half of cross-filtering (plan §3
// "widget -> dashboard variable binding: a click on a chart segment sets a
// variable; other widgets bound to it re-query"). The backend contributes
// only metadata — `dashboard_widget.emits`/`.listens`
// (crates/engine/attome-dashboard/src/seed.rs), each a JSON array of variable
// names — and the actual query re-execution already goes through the
// existing `/api/v1/query/execute` (no new backend surface, see that
// module's own doc comment). This file is the client-side bus that turns
// "widget A's click set variable X" into "which OTHER widgets, bound to X
// directly or transitively, must re-query."
//
// **Why "transitively" needs a bound.** A widget can both `listens` on a
// variable AND `emits` one when its own re-query completes and the user
// interacts with it again — so a change can, in principle, chain through
// several widgets (A emits X -> B listens X, re-queries, later emits Y -> C
// listens Y, ...). Two widgets can also form a direct cycle (A emits X,
// listens Y; B emits Y, listens X). `resolveReQueryChain` below computes the
// full one-change closure breadth-first, hop by hop, and a `visited` set
// means no widget is ever added to the result twice — but the explicit
// `MAX_PROPAGATION_HOPS` cap is the real guarantee: propagation depth is
// bounded independent of how many widgets exist on the dashboard, so a
// pathological binding graph degrades to "stops re-querying after N hops,"
// never "the browser tab hangs." See `dashboard-variable-bus.service.spec.ts`
// for the bounded-loop regression coverage.

/** Mirrors one `dashboard_widget` row's cross-filtering metadata. */
export interface WidgetCrossFilterBinding {
  widgetId: string;
  emits: string[];
  listens: string[];
}

export interface VariableChangeEvent {
  variable: string;
  value: unknown;
  /** The widget whose own interaction (e.g. a chart-segment click) set this
   * variable — excluded from re-query since it isn't reacting to its own
   * click. */
  sourceWidgetId: string;
}

export interface ReQueryNotification {
  event: VariableChangeEvent;
  /** Widget ids to re-query, in propagation order — never contains
   * `event.sourceWidgetId`, never contains a duplicate. */
  widgetIds: string[];
}

/** How many hops of transitive emit -> listen chaining a single variable
 * change may propagate through before the bus stops expanding it further —
 * the bounded-loop guardrail this module's doc comment describes. Generous
 * enough for any real dashboard (a builder UI realistically nests far fewer
 * than 8 levels of cross-filtering) while still being a hard, observable
 * ceiling rather than "large enough that pathological cases are unlikely." */
export const MAX_PROPAGATION_HOPS = 8;

/** Every widget listening directly on `variable`, excluding
 * `excludeWidgetId` — the one-hop primitive `resolveReQueryChain` builds on.
 * Exported separately because a caller that only cares about direct
 * (non-transitive) cross-filtering doesn't need the bounded BFS below. */
export function widgetsListeningOn(
  bindings: readonly WidgetCrossFilterBinding[],
  variable: string,
  excludeWidgetId: string,
): string[] {
  return bindings
    .filter((b) => b.widgetId !== excludeWidgetId && b.listens.includes(variable))
    .map((b) => b.widgetId);
}

/**
 * Resolves the full, bounded set of widgets one variable change should
 * re-query — a breadth-first expansion through each newly-reached widget's
 * own `emits`, capped at {@link MAX_PROPAGATION_HOPS} hops and de-duplicated
 * via a `visited` set (so even within the hop budget, no widget is ever
 * told to re-query twice for the same change, and the original source
 * widget is never included). Pure function — no bus/subscription state — so
 * it is unit-testable in isolation and is exactly what
 * {@link DashboardVariableBusService.emit} calls.
 */
export function resolveReQueryChain(
  bindings: readonly WidgetCrossFilterBinding[],
  changed: VariableChangeEvent,
): string[] {
  const visited = new Set<string>([changed.sourceWidgetId]);
  const result: string[] = [];
  let frontierVariables = new Set<string>([changed.variable]);
  let hop = 0;

  while (frontierVariables.size > 0 && hop < MAX_PROPAGATION_HOPS) {
    hop++;
    const nextVariables = new Set<string>();
    for (const variable of frontierVariables) {
      for (const binding of bindings) {
        if (visited.has(binding.widgetId) || !binding.listens.includes(variable)) continue;
        visited.add(binding.widgetId);
        result.push(binding.widgetId);
        for (const emitted of binding.emits) nextVariables.add(emitted);
      }
    }
    frontierVariables = nextVariables;
  }
  return result;
}

/** Structural shape of a filter carrying a `@variable` placeholder. Kept for
 * callers outside the dashboard viewer; the viewer itself sends variable values
 * to the server as `cross_filters` (Phase 2.3). */
export interface VariableBoundFilter {
  field: string;
  op:    string;
  value?: string;
}

/**
 * Replaces a filter whose `value` is a `@variable` placeholder with that
 * variable's current value from {@link DashboardVariableBusService.values}.
 * This is what makes cross-filtering *actually filter*: a widget whose
 * `query_params` carries `{"field":"region","op":"eq","value":"@region"}`
 * genuinely narrows once another widget emits `region`. A filter whose value
 * is not a `@` placeholder, or names a variable nothing has set yet, is
 * returned unchanged — so a widget with no bound variables, or a dashboard
 * where no cross-filter has fired, behaves exactly as before.
 *
 * Both naming conventions resolve: `dashboard_widget.emits`/`.listens`
 * carry **bare** names (`region`), while the backend's built-in variables
 * (`context.rs`) are `@`-prefixed (`@current_user`). `@region` therefore tries
 * the key `@region` first, then falls back to `region`.
 */
export function substituteVariableValues<T extends VariableBoundFilter>(
  filters: readonly T[],
  values: ReadonlyMap<string, unknown>,
): T[] {
  return filters.map(filter => {
    if (typeof filter.value !== 'string' || !filter.value.startsWith('@')) return filter;
    const resolved = values.get(filter.value) ?? values.get(filter.value.slice(1));
    if (resolved === undefined || resolved === null) return filter;
    return { ...filter, value: String(resolved) };
  });
}

/**
 * The dashboard-scoped variable bus a widget renderer injects. Dashboard 10/10
 * Phase 2.4: provided per dashboard view (`DashboardViewerComponent`,
 * `PageEditorComponent`), never in root — a root instance kept every
 * variable's last value for the whole session, so a cross-filter set on one
 * dashboard silently narrowed the next dashboard that happened to listen on a
 * variable of the same name.
 */
@Injectable()
export class DashboardVariableBusService {
  private readonly bindings = new Map<string, WidgetCrossFilterBinding>();
  /** Every variable's last-set value — what turns a widget's `@var` filter
   * placeholder into a concrete value at fetch time (see
   * {@link substituteVariableValues}). */
  private readonly currentValues = new Map<string, unknown>();
  private readonly changes = new Subject<ReQueryNotification>();

  register(binding: WidgetCrossFilterBinding): void {
    this.bindings.set(binding.widgetId, binding);
  }

  unregister(widgetId: string): void {
    this.bindings.delete(widgetId);
  }

  /** A widget calls this when its own interaction should set a dashboard
   * variable (e.g. a bar-chart segment click). Records the value, computes
   * the bounded re-query chain, and publishes it on {@link changes$}. */
  emit(variable: string, value: unknown, sourceWidgetId: string): void {
    const event: VariableChangeEvent = { variable, value, sourceWidgetId };
    this.currentValues.set(variable, value);
    const widgetIds = resolveReQueryChain(Array.from(this.bindings.values()), event);
    this.changes.next({ event, widgetIds });
  }

  /** The current value of every variable set since this bus was created.
   * Never cleared — a variable keeps its last-set value, the same way a
   * filter-bar selection persists until the operator changes it again. */
  values(): ReadonlyMap<string, unknown> {
    return this.currentValues;
  }

  /** Every widget renderer subscribes and re-queries when its own id
   * appears in `widgetIds`. */
  changes$(): Observable<ReQueryNotification> {
    return this.changes.asObservable();
  }
}
