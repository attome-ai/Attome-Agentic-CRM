import { Injectable, Type, signal } from '@angular/core';
import type { Observable } from 'rxjs';

/**
 * A bulk action offered in the list's selection toolbar, in addition to (or
 * instead of) the stock Delete.
 *
 * `isVisible`/`isEnabled` are deliberately separate. An action that does not
 * apply to *any* selected row is hidden; one that applies to some but not all
 * is shown *disabled*, so a mixed selection surfaces the ambiguity instead of
 * the toolbar silently guessing which half of the selection the operator
 * meant. Both receive the raw row data of the selected records.
 */
export interface SelectionAction {
  /** Stable identity for `@for` tracking. */
  key:         string;
  /** i18n key resolved through `TranslatePipe`. */
  labelKey:    string;
  /** Maps to the `btn-*` class; defaults to `secondary`. */
  style?:      'primary' | 'secondary' | 'danger';
  /** i18n key for a `confirm()` prompt, interpolated with `{count}`. */
  confirmKey?: string;
  isVisible?(rows: Record<string, unknown>[]): boolean;
  isEnabled?(rows: Record<string, unknown>[]): boolean;
  /** Runs against one record. The list fans out over the selection. */
  run(id: string): Observable<unknown>;
}

/**
 * Draws one list column's cells for an entity instead of the stock text cell,
 * keyed by the column's name (a query output column). The component must
 * declare a `row` input; the list binds the row's full record data to it —
 * every column the view's query returned, hidden ones included, so a
 * renderer can read helper columns the view keeps out of sight. A column the
 * current view does not return simply renders nothing extra.
 */
export type ListCellRenderers = Readonly<Record<string, Type<unknown>>>;

export interface EntityRouteOverride {
  listComponent?: Type<unknown>;
  /** Per-column cell renderers for the generic list (see `ListCellRenderers`). */
  cellRenderers?: ListCellRenderers;
  formComponent?: Type<unknown>;
  /** Extra bulk actions for this entity's selection toolbar. */
  selectionActions?: SelectionAction[];
  /**
   * Removes the stock "Delete selected" button. For an entity whose delete
   * needs side effects the generic soft delete does not perform, hiding it
   * and supplying a `selectionActions` replacement is the only way to keep
   * the weaker path from being reachable.
   */
  hideDeleteAction?: boolean;
}

/** Loads the module that registers one or more entities' overrides. Resolves
 * once `register(...)` has actually been called against the registry passed
 * in — the caller doesn't call it directly. */
export type EntityOverrideLoader = (registry: EntityRouteRegistry) => Promise<void>;

/**
 * Registry for custom entity page overrides — and, as of this file's most
 * recent change (bundle-size: see `chunk-budget.mjs`), for the *lazy
 * loaders* that populate it.
 *
 * Register by logical name (e.g. 'user_account') to replace the
 * default list or form page with a custom component:
 *
 *   inject(EntityRouteRegistry).register('user_account', {
 *     listComponent: CustomUserListComponent,
 *   });
 *
 * With ~30 registered entities now spanning every xrm module, eagerly
 * importing every module's override components at app-shell bootstrap (the
 * previous design: each module's `provide*EntityForms()` statically
 * imported and composed in `xrm-shell.routes.ts`'s `providers:` array) blew
 * past the 260KB lazy-chunk cap — every module's registration, and therefore
 * every module's bespoke form components, landed in one shared chunk merged
 * with `xrm-shell.routes.ts` itself. `registerLoader` instead lets the app's
 * composition root (`src/app/attome-metadata-form-loaders.ts`) register a lazy
 * `import()` per logicalname, deferred until `ensureLoaded` is actually
 * called for that logicalname — from `EntityRouterComponent`, once, when
 * that entity is first routed to.
 *
 * `overridesSignal`/`pendingSignal` are real Angular signals (not plain
 * fields) specifically so a *late* registration — one that lands after
 * `EntityRouterComponent`'s `resolved` computed has already run once for
 * this navigation — retroactively triggers a recompute instead of leaving
 * the generic dispatcher rendered until the next unrelated change detection.
 * `get()`/`isPending()` read those signals, so anything computed from them
 * (namely `resolved`) is correctly reactive to a loader resolving.
 */
@Injectable({ providedIn: 'root' })
export class EntityRouteRegistry {
  private readonly overridesSignal = signal<ReadonlyMap<string, EntityRouteOverride>>(new Map());
  private readonly loaders = new Map<string, EntityOverrideLoader>();
  private readonly pendingSignal = signal<ReadonlySet<string>>(new Set());
  private readonly triggeredLoaders = new Set<string>();

  register(logicalname: string, override: EntityRouteOverride): void {
    this.overridesSignal.update(overrides => {
      const next = new Map(overrides);
      next.set(logicalname, { ...next.get(logicalname), ...override });
      return next;
    });
  }

  get(logicalname: string): EntityRouteOverride | null {
    return this.overridesSignal().get(logicalname) ?? null;
  }

  /**
   * Declares (but does not run) the lazy loader for `logicalname`'s override.
   * Called once per logicalname, up front, by the app's composition root —
   * cheap, since it's just populating a `Map<string, () => Promise<...>>`,
   * no `import()` happens until `ensureLoaded` actually triggers this loader.
   */
  registerLoader(logicalname: string, loader: EntityOverrideLoader): void {
    this.loaders.set(logicalname, loader);
  }

  /**
   * True when `logicalname` has a declared loader or a registered override —
   * the "this entity exists in code" test `EntityRouterComponent` uses to
   * pick between a URL's candidate logical names (`resolveEntityUrlPath`).
   * Reads the overrides signal, so a `computed()` calling it is reactive.
   */
  isRegistered(logicalname: string): boolean {
    return this.loaders.has(logicalname) || this.overridesSignal().has(logicalname);
  }

  /**
   * Triggers `logicalname`'s loader on first call; a no-op on every call
   * after (whether or not a loader was registered for it — an entity with no
   * bespoke override still only needs this checked once). Safe to call on
   * every route resolution, including ones that re-resolve the same entity.
   */
  ensureLoaded(logicalname: string): void {
    if (this.triggeredLoaders.has(logicalname)) return;
    this.triggeredLoaders.add(logicalname);
    const loader = this.loaders.get(logicalname);
    if (!loader) return;

    this.pendingSignal.update(pending => new Set(pending).add(logicalname));
    void loader(this).finally(() => {
      this.pendingSignal.update(pending => {
        const next = new Set(pending);
        next.delete(logicalname);
        return next;
      });
    });
  }

  /** True while `logicalname`'s loader (if any) is still in flight — the
   * signal `EntityRouterComponent.resolved` reads to hold off on the generic
   * fallback until a registered override has had its chance to load. */
  isPending(logicalname: string): boolean {
    return this.pendingSignal().has(logicalname);
  }
}
