import { NgComponentOutlet } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, effect, inject, Type, untracked } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { toSignal } from '@angular/core/rxjs-interop';
import { combineLatest } from 'rxjs';

import { EntityListPageComponent } from './pages/entity-list-page.component';
import { MissingFormPageComponent } from './pages/missing-form-page.component';
import { EntityRouteRegistry, resolveEntityUrlPath } from '@attome/xrm/core/entity';

type EntityAction = 'list' | 'form';

// Paths already warned about as ambiguous, so the warning fires once per
// path per session rather than on every change-detection pass.
const warnedAmbiguousPaths = new Set<string>();

// No server round-trip: URL -> logical name is resolved synchronously
// (entity-url.utils.ts). Logical names do NOT all start with 'xrm_' —
// `trd_*` trading entities, prefix-less vertical entities (`account`) and
// three-letter project prefixes (`bmd_*`) exist too — so the canonical URL is
// `/xrm/{module}/{entity}` for `xrm_*` names and `/xrm/entity/{logicalname}`
// for every other name. A non-canonical `/xrm/{prefix}/{entity}` path still
// resolves: `resolveEntityUrlPath` prefers whichever candidate
// (`xrm_{prefix}_{entity}`, then `{prefix}_{entity}`) has a form registered
// in `EntityRouteRegistry`, and falls back to the `xrm_` reading. An invalid
// entity name is not pre-checked here and instead surfaces as
// query/execute's own error response (a hardened, privilege-gated path per
// D-036).
@Component({
  selector:   'attome-metadata-router',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [NgComponentOutlet],
  styleUrls:  ['../../../styles/xrm-form.css'],
  styles: [':host { display: block; width: 100%; height: 100%; position: relative; }'],
  template: `
    @if (resolved(); as r) {
      <ng-container
        [ngComponentOutlet]="r.component"
        [ngComponentOutletInputs]="r.inputs"
      />
    } @else {
      <div class="xf-loading">
        <i class="las la-circle-notch" style="animation:xf-spin .9s linear infinite"></i>
      </div>
    }
  `,
})
export class EntityRouterComponent {
  private readonly route    = inject(ActivatedRoute);
  private readonly registry = inject(EntityRouteRegistry);

  private readonly routeState = toSignal(
    combineLatest([this.route.url, this.route.queryParams]),
    { requireSync: true },
  );

  private readonly resolution = computed(() => {
    const [urlSegments] = this.routeState();
    const parts = urlSegments.map(s => s.path);
    // Everything before the last segment (the 'list'/'form' action keyword)
    // is the entity URL path relative to '/xrm/' ('core/entity/info',
    // 'entity/trd_symbol', …) — this route matches under the 'xrm' parent
    // path (app.routes.ts), which isn't part of `route.url`, so it's
    // prepended back on before resolving to a logical name.
    const urlPath = `xrm/${parts.slice(0, -1).join('/')}`;
    return {
      urlPath,
      ...resolveEntityUrlPath(urlPath, name => this.registry.isRegistered(name)),
    };
  });

  private readonly logicalname = computed(() => this.resolution().logicalname);

  // Side-effecting (triggers `EntityRouteRegistry`'s lazy `import()`, and
  // logs an ambiguous path), so it's a constructor effect rather than folded
  // into `resolved` — a `computed()` must stay pure. `ensureLoaded` itself is
  // idempotent per logicalname, so re-running this for the same entity (any
  // unrelated change detection pass) is a cheap no-op.
  constructor() {
    effect(() => {
      const { urlPath, logicalname, ambiguous } = this.resolution();
      untracked(() => {
        if (ambiguous.length > 0 && !warnedAmbiguousPaths.has(urlPath)) {
          warnedAmbiguousPaths.add(urlPath);
          console.warn(
            `[attome-metadata-router] /${urlPath} matches the registered entities ${ambiguous.join(', ')};`
            + ` opening ${logicalname}. Link to /xrm/entity/<logicalname> for the other.`,
          );
        }
        this.registry.ensureLoaded(logicalname);
      });
    });
  }

  /**
   * `null` while the current entity's override loader (if it has one) is
   * still in flight — the template shows a small spinner instead of
   * dispatching to the generic list (or the missing-form page) and then
   * swapping to the bespoke one a moment later. `registry.isPending`/`registry.get` both read signals
   * internally, so this recomputes correctly once the loader resolves.
   */
  readonly resolved = computed(() => {
    const [urlSegments, queryParams] = this.routeState();
    const parts  = urlSegments.map(s => s.path);
    const action = (parts.at(-1) ?? 'list') as EntityAction;
    const logicalname = this.logicalname();
    const editId = queryParams['id'] as string | undefined ?? null;

    if (this.registry.isPending(logicalname)) return null;

    const override = this.registry.get(logicalname);

    if (action === 'list') {
      return {
        component: (override?.listComponent ?? EntityListPageComponent) as Type<unknown>,
        inputs:    { name: logicalname },
      };
    }
    // No generic form fallback (SYSTEM-CHANGES.md Topic 14,
    // FORMS-IN-CODE-PLAN.md §6 step 2): every entity has its own form in
    // code, so an entity without a registered formComponent gets the explicit
    // "no form registered" page. Lists stay generic.
    return {
      component: (override?.formComponent ?? MissingFormPageComponent) as Type<unknown>,
      inputs:    { name: logicalname, id: editId },
    };
  });
}
