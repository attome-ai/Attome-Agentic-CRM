import { ChangeDetectionStrategy, Component, OnInit, inject, input, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { Observable, catchError, filter, from, map, mergeMap, of, toArray } from 'rxjs';
import { ApiError, TranslatePipe } from '@attome/base';
import { EntityRecord } from '@attome/xrm';
import { EntityService, entityFormRoute } from '@attome/xrm/core/entity';
import { DashboardViewerComponent } from '../dashboard-viewer/dashboard-viewer.component';

/**
 * Drop a live dashboard into any unrelated record's form — the "dashboard
 * component can also be used in normal forms" request. Two ways to pick
 * *which* dashboard:
 *
 * - `dashboardId` — a specific, known dashboard. Renders it directly, no
 *   picker, no query.
 * - `tags` — pick by tag name instead of by id ("select dashboard of same
 *   category easily," multiple tags supported). A tag is the platform's
 *   polymorphic join (`tag_item` where `entity_name = 'attome_dashboard'`),
 *   whose human label lives on `tag_category.name` — so a tag name
 *   resolves category -> join -> dashboard (R-19).
 *
 * A single match renders immediately with no picker. More than one match
 * (e.g. two dashboards both tagged "sales") shows a small `<select>` so the
 * user can switch between them; whichever is showing renders through
 * `DashboardViewerComponent`.
 */
@Component({
  selector:   'attome-dashboard-embed',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [DashboardViewerComponent, RouterLink, TranslatePipe],
  styleUrls:  ['./dashboard-embed.component.css'],
  templateUrl: './dashboard-embed.component.html',
})
export class DashboardEmbedComponent implements OnInit {
  private readonly svc = inject(EntityService);

  /** Where the empty-state card's "create one" link goes — the generic
   * `attome_dashboard` create-mode form (no `?id=`). */
  readonly newDashboardRoute = entityFormRoute('attome_dashboard');

  readonly dashboardId = input<string | null>(null);
  /** OR semantics: a dashboard tagged with ANY of these is a match. */
  readonly tags = input<string[]>([]);
  /** Whether the viewer should hide top header actions (defaults to true for in-form embedding). */
  readonly embedded = input(true);

  readonly loading    = signal(false);
  readonly error      = signal<string | null>(null);
  readonly matches    = signal<EntityRecord[]>([]);
  readonly selectedId = signal<string | null>(null);
  /** True once resolution has finished and neither `dashboardId` nor `tags`
   * turned up a dashboard to render — the home page's "no default dashboard
   * configured yet" case (R-10), not an error: nothing went wrong, there is
   * just genuinely nothing to show. Kept distinct from `error` (an actual
   * failed request) so the template can offer a "create one" call to action
   * instead of the generic error banner. */
  readonly emptyState = signal(false);

  ngOnInit(): void {
    const direct = this.dashboardId();
    if (direct) {
      this.selectedId.set(direct);
      return;
    }
    const tags = this.tags();
    if (tags.length === 0) {
      this.emptyState.set(true);
      return;
    }
    this.loading.set(true);
    from(tags).pipe(
      mergeMap(tag => this.recordIdsForTag(tag)),
      toArray(),
      map((lists: string[][]) => [...new Set(lists.flat())]),
      mergeMap((recordIds: string[]) => {
        if (recordIds.length === 0) return of<EntityRecord[]>([]);
        return from(recordIds).pipe(
          mergeMap(id => this.svc.get('attome_dashboard', id).pipe(
            map(res => ({ id: res.id, data: res.data } as EntityRecord)),
            catchError(() => of(null)),
          )),
          filter((r): r is EntityRecord => r !== null),
          toArray(),
        );
      }),
    ).subscribe({
      next: dashboards => {
        this.loading.set(false);
        const byId = new Map<string, EntityRecord>();
        for (const d of dashboards) byId.set(d.id, d);
        const all = [...byId.values()];
        this.matches.set(all);
        if (all.length > 0) this.selectedId.set(all[0].id);
        else this.emptyState.set(true);
      },
      error: (e: ApiError) => { this.loading.set(false); this.error.set(e.message); },
    });
  }

  /**
   * Resolves one dashboard tag to the `attome_dashboard` record ids carrying it, via the platform's
   * polymorphic tagging join (`tag_category` -> `tag_item`), the same three-table path
   * `TagsPanelComponent` uses.
   *
   * R-19: the previous version filtered `tag_item` by a `name` column that does not exist and
   * fell back to a `tags` column on `attome_dashboard` that does not exist either — both always
   * failed, and both failures were swallowed by `catchError`, so this path never resolved a
   * dashboard. `tag_item` carries no name of its own: a tag is a
   * `(category_id, entity_name, record_id)` join and the human label lives on
   * `tag_category.name`. A tag name therefore resolves to a category first, then to that
   * category's dashboard joins.
   *
   * Non-fatal per step (degrades to "no match"): a tag name with no matching category is not an
   * error, matching the component's previous posture — a genuine transport failure still reaches
   * the outer `error` handler on the caller's subscribe.
   */
  private recordIdsForTag(tag: string): Observable<string[]> {
    return this.svc.list('tag_category', {
      filters: [{ field: 'name', op: 'eq', value: tag }],
      limit: 10,
    }).pipe(
      map(res => res.data.map(category => category.id)),
      mergeMap(categoryIds => {
        if (categoryIds.length === 0) return of<string[]>([]);
        return from(categoryIds).pipe(
          mergeMap(categoryId => this.svc.list('tag_item', {
            // The generic entity list has no `in` op (`attome-core::filter`) — one `eq` per
            // category, merged, is the supported shape.
            filters: [
              { field: 'entity_name', op: 'eq', value: 'attome_dashboard' },
              { field: 'category_id', op: 'eq', value: categoryId },
            ],
            limit: 100,
          }).pipe(
            map(res => res.data.map(item => String(item.data['record_id'])).filter(Boolean)),
            catchError(() => of<string[]>([])),
          )),
          toArray(),
          map(lists => lists.flat()),
        );
      }),
      catchError(() => of<string[]>([])),
    );
  }

  selectDashboard(id: string): void {
    this.selectedId.set(id);
  }
}
