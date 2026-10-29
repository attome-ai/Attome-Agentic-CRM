import { ChangeDetectionStrategy, Component, effect, inject, input, output, signal, untracked } from '@angular/core';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { AvailableView, MapViewMetadata, QueryService, ViewAdminService } from '@attome/xrm/core/query/data';

import { MapPoint, PointsMapComponent } from './points-map.component';

export { MAP_LIBRARY_LOADER } from './points-map.component';
export type { MapLibraryLoader, MapPoint, PointTone } from './points-map.component';

/** The most records one map reads. */
export const MAP_MAX_POINTS = 500;

/** A geolocation value as stored (`{lat, lng}`, A2-T3) or as text
 * (`"lat,lng"`), or `null` when it is neither or out of range. Pure. */
export function pointOf(value: unknown): { lat: number; lng: number } | null {
  let lat: unknown;
  let lng: unknown;
  if (typeof value === 'string') {
    [lat, lng] = value.split(',').map(part => Number(part.trim()));
  } else if (value && typeof value === 'object') {
    lat = (value as Record<string, unknown>)['lat'];
    lng = (value as Record<string, unknown>)['lng'];
  }
  if (typeof lat !== 'number' || typeof lng !== 'number' || !Number.isFinite(lat) || !Number.isFinite(lng)) return null;
  if (Math.abs(lat) > 90 || Math.abs(lng) > 180) return null;
  return { lat, lng };
}

/**
 * `kind = map` (B15-T2): each record of the view's bound query at its
 * geolocation field, on `PointsMapComponent` (tiles through the server,
 * nearby records clustered). The records come from the same
 * `POST /api/v1/query/execute` feed a list uses, so record security is the
 * feed's. The records are also listed under the map, for keyboards and
 * screen readers, and open on click there or on the map.
 */
@Component({
  selector:   'xrm-map-view',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [PointsMapComponent, TranslatePipe],
  template: `
    @if (error(); as message) {
      <p class="mv-error" role="alert">{{ message }}</p>
    }
    @if (loading()) {
      <p class="mv-muted" role="status">{{ 'entityViews.map.loading' | translate }}</p>
    }
    @if (ready()) {
      <xrm-points-map [points]="points()" (pointClick)="recordClick.emit($event)" />
    }
    @if (truncated(); as t) {
      <p class="mv-muted">{{ 'entityViews.map.truncated' | translate: { shown: t.shown, total: t.total } }}</p>
    }
    @if (missing() > 0) {
      <p class="mv-muted">{{ 'entityViews.map.withoutLocation' | translate: { count: missing() } }}</p>
    }
    @if (points().length > 0) {
      <ul class="mv-list" [attr.aria-label]="'entityViews.map.list' | translate">
        @for (p of points(); track p.id) {
          <li><button type="button" class="mv-link" dir="auto" (click)="recordClick.emit(p.id)">{{ p.label }}</button></li>
        }
      </ul>
    }
  `,
  styles: [`
    :host { display: flex; flex-direction: column; gap: 0.5rem; }
    .mv-list { list-style: none; margin: 0; padding: 0; display: flex; flex-wrap: wrap; gap: 0.25rem 0.75rem;
      max-block-size: 10rem; overflow: auto; font-size: 0.8125rem; }
    .mv-link { background: none; border: 0; padding: 0; color: var(--color-primary); cursor: pointer; }
    .mv-muted { color: var(--color-text-secondary); font-size: 0.8125rem; margin: 0; }
    .mv-error { color: var(--color-danger); margin: 0; }
  `],
})
export class MapViewComponent {
  readonly entityName = input.required<string>();
  readonly viewId = input<string | null>(null);
  readonly recordClick = output<string>();

  private readonly querySvc = inject(QueryService);
  private readonly viewSvc = inject(ViewAdminService);
  private readonly lang = inject(LangService);

  readonly loading = signal(false);
  readonly ready = signal(false);
  readonly error = signal<string | null>(null);
  readonly points = signal<MapPoint[]>([]);
  readonly missing = signal(0);
  readonly truncated = signal<{ shown: number; total: number } | null>(null);

  private generation = 0;

  constructor() {
    effect(() => {
      this.entityName();
      this.viewId();
      untracked(() => this.load());
    });
  }

  private fail(message: string): void {
    this.loading.set(false);
    this.error.set(message);
  }

  private load(): void {
    const generation = ++this.generation;
    this.loading.set(true);
    this.ready.set(false);
    this.error.set(null);
    this.viewSvc.listAvailable(this.entityName()).subscribe({
      next: views => {
        const requested = this.viewId();
        const view = requested
          ? views.find(v => v.id === requested && v.kind === 'map')
          : views.find(v => v.kind === 'map');
        if (!view) {
          this.fail(this.lang.translate('entityViews.map.noView'));
          return;
        }
        this.loadPoints(view, generation);
      },
      error: (e: ApiError) => this.fail(e.message),
    });
  }

  private loadPoints(view: AvailableView, generation: number): void {
    const meta = view.view_metadata as unknown as MapViewMetadata;
    if (!meta.location_field) {
      this.fail(this.lang.translate('entityViews.map.noField'));
      return;
    }
    this.querySvc.execute({ view_id: view.id, page: 1, page_size: MAP_MAX_POINTS, include_total: true }).subscribe({
      next: res => {
        if (generation !== this.generation) return;
        const labelField = meta.label_field || res.data.columns.find(c => c.is_visible)?.name;
        const points: MapPoint[] = [];
        let missing = 0;
        for (const record of res.data.records) {
          const at = pointOf(record[meta.location_field]);
          if (!at) {
            missing++;
            continue;
          }
          const id = String(record['id'] ?? '');
          const colour = meta.color_field ? record[meta.color_field] : null;
          points.push({
            id,
            label: labelField ? String(record[labelField] ?? id) : id,
            ...at,
            color: typeof colour === 'string' && colour ? colour : null,
          });
        }
        this.points.set(points);
        this.missing.set(missing);
        const total = res.data.total ?? res.data.records.length;
        this.truncated.set(total > res.data.records.length ? { shown: res.data.records.length, total } : null);
        this.loading.set(false);
        this.ready.set(true);
      },
      error: (e: ApiError) => this.fail(e.message),
    });
  }
}
