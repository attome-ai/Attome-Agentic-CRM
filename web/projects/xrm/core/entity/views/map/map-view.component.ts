import {
  ChangeDetectionStrategy, Component, DestroyRef, ElementRef, InjectionToken, effect, inject, input, output,
  signal, untracked, viewChild,
} from '@angular/core';
import { DOCUMENT } from '@angular/common';
import { ApiError, ApiService, LangService, TranslatePipe } from '@attome/base';
import { AvailableView, MapViewMetadata, QueryService, ViewAdminService } from '@attome/xrm/core/query/data';
import type * as MapLibre from 'maplibre-gl';

/** The most records one map reads. */
export const MAP_MAX_POINTS = 500;
/** B15-T2: the defaults of the `maps.tile_url` and `maps.attribution` settings. */
const DEFAULT_TILES = 'https://tile.openstreetmap.org/{z}/{x}/{y}.png';
const DEFAULT_ATTRIBUTION = '© OpenStreetMap contributors';

/** Loads MapLibre — its own lazy chunk, fetched the first time a map is shown. */
export type MapLibraryLoader = () => Promise<typeof MapLibre>;
export const MAP_LIBRARY_LOADER = new InjectionToken<MapLibraryLoader>('MAP_LIBRARY_LOADER', {
  providedIn: 'root',
  factory: () => () => import('maplibre-gl'),
});

/** A point the map can place. */
export interface MapPoint { id: string; label: string; lat: number; lng: number; color: string | null }

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
 * geolocation field, over raster tiles from the `maps.tile_url` setting
 * (OpenStreetMap's by default, or the customer's own tile server), with
 * nearby records clustered. The records come from the same
 * `POST /api/v1/query/execute` feed a list uses, so record security is the
 * feed's. The records are also listed under the map, for keyboards and
 * screen readers, and open on click there or on the map.
 */
@Component({
  selector:   'xrm-map-view',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [TranslatePipe],
  template: `
    @if (error(); as message) {
      <p class="mv-error" role="alert">{{ message }}</p>
    }
    @if (loading()) {
      <p class="mv-muted" role="status">{{ 'entityViews.map.loading' | translate }}</p>
    }
    <div #canvas class="mv-canvas" [attr.aria-label]="'entityViews.map.label' | translate" role="region"></div>
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
    .mv-canvas { block-size: 28rem; inline-size: 100%; border: 1px solid var(--color-border); border-radius: 6px; }
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

  private readonly api = inject(ApiService);
  private readonly querySvc = inject(QueryService);
  private readonly viewSvc = inject(ViewAdminService);
  private readonly lang = inject(LangService);
  private readonly loadLibrary = inject(MAP_LIBRARY_LOADER);
  private readonly document = inject(DOCUMENT);
  private readonly host = inject(ElementRef<HTMLElement>);
  private readonly canvas = viewChild.required<ElementRef<HTMLElement>>('canvas');

  readonly loading = signal(false);
  readonly error = signal<string | null>(null);
  readonly points = signal<MapPoint[]>([]);
  readonly missing = signal(0);
  readonly truncated = signal<{ shown: number; total: number } | null>(null);

  private map: MapLibre.Map | null = null;
  private generation = 0;

  constructor() {
    effect(() => {
      this.entityName();
      this.viewId();
      untracked(() => this.load());
    });
    inject(DestroyRef).onDestroy(() => {
      this.generation++;
      this.map?.remove();
      this.map = null;
    });
  }

  private fail(message: string): void {
    this.loading.set(false);
    this.error.set(message);
  }

  private load(): void {
    const generation = ++this.generation;
    this.loading.set(true);
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
        void this.draw(points, generation);
      },
      error: (e: ApiError) => this.fail(e.message),
    });
  }

  /** The tile settings, as the caller resolves them; the defaults on failure. */
  private async tiles(): Promise<{ url: string; attribution: string }> {
    try {
      const settings = await new Promise<{ items: { key: string; value: unknown }[] }>((resolve, reject) =>
        this.api.get<{ items: { key: string; value: unknown }[] }>('/api/v1/settings/me').subscribe({ next: resolve, error: reject }));
      const value = (key: string) => settings.items.find(i => i.key === key)?.value;
      const url = value('maps.tile_url');
      const attribution = value('maps.attribution');
      return {
        url: typeof url === 'string' && url ? url : DEFAULT_TILES,
        attribution: typeof attribution === 'string' ? attribution : DEFAULT_ATTRIBUTION,
      };
    } catch {
      return { url: DEFAULT_TILES, attribution: DEFAULT_ATTRIBUTION };
    }
  }

  /** MapLibre's stylesheet, once per page (an app asset, B15-T2). */
  private ensureStylesheet(): void {
    if (this.document.querySelector('link[data-maplibre]')) return;
    const link = this.document.createElement('link');
    link.rel = 'stylesheet';
    link.href = 'maplibre/maplibre-gl.css';
    link.setAttribute('data-maplibre', '');
    this.document.head.appendChild(link);
  }

  /** The theme's colour for markers: canvas paint needs a value, not a variable. */
  private themeColour(name: string): string {
    const style = getComputedStyle(this.host.nativeElement);
    return style.getPropertyValue(name).trim() || style.color;
  }

  private async draw(points: MapPoint[], generation: number): Promise<void> {
    let lib: typeof MapLibre;
    let tiles: { url: string; attribution: string };
    try {
      [lib, tiles] = await Promise.all([this.loadLibrary(), this.tiles()]);
    } catch {
      if (generation === this.generation) this.fail(this.lang.translate('entityViews.map.loadFailed'));
      return;
    }
    if (generation !== this.generation) return;
    this.ensureStylesheet();
    this.map?.remove();
    const primary = this.themeColour('--color-primary');
    const surface = this.themeColour('--color-surface');
    const map = new lib.Map({
      container: this.canvas().nativeElement,
      style: {
        version: 8,
        sources: {
          tiles: { type: 'raster', tiles: [tiles.url], tileSize: 256, attribution: tiles.attribution },
        },
        layers: [{ id: 'tiles', type: 'raster', source: 'tiles' }],
      },
      center: [0, 20],
      zoom: 1,
      attributionControl: { compact: true },
    });
    this.map = map;
    map.on('load', () => {
      map.addSource('records', {
        type: 'geojson',
        cluster: true,
        clusterRadius: 50,
        data: {
          type: 'FeatureCollection',
          features: points.map(p => ({
            type: 'Feature' as const,
            properties: { id: p.id, label: p.label, color: p.color ?? primary },
            geometry: { type: 'Point' as const, coordinates: [p.lng, p.lat] },
          })),
        },
      });
      map.addLayer({
        id: 'clusters', type: 'circle', source: 'records', filter: ['has', 'point_count'],
        paint: {
          'circle-color': primary, 'circle-opacity': 0.75,
          'circle-radius': ['step', ['get', 'point_count'], 14, 10, 20, 50, 28],
          'circle-stroke-width': 2, 'circle-stroke-color': surface,
        },
      });
      map.addLayer({
        id: 'points', type: 'circle', source: 'records', filter: ['!', ['has', 'point_count']],
        paint: {
          'circle-color': ['get', 'color'], 'circle-radius': 7,
          'circle-stroke-width': 2, 'circle-stroke-color': surface,
        },
      });
      map.on('click', 'points', event => {
        const id = event.features?.[0]?.properties?.['id'];
        if (typeof id === 'string') this.recordClick.emit(id);
      });
      map.on('click', 'clusters', event => {
        const feature = event.features?.[0];
        const clusterId = feature?.properties?.['cluster_id'];
        const geometry = feature?.geometry;
        const source = map.getSource('records') as MapLibre.GeoJSONSource | undefined;
        if (typeof clusterId !== 'number' || !source || !geometry || geometry.type !== 'Point') return;
        const center = geometry.coordinates as [number, number];
        void source.getClusterExpansionZoom(clusterId).then(zoom => map.easeTo({ center, zoom }));
      });
      this.fit(lib, map, points);
      this.loading.set(false);
    });
  }

  private fit(lib: typeof MapLibre, map: MapLibre.Map, points: MapPoint[]): void {
    if (points.length === 0) return;
    if (points.length === 1) {
      map.jumpTo({ center: [points[0].lng, points[0].lat], zoom: 12 });
      return;
    }
    const bounds = new lib.LngLatBounds();
    for (const p of points) bounds.extend([p.lng, p.lat]);
    map.fitBounds(bounds, { padding: 40, maxZoom: 14, animate: false });
  }
}
