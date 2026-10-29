import {
  ChangeDetectionStrategy, Component, DestroyRef, ElementRef, InjectionToken, effect, inject, input, output,
  signal, untracked, viewChild,
} from '@angular/core';
import { DOCUMENT } from '@angular/common';
import { ATTOME_CONFIG, ApiService, TranslatePipe } from '@attome/base';
import type * as MapLibre from 'maplibre-gl';

/** B15-T2: the default of the `maps.attribution` setting. */
const DEFAULT_ATTRIBUTION = '© OpenStreetMap contributors';
/** Where the app serves MapLibre (`angular.json` assets): its module, its
 * worker beside it and its stylesheet, all from the deployment, which the
 * page's CSP requires (`script-src 'self'`; the worker is found next to the
 * module). Not bundled: at about a megabyte it would be the largest chunk. */
const MAPLIBRE_ASSETS = 'maplibre/';

/** Loads MapLibre the first time a map is shown. */
export type MapLibraryLoader = () => Promise<typeof MapLibre>;
export const MAP_LIBRARY_LOADER = new InjectionToken<MapLibraryLoader>('MAP_LIBRARY_LOADER', {
  providedIn: 'root',
  factory: () => {
    const document = inject(DOCUMENT);
    return () => {
      const url = new URL(`${MAPLIBRE_ASSETS}maplibre-gl.mjs`, document.baseURI).href;
      return import(/* @vite-ignore */ url) as Promise<typeof MapLibre>;
    };
  },
});

/** The theme colour a point is drawn in: a `--color-<tone>` variable. */
export type PointTone = 'primary' | 'success' | 'warning' | 'danger' | 'muted';

/** A point the map can place. */
export interface MapPoint {
  id: string;
  label: string;
  lat: number;
  lng: number;
  /** A colour the record itself names (its colour field), else the tone's. */
  color?: string | null;
  tone?: PointTone;
}

/**
 * B15-T2 / I3-T2: points on a map over raster tiles the server fetches
 * (`GET /api/v1/maps/tiles/...`, so the browser talks only to the
 * deployment), nearby points clustered (a click zooms in), a point's click
 * emitted. New `points` redraw the same map in place, so live updates do not
 * reset the view. The map view and the dispatch board share it.
 */
@Component({
  selector:   'xrm-points-map',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [TranslatePipe],
  template: `
    @if (failed()) {
      <p class="pm-error" role="alert">{{ 'entityViews.map.loadFailed' | translate }}</p>
    }
    <div #canvas class="pm-canvas" role="region" [attr.aria-label]="label() | translate"></div>
  `,
  styles: [`
    :host { display: block; }
    .pm-canvas { block-size: 28rem; inline-size: 100%; border: 1px solid var(--color-border); border-radius: 6px; }
    .pm-error { color: var(--color-danger); margin: 0; }
  `],
})
export class PointsMapComponent {
  readonly points = input.required<MapPoint[]>();
  /** The catalogue key naming the map for screen readers. */
  readonly label = input('entityViews.map.label');
  readonly pointClick = output<string>();

  private readonly api = inject(ApiService);
  private readonly config = inject(ATTOME_CONFIG);
  private readonly loadLibrary = inject(MAP_LIBRARY_LOADER);
  private readonly document = inject(DOCUMENT);
  private readonly host = inject(ElementRef<HTMLElement>);
  private readonly canvas = viewChild.required<ElementRef<HTMLElement>>('canvas');

  readonly failed = signal(false);
  private map: MapLibre.Map | null = null;
  private loaded = false;
  private drawn = false;
  private destroyed = false;

  constructor() {
    effect(() => {
      const points = this.points();
      untracked(() => void this.show(points));
    });
    inject(DestroyRef).onDestroy(() => {
      this.destroyed = true;
      this.map?.remove();
      this.map = null;
    });
  }

  /** The tiles: the server's tile route, and the credit the
   * `maps.attribution` setting gives (its default on failure). */
  private async tiles(): Promise<{ url: string; attribution: string }> {
    const url = `${this.config.apiUrl}/api/v1/maps/tiles/{z}/{x}/{y}`;
    try {
      const settings = await new Promise<{ items: { key: string; value: unknown }[] }>((resolve, reject) =>
        this.api.get<{ items: { key: string; value: unknown }[] }>('/api/v1/settings/me').subscribe({ next: resolve, error: reject }));
      const attribution = settings.items.find(i => i.key === 'maps.attribution')?.value;
      return { url, attribution: typeof attribution === 'string' ? attribution : DEFAULT_ATTRIBUTION };
    } catch {
      return { url, attribution: DEFAULT_ATTRIBUTION };
    }
  }

  /** MapLibre's stylesheet, once per page. */
  private ensureStylesheet(): void {
    if (this.document.querySelector('link[data-maplibre]')) return;
    const link = this.document.createElement('link');
    link.rel = 'stylesheet';
    link.href = `${MAPLIBRE_ASSETS}maplibre-gl.css`;
    link.setAttribute('data-maplibre', '');
    this.document.head.appendChild(link);
  }

  /** The theme's colour: canvas paint needs a value, not a variable. */
  private themeColour(name: string): string {
    const style = getComputedStyle(this.host.nativeElement);
    return style.getPropertyValue(name).trim() || style.color;
  }

  private features(points: MapPoint[]) {
    return {
      type: 'FeatureCollection' as const,
      features: points.map(p => ({
        type: 'Feature' as const,
        properties: { id: p.id, label: p.label, color: p.color ?? this.themeColour(`--color-${p.tone ?? 'primary'}`) },
        geometry: { type: 'Point' as const, coordinates: [p.lng, p.lat] },
      })),
    };
  }

  private async show(points: MapPoint[]): Promise<void> {
    if (this.map && this.loaded) {
      const source = this.map.getSource('records') as MapLibre.GeoJSONSource | undefined;
      source?.setData(this.features(points));
      return;
    }
    if (this.drawn) return;
    this.drawn = true;
    let lib: typeof MapLibre;
    let tiles: { url: string; attribution: string };
    try {
      [lib, tiles] = await Promise.all([this.loadLibrary(), this.tiles()]);
    } catch {
      this.failed.set(true);
      return;
    }
    if (this.destroyed) return;
    this.ensureStylesheet();
    const surface = this.themeColour('--color-surface');
    const primary = this.themeColour('--color-primary');
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
      // The tile route needs the session cookie, also when the API is
      // another origin (local development).
      transformRequest: url => ({ url, credentials: 'include' }),
    });
    this.map = map;
    map.on('load', () => {
      const current = this.points();
      map.addSource('records', { type: 'geojson', cluster: true, clusterRadius: 50, data: this.features(current) });
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
        if (typeof id === 'string') this.pointClick.emit(id);
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
      this.loaded = true;
      this.fit(lib, map, current);
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
