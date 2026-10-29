import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ATTOME_CONFIG, ApiService, LangService } from '@attome/base';
import { QueryService, ViewAdminService } from '@attome/xrm/core/query/data';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { MAP_LIBRARY_LOADER, MapViewComponent, pointOf } from './map-view.component';

/** A MapLibre stand-in that records what the component asks of it. */
function fakeLibrary() {
  const maps: FakeMap[] = [];
  class FakeMap {
    readonly options: Record<string, unknown>;
    readonly sources: Record<string, Record<string, unknown>> = {};
    readonly layers: Record<string, unknown>[] = [];
    readonly handlers: Record<string, (event: unknown) => void> = {};
    fitted = false;
    constructor(options: Record<string, unknown>) {
      this.options = options;
      maps.push(this);
    }
    on(event: string, layerOrHandler: unknown, handler?: (event: unknown) => void): void {
      if (event === 'load' && typeof layerOrHandler === 'function') {
        (layerOrHandler as () => void)();
      } else if (typeof layerOrHandler === 'string' && handler) {
        this.handlers[`${event}:${layerOrHandler}`] = handler;
      }
    }
    addSource(id: string, source: Record<string, unknown>): void { this.sources[id] = source; }
    addLayer(layer: Record<string, unknown>): void { this.layers.push(layer); }
    getSource(): undefined { return undefined; }
    jumpTo(): void { this.fitted = true; }
    fitBounds(): void { this.fitted = true; }
    easeTo(): void { /* not used */ }
    remove(): void { /* nothing to free */ }
  }
  class FakeBounds { extend(): this { return this; } }
  return { maps, library: { Map: FakeMap, LngLatBounds: FakeBounds } };
}

describe('pointOf (B15-T2)', () => {
  it('reads a stored point, the lat,lng text, and refuses the rest', () => {
    expect(pointOf({ lat: 24.71, lng: 46.67 })).toEqual({ lat: 24.71, lng: 46.67 });
    expect(pointOf('21.49, 39.19')).toEqual({ lat: 21.49, lng: 39.19 });
    expect(pointOf({ lat: 91, lng: 0 })).toBeNull();
    expect(pointOf('north')).toBeNull();
    expect(pointOf(null)).toBeNull();
  });
});

describe('MapViewComponent (B15-T2)', () => {
  async function create(records: Record<string, unknown>[], total: number) {
    const { maps, library } = fakeLibrary();
    const execute = vi.fn(() => of({
      metadata: {},
      data: { columns: [{ name: 'name', is_visible: true }], records, total, page: 1, page_size: 500, total_pages: 1 },
    }));
    const get = vi.fn(() => of({ items: [{ key: 'maps.attribution', value: 'Example tiles' }] }));
    TestBed.configureTestingModule({
      imports: [MapViewComponent],
      providers: [
        { provide: ViewAdminService, useValue: { listAvailable: () => of([
          { id: 'v1', kind: 'map', view_metadata: { location_field: 'location', label_field: 'name' } },
        ]) } },
        { provide: QueryService, useValue: { execute } },
        { provide: ApiService, useValue: { get } },
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://api.test' } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: () => 'en-US' } },
        { provide: MAP_LIBRARY_LOADER, useValue: () => Promise.resolve(library) },
      ],
    });
    const fixture = TestBed.createComponent(MapViewComponent);
    fixture.componentRef.setInput('entityName', 'account');
    // The view loads, then the map draws (its library and settings are awaited).
    for (let i = 0; i < 3; i++) {
      fixture.detectChanges();
      await new Promise(resolve => setTimeout(resolve));
    }
    fixture.detectChanges();
    return { fixture, maps, execute };
  }

  it('places the records with a location, clustered, on tiles from the server', async () => {
    const { fixture, maps, execute } = await create([
      { id: 'a', name: 'Riyadh office', location: { lat: 24.71, lng: 46.67 } },
      { id: 'b', name: 'Jeddah office', location: '21.49,39.19' },
      { id: 'c', name: 'No address', location: null },
    ], 3);
    expect(execute).toHaveBeenCalledWith(expect.objectContaining({ view_id: 'v1', page_size: 500 }));
    expect(maps.length).toBe(1);
    const map = maps[0];
    const style = map.options['style'] as { sources: { tiles: { tiles: string[]; attribution: string } } };
    // The browser asks the deployment, never the tile server (the page's CSP).
    expect(style.sources.tiles.tiles).toEqual(['http://api.test/api/v1/maps/tiles/{z}/{x}/{y}']);
    expect(style.sources.tiles.attribution).toBe('Example tiles');
    const records = map.sources['records'] as { cluster: boolean; data: { features: unknown[] } };
    expect(records.cluster).toBe(true);
    expect(records.data.features.length).toBe(2);
    expect(map.layers.map(l => l['id'])).toEqual(['clusters', 'points']);
    expect(map.fitted).toBe(true);

    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelectorAll('.mv-list button').length).toBe(2);
    expect(el.textContent).toContain('entityViews.map.withoutLocation');
  });

  it('opens a record from the map and from the list', async () => {
    const { fixture, maps } = await create([{ id: 'a', name: 'Riyadh office', location: { lat: 24.71, lng: 46.67 } }], 1);
    const opened: string[] = [];
    fixture.componentInstance.recordClick.subscribe(id => opened.push(id));
    maps[0].handlers['click:points']({ features: [{ properties: { id: 'a' } }] });
    (fixture.nativeElement as HTMLElement).querySelector<HTMLButtonElement>('.mv-list button')?.click();
    expect(opened).toEqual(['a', 'a']);
  });

  it('says when it shows only the first records', async () => {
    const { fixture } = await create([{ id: 'a', name: 'A', location: { lat: 1, lng: 1 } }], 900);
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('entityViews.map.truncated');
  });
});
