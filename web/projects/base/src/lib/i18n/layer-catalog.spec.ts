import { EnvironmentInjector, createEnvironmentInjector, runInInjectionContext } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ATTOME_CONFIG } from '../config';
import { LangService } from '../lang.service';
import { provideAttomeI18n } from '../provide';
import { layerCatalogsReady, provideLayerCatalog } from './layer-catalog';

// NGB-5.2a / D-761 — a layer's catalog merges into the one Transloco
// registration: English at once, Arabic with (or after) base's Arabic.
const layerEn = { layerDemo: { title: 'Layer title' } };
const layerAr = { layerDemo: { title: 'عنوان الطبقة' } };

function setUp(loadAr: () => Promise<typeof layerAr> = () => Promise.resolve(layerAr), rootLayer = true) {
  TestBed.configureTestingModule({
    providers: [
      { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
      provideAttomeI18n(),
      ...(rootLayer ? [provideLayerCatalog(layerEn, loadAr)] : []),
    ],
  });
  return TestBed.inject(LangService);
}

/** A lazy route's environment injector, the way the router creates one. */
function mountRoute(loadAr: () => Promise<typeof layerAr>): EnvironmentInjector {
  return createEnvironmentInjector([provideLayerCatalog(layerEn, loadAr)], TestBed.inject(EnvironmentInjector));
}

describe('provideLayerCatalog', () => {
  afterEach(() => localStorage.clear());

  it('resolves a root layer key in English, and in Arabic after a switch', async () => {
    const lang = setUp();
    expect(lang.translate('layerDemo.title')).toBe('Layer title');
    await lang.set('ar');
    expect(lang.translate('layerDemo.title')).toBe('عنوان الطبقة');
    expect(lang.translate('dialog.cancel')).toBe('إلغاء');
  });

  it('never shows a raw key: the switch applies only once the layer has landed', async () => {
    let release!: (c: typeof layerAr) => void;
    const lang = setUp(() => new Promise(r => { release = r; }));
    const switching = lang.set('ar');
    await Promise.resolve();
    expect(lang.current()).toBe('en');
    expect(lang.translate('layerDemo.title')).toBe('Layer title');
    release(layerAr);
    await switching;
    expect(lang.current()).toBe('ar');
    expect(lang.translate('layerDemo.title')).toBe('عنوان الطبقة');
  });

  it('a route-level layer mounted while Arabic is active loads its Arabic, and the guard waits for it', async () => {
    const lang = setUp(undefined, false);
    await lang.set('ar');
    let release!: (c: typeof layerAr) => void;
    const route = mountRoute(() => new Promise(r => { release = r; }));
    expect(lang.translate('layerDemo.title')).toBe('Layer title');

    let passed = false;
    const guard = (runInInjectionContext(route, () => layerCatalogsReady({} as never, {} as never)) as Promise<boolean>)
      .then(v => { passed = v; });
    await Promise.resolve();
    expect(passed).toBe(false);
    release(layerAr);
    await guard;
    expect(passed).toBe(true);
    expect(lang.translate('layerDemo.title')).toBe('عنوان الطبقة');
  });

  it('registers a layer once however many routes mount it', async () => {
    const loadAr = vi.fn(() => Promise.resolve(layerAr));
    const lang = setUp(undefined, false);
    mountRoute(loadAr);
    mountRoute(loadAr);
    await lang.set('ar');
    expect(loadAr).toHaveBeenCalledTimes(1);
  });

  it('a layer whose Arabic fails still switches, rendering that layer in English', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const lang = setUp(() => Promise.reject(new Error('chunk')));
    await lang.set('ar');
    expect(lang.current()).toBe('ar');
    expect(lang.translate('layerDemo.title')).toBe('Layer title');
    expect(error).toHaveBeenCalled();
    error.mockRestore();
  });

  it('a layer whose English is a loader holds its route until the English lands, and loads it once', async () => {
    setUp(undefined, false);
    let release!: (c: typeof layerEn) => void;
    const loadEn = vi.fn(() => new Promise<typeof layerEn>(r => { release = r; }));
    const lazyLayer = () => createEnvironmentInjector(
      [provideLayerCatalog(loadEn, () => Promise.resolve(layerAr))],
      TestBed.inject(EnvironmentInjector),
    );
    const route = lazyLayer();
    lazyLayer();
    const lang = TestBed.inject(LangService);

    let passed = false;
    const guard = (runInInjectionContext(route, () => layerCatalogsReady({} as never, {} as never)) as Promise<boolean>)
      .then(v => { passed = v; });
    await Promise.resolve();
    expect(passed).toBe(false);
    release(layerEn);
    await guard;
    expect(passed).toBe(true);
    expect(lang.translate('layerDemo.title')).toBe('Layer title');
    expect(loadEn).toHaveBeenCalledTimes(1);
  });
});
