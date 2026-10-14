import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ThemeService } from './theme.service';
import { ATTOME_CONFIG } from './config';

/**
 * NGB-P.1 / NGB-1.6. `ThemeService.load()` read `localStorage` unguarded and
 * cast the stored mode unchecked: with site data blocked (Safari private
 * browsing, a cookie-blocking extension, an embedded webview) the very first
 * `localStorage.getItem` threw `SecurityError` out of the service
 * constructor, so `/xrm/login` and the whole xrm shell failed to construct.
 * The first case below was written against that defect (`it.fails`), and
 * NGB-1.6 flipped it.
 */
describe('ThemeService', () => {
  function setUp() {
    TestBed.configureTestingModule({
      providers: [{ provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } }],
    });
    return TestBed.inject(ThemeService);
  }

  afterEach(() => {
    vi.restoreAllMocks();
    try { localStorage.clear(); } catch { /* blocked in the case below */ }
  });

  function blockStorage(): void {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new DOMException('The operation is insecure.', 'SecurityError');
    });
  }

  it('B13-T8 lays the published brand over the light scheme only', () => {
    const theme = setUp();
    theme.setMode('light');
    theme.setBrand({ '--color-accent': '#112233', '--evil': '#000000', '--color-primary': 'red' });
    const root = document.documentElement.style;
    expect(root.getPropertyValue('--color-accent')).toBe('#112233');
    expect(root.getPropertyValue('--evil')).toBe('');
    expect(root.getPropertyValue('--color-primary')).not.toBe('red');
    theme.setMode('dark');
    expect(root.getPropertyValue('--color-accent')).not.toBe('#112233');
  });

  it('B13-T8 applies brand fonts in both schemes and removes stale ones', () => {
    const theme = setUp();
    theme.setMode('dark');
    theme.setBrand({
      '--brand-font-arabic': '"Noto Naskh Arabic"',
      '--brand-arabic-line-height': '1.8',
      '--brand-font-latin': '"x"; } body {',
    });
    const root = document.documentElement.style;
    expect(root.getPropertyValue('--brand-font-arabic')).toBe('"Noto Naskh Arabic"');
    expect(root.getPropertyValue('--brand-arabic-line-height')).toBe('1.8');
    expect(root.getPropertyValue('--brand-font-latin')).toBe('');
    theme.setBrand({ '--brand-arabic-line-height': '1.6' });
    expect(root.getPropertyValue('--brand-font-arabic')).toBe('');
    expect(root.getPropertyValue('--brand-arabic-line-height')).toBe('1.6');
    theme.setBrand(null);
    expect(root.getPropertyValue('--brand-arabic-line-height')).toBe('');
  });

  // NGB-P.1, flipped by NGB-1.6: `load()` goes through a guarded read now, so a
  // blocked store leaves the defaults in place instead of throwing out of the
  // constructor.
  it('NGB-F13 ThemeService constructs with storage blocked', () => {
    blockStorage();
    const theme = setUp();
    expect(theme.mode()).toBe('auto');
    expect(theme.isDark()).toBe(false);
  });

  // NGB-1.6 — the stored mode was cast to `ThemeMode`, so any other string (a
  // hand-edited key, an older portal's format) was applied as if it were `auto`.
  it('NGB-F13 ignores a stored mode that is not a ThemeMode', () => {
    localStorage.setItem('attome-theme-mode', 'sepia');
    expect(setUp().mode()).toBe('auto');
  });

  it('restores a stored mode', () => {
    localStorage.setItem('attome-theme-mode', 'dark');
    const theme = setUp();
    expect(theme.mode()).toBe('dark');
    expect(theme.isDark()).toBe(true);
  });

  // NGB-4.1 — one reactivity model: the signal is the state.
  it('exposes the mode as a signal', () => {
    const theme = setUp();
    theme.setMode('dark');
    expect(theme.mode()).toBe('dark');
    expect(theme.isDark()).toBe(true);
  });

  it('namespaces its storage keys by portalKey', () => {
    localStorage.setItem('myportal-theme-mode', 'light');
    TestBed.configureTestingModule({
      providers: [{ provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865', portalKey: 'myportal' } }],
    });
    expect(TestBed.inject(ThemeService).mode()).toBe('light');
  });

  it('cycles light -> dark -> auto', () => {
    const theme = setUp();
    theme.setMode('light');
    theme.cycleMode();
    expect(theme.mode()).toBe('dark');
    theme.cycleMode();
    expect(theme.mode()).toBe('auto');
  });
});
