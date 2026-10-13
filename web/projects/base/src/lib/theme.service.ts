import { inject, Injectable, PLATFORM_ID, signal } from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { DOCUMENT } from '@angular/common';
import { ATTOME_CONFIG } from './config';

export interface ColorScheme {
  bg:           string;
  bgAlt:        string;
  textPrimary:  string;
  textSecondary:string;
  primary:      string;
  primaryHover: string;
  border:       string;
  accent:       string;
  accentHover:  string;
  shadow:       string;
  rangeThumb:   string;
  rangeTrack:   string;
  /** Text/icon colour on an `accent` fill — white in light, near-black in dark (the dark accent is light). */
  onAccent:     string;
  /** Errors and destructive actions; readable as text on `bg`/`bgAlt`. */
  danger:       string;
  /** Confirmations (e.g. a form's "Saved" state); readable as text on `bg`/`bgAlt`. */
  success:      string;
}

export interface ColorPalette {
  name:  string;
  light: ColorScheme;
  dark:  ColorScheme;
}

export type ThemeMode = 'light' | 'dark' | 'auto';

/** Runtime check for the one string union this service persists (NGB-F13). */
export function isThemeMode(value: unknown): value is ThemeMode {
  return value === 'light' || value === 'dark' || value === 'auto';
}

/**
 * The token set this service publishes as `--color-*` on `<html>`. OD-7
 * deleted the palette *API* (seven selectable palettes, `setPalette`,
 * `nextPalette`, `getAvailablePalettes`, `currentPalette$`) — it had zero
 * consumers outside this file — so one scheme pair remains.
 */
const SCHEME: ColorPalette = {
  name: 'Default Purple',
  light: { bg:'#f5f6fb', bgAlt:'#ffffff', textPrimary:'#0d1117', textSecondary:'#6b7280', primary:'#374151', primaryHover:'#1f2937', border:'#dde1ef', accent:'#6d28d9', accentHover:'#5b21b6', shadow:'rgba(0,0,0,0.08)', rangeTrack:'#e5e7eb', rangeThumb:'#6d28d9', onAccent:'#ffffff', danger:'#b91c1c', success:'#166534' },
  dark:  { bg:'#0d0f1e', bgAlt:'#141728', textPrimary:'#e8eaf6', textSecondary:'#8b90bf', primary:'#5a5f8a', primaryHover:'#a78bfa', border:'#2e3150', accent:'#a78bfa', accentHover:'#c4b5fd', shadow:'rgba(0,0,0,0.5)', rangeTrack:'#2e3150', rangeThumb:'#a78bfa', onAccent:'#0d0f1e', danger:'#f87171', success:'#4ade80' },
};

/**
 * NGB-4.1 — the theme is one reactivity model: signals for state (`mode()`,
 * `isDark()`); the deprecated Observable/getter accessors were deleted
 * (D-790). `isDark()` is what a template or an `effect` should read: reading it
 * is what makes an effect re-run, which the old `void this.theme.isDarkMode$;`
 * in the login page did not do (NGB-F15).
 */
@Injectable({ providedIn: 'root' })
export class ThemeService {
  private readonly doc        = inject(DOCUMENT);
  private readonly platformId = inject(PLATFORM_ID);
  private readonly config     = inject(ATTOME_CONFIG);

  // Per-portal localStorage key — portals never overwrite each other
  private readonly keys = {
    mode: `${this.config.portalKey ?? 'attome'}-theme-mode`,
  };

  private readonly modeSignal   = signal<ThemeMode>('auto');
  private readonly isDarkSignal = signal(false);

  readonly mode   = this.modeSignal.asReadonly();
  readonly isDark = this.isDarkSignal.asReadonly();

  constructor() {
    if (!isPlatformBrowser(this.platformId)) return;
    this.load();
    this.watchSystemScheme();
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  setMode(mode: ThemeMode): void {
    this.modeSignal.set(mode);
    this.save(this.keys.mode, mode);
    this.apply();
  }

  cycleMode(): void {
    const modes: ThemeMode[] = ['light', 'dark', 'auto'];
    const next = (modes.indexOf(this.modeSignal()) + 1) % modes.length;
    this.setMode(modes[next]);
  }

  /** Back to the OS preference. The palette reset went with the palette API (OD-7). */
  resetTheme(): void { this.setMode('auto'); }

  // ── Private ────────────────────────────────────────────────────────────────

  private load(): void {
    // NGB-F13: with site data blocked (Safari private browsing, a
    // cookie-blocking extension, an embedded webview) the first
    // `localStorage.getItem` throws `SecurityError`; unguarded it escaped the
    // service constructor and took the whole shell down with it. A blocked
    // store is a missing preference, not a fatal condition — the same posture
    // `LangService` already takes for its own storage read.
    const m = this.read(this.keys.mode);
    // NGB-F13/F20: the stored mode was cast to `ThemeMode` unchecked, so any
    // other string (a hand-edited key, a portal's older format) reached
    // `apply()` and fell through the system-scheme branch as if it were
    // `auto`. Validate it instead of casting.
    this.modeSignal.set(isThemeMode(m) ? m : 'auto');
    this.apply();
  }

  /** A storage read that cannot fail the caller — `null` when blocked. */
  private read(key: string): string | null {
    try { return localStorage.getItem(key); } catch { return null; }
  }

  private watchSystemScheme(): void {
    const mq = window.matchMedia?.('(prefers-color-scheme: dark)');
    if (!mq) return;
    mq.addEventListener('change', () => {
      if (this.modeSignal() === 'auto') this.apply();
    });
  }

  private apply(): void {
    const mode = this.modeSignal();
    const isDark =
      mode === 'dark' ? true :
      mode === 'light' ? false :
      (window.matchMedia?.('(prefers-color-scheme: dark)').matches ?? false);

    this.isDarkSignal.set(isDark);

    const colors = SCHEME[isDark ? 'dark' : 'light'];
    const root   = this.doc.documentElement;

    root.style.setProperty('--color-bg',            colors.bg);
    root.style.setProperty('--color-bg-alt',         colors.bgAlt);
    root.style.setProperty('--color-text-primary',   colors.textPrimary);
    root.style.setProperty('--color-text-secondary', colors.textSecondary);
    root.style.setProperty('--color-primary',        colors.primary);
    root.style.setProperty('--color-primary-hover',  colors.primaryHover);
    root.style.setProperty('--color-border',         colors.border);
    root.style.setProperty('--color-accent',         colors.accent);
    root.style.setProperty('--color-accent-hover',   colors.accentHover);
    root.style.setProperty('--color-card-shadow',    colors.shadow);
    root.style.setProperty('--range-track-color',    colors.rangeTrack);
    root.style.setProperty('--range-thumb-color',    colors.rangeThumb);
    root.style.setProperty('--color-on-accent',      colors.onAccent);
    root.style.setProperty('--color-danger',         colors.danger);
    root.style.setProperty('--color-success',        colors.success);

    if (isDark) {
      if (!root.classList.replace('light', 'dark')) root.classList.add('dark');
    } else {
      if (!root.classList.replace('dark', 'light')) root.classList.add('light');
    }
  }

  private save(key: string, value: string): void {
    try { localStorage.setItem(key, value); } catch { /* SSR / private browsing */ }
  }
}
