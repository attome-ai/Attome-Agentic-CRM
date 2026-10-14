import { ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ApiError, ApiService, Page, TranslatePipe } from '@attome/base';
import { Subject, debounceTime, switchMap } from 'rxjs';

/** The colour tokens the editor shows, in `attome_core::theme_tokens::ThemeTokens` order. */
export const COLOUR_TOKENS = [
  'primary', 'accent', 'surface', 'surface_dark', 'text', 'text_dark',
  'success', 'warning', 'danger', 'info',
] as const;
export type ColourToken = typeof COLOUR_TOKENS[number];

/** `attome_core::theme_tokens::ThemeTokens`: every token optional. */
export interface ThemeTokens extends Partial<Record<ColourToken, string>> {
  font_latin?: string;
  font_arabic?: string;
  arabic_line_height?: number;
  radius_px?: number;
  density?: 'comfortable' | 'compact';
  hide_vendor_name?: boolean;
}

/** `attome_core::theme_store::ThemeRow`. */
export interface ThemeRow {
  id: string;
  scope_kind: string;
  scope_ref: string;
  version: number;
  status: 'draft' | 'published' | 'retired';
  tokens: ThemeTokens;
  created_at: string;
  published_at: string | null;
  row_version: number;
}

/** `attome_core::theme_tokens::ContrastReport`. */
export interface ContrastReport {
  passed: boolean;
  failures: { pair: string; mode: string; ratio: number; required: number }[];
}

/** `attome_core::theme_store::TokenChange`. */
export interface TokenChange {
  field: string;
  before: unknown;
  after: unknown;
}

const HEX = /^#[0-9a-fA-F]{6}$/;

/**
 * Branding (roadmap B13-T9): the deployment's theme. Colour pickers with a
 * live contrast check, a preview in the chosen colours, save as a draft,
 * publish, the versions with what each changes, and roll back. Logical CSS
 * only.
 */
@Component({
  selector:        'xrm-branding',
  standalone:      true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:         [TranslatePipe],
  templateUrl:     './branding.component.html',
  styleUrls:       ['./branding.component.css'],
})
export class BrandingComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly checks = new Subject<ThemeTokens>();

  readonly colourTokens = COLOUR_TOKENS;
  readonly tokens = signal<ThemeTokens>({});
  readonly report = signal<ContrastReport | null>(null);
  readonly versions = signal<ThemeRow[]>([]);
  readonly changes = signal<{ version: number; changes: TokenChange[] } | null>(null);
  readonly error = signal<string | null>(null);
  readonly saved = signal<ThemeRow | null>(null);
  readonly busy = signal(false);
  /** Asset kinds uploaded to the saved draft, for a confirmation. */
  readonly uploaded = signal<string[]>([]);

  /** The deployment-wide versions, newest first. */
  readonly deploymentVersions = computed(() =>
    this.versions().filter(v => v.scope_kind === 'deployment' && v.scope_ref === ''));
  /** Inline styles for the preview card. */
  readonly preview = computed(() => {
    const t = this.tokens();
    return {
      surface: t.surface ?? '#ffffff',
      text: t.text ?? '#1f2937',
      primary: t.primary ?? '#2563eb',
      accent: t.accent ?? '#7c3aed',
      radius: `${t.radius_px ?? 6}px`,
    };
  });

  ngOnInit(): void {
    this.checks.pipe(
      debounceTime(300),
      switchMap(tokens => this.api.post<ContrastReport>('/api/v1/admin/themes/preview-check', { tokens })),
      takeUntilDestroyed(this.destroyRef),
    ).subscribe({
      next: r => this.report.set(r),
      error: (e: ApiError) => this.error.set(e.message),
    });
    this.load();
  }

  load(): void {
    this.api.get<Page<ThemeRow>>('/api/v1/admin/themes', { page: '1', page_size: '100' }).subscribe({
      next: page => {
        this.versions.set(page.items);
        const current = this.deploymentVersions()[0];
        if (current && Object.keys(this.tokens()).length === 0) this.setTokens({ ...current.tokens });
      },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  /** A colour from a picker or the text box beside it; anything not `#RRGGBB` is ignored. */
  setColour(token: ColourToken, value: string): void {
    if (value !== '' && !HEX.test(value)) return;
    const next = { ...this.tokens() };
    if (value === '') delete next[token]; else next[token] = value.toLowerCase();
    this.setTokens(next);
  }

  setRadius(value: string): void {
    const n = Number(value);
    const next = { ...this.tokens() };
    if (value === '' || !Number.isInteger(n) || n < 0 || n > 24) delete next.radius_px; else next.radius_px = n;
    this.setTokens(next);
  }

  setHideVendor(on: boolean): void {
    this.setTokens({ ...this.tokens(), hide_vendor_name: on || undefined });
  }

  private setTokens(tokens: ThemeTokens): void {
    this.tokens.set(tokens);
    this.saved.set(null);
    this.uploaded.set([]);
    this.checks.next(tokens);
  }

  /** Saves the editor's tokens as a new draft version of the deployment theme. */
  saveDraft(): void {
    this.busy.set(true);
    this.api.post<ThemeRow>('/api/v1/admin/themes', { scope_kind: 'deployment', scope_ref: '', tokens: this.tokens() }).subscribe({
      next: row => { this.busy.set(false); this.saved.set(row); this.load(); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  /** Uploads a logo or favicon to the saved draft; the server checks type, size and SVG content. */
  upload(kind: 'logo' | 'favicon', file: File | undefined): void {
    const draft = this.saved();
    if (!draft || !file) return;
    this.busy.set(true);
    this.api.post<unknown>(`/api/v1/admin/themes/${draft.id}/assets?kind=${kind}`, file).subscribe({
      next: () => { this.busy.set(false); this.uploaded.update(kinds => [...kinds.filter(k => k !== kind), kind]); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  publish(row: ThemeRow): void {
    this.busy.set(true);
    this.api.post<unknown>(`/api/v1/admin/themes/${row.id}/publish`, {}, { ifMatch: row.row_version }).subscribe({
      next: () => { this.busy.set(false); this.load(); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  rollback(row: ThemeRow): void {
    this.busy.set(true);
    this.api.post<ThemeRow>('/api/v1/admin/themes/rollback', {
      scope_kind: row.scope_kind, scope_ref: row.scope_ref, version: row.version,
    }).subscribe({
      next: () => { this.busy.set(false); this.load(); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  showChanges(row: ThemeRow): void {
    this.api.get<TokenChange[]>(`/api/v1/admin/themes/${row.id}/diff`).subscribe({
      next: changes => this.changes.set({ version: row.version, changes }),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  /** Loads a version's tokens into the editor. */
  edit(row: ThemeRow): void {
    this.setTokens({ ...row.tokens });
  }

  display(value: unknown): string {
    return value === null || value === undefined ? '—' : String(value);
  }
}
