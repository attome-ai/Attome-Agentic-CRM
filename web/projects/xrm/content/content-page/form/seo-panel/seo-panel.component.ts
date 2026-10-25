import {
  ChangeDetectionStrategy, Component, OnInit, inject, input, output, signal,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, TranslatePipe } from '@attome/base';

import { PageSeo, SeoService } from '../../../seo/seo.service';
import {
  DESCRIPTION_BAND, LengthState, TITLE_BAND, clip, displayLength, isArabic, lengthState,
} from '../../../seo/seo-text';
import { SeoFindingsComponent } from '../../../seo/seo-findings.component';

/**
 * E13-T12: a content page's search settings with a live search-result and
 * sharing-card preview, length counters (titles 30–60, descriptions 70–160
 * display characters), the page audit and its findings. Arabic pages preview
 * right to left. Saves with the settings' row version as `If-Match`.
 */
@Component({
  selector: 'attome-seo-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe, SeoFindingsComponent],
  template: `
    <section class="seo" [attr.dir]="rtl() ? 'rtl' : 'ltr'" data-testid="seo-panel">
      <h4>{{ 'e13.panelTitle' | translate }}</h4>
      @if (error(); as message) { <p class="seo-error" role="alert">{{ message }}</p> }

      <label class="seo-field">
        <span>{{ 'e13.title' | translate }}</span>
        <input type="text" maxlength="200" [(ngModel)]="title" name="seoTitle" />
        <span class="seo-count" [attr.data-state]="titleState()" data-testid="title-count">
          {{ length(title) }} · {{ ('e13.length.' + titleState()) | translate }}
        </span>
      </label>
      <label class="seo-field">
        <span>{{ 'e13.description' | translate }}</span>
        <textarea rows="3" maxlength="400" [(ngModel)]="description" name="seoDescription"></textarea>
        <span class="seo-count" [attr.data-state]="descriptionState()" data-testid="description-count">
          {{ length(description) }} · {{ ('e13.length.' + descriptionState()) | translate }}
        </span>
      </label>
      <label class="seo-field">
        <span>{{ 'e13.canonical' | translate }}</span>
        <input type="url" [(ngModel)]="canonical" name="seoCanonical" dir="ltr" />
      </label>
      <label class="seo-check">
        <input type="checkbox" [(ngModel)]="noindex" name="seoNoindex" />
        {{ 'e13.noindex' | translate }}
      </label>
      <label class="seo-check">
        <input type="checkbox" [(ngModel)]="nofollow" name="seoNofollow" />
        {{ 'e13.nofollow' | translate }}
      </label>
      <label class="seo-field">
        <span>{{ 'e13.ogTitle' | translate }}</span>
        <input type="text" maxlength="200" [(ngModel)]="ogTitle" name="seoOgTitle" />
      </label>
      <label class="seo-field">
        <span>{{ 'e13.ogDescription' | translate }}</span>
        <textarea rows="2" maxlength="400" [(ngModel)]="ogDescription" name="seoOgDescription"></textarea>
      </label>

      <h5>{{ 'e13.previewSearch' | translate }}</h5>
      <div class="seo-serp" data-testid="serp-preview">
        <div class="seo-serp-title">{{ clip(title || pageTitle(), 60) }}</div>
        <div class="seo-serp-url" dir="ltr">{{ canonical || pageUrl() }}</div>
        <div class="seo-serp-desc">{{ clip(description, 160) }}</div>
      </div>
      <h5>{{ 'e13.previewShare' | translate }}</h5>
      <div class="seo-card" data-testid="share-preview">
        <div class="seo-card-title">{{ clip(ogTitle || title || pageTitle(), 70) }}</div>
        <div class="seo-card-desc">{{ clip(ogDescription || description, 200) }}</div>
      </div>

      <div class="seo-actions">
        <button type="button" class="btn-primary" (click)="save()" [disabled]="saving() || rowVersion() === null">
          {{ (saving() ? 'e13.saving' : 'e13.save') | translate }}
        </button>
        <button type="button" class="btn-ghost" (click)="runAudit()" [disabled]="auditing()">
          {{ 'e13.runAudit' | translate }}
        </button>
        @if (saved()) { <span role="status">{{ 'e13.saved' | translate }}</span> }
        @if (score() !== null) {
          <span class="seo-score" data-testid="seo-score">{{ 'e13.score' | translate }} {{ score() }}</span>
        }
      </div>

      <attome-seo-findings [pageId]="pageId()" [refresh]="audits()" (goToBlock)="goToBlock.emit($event)" />
    </section>
  `,
  styles: [`
    .seo { display: grid; gap: 0.6rem; }
    .seo-field { display: grid; gap: 0.25rem; }
    .seo-check { display: flex; gap: 0.5rem; align-items: center; }
    .seo-count { font-size: 0.8rem; color: var(--text-muted, #6b7280); }
    .seo-count[data-state='ok'] { color: var(--success, #15803d); }
    .seo-count[data-state='short'], .seo-count[data-state='long'] { color: var(--warning, #b45309); }
    .seo-serp, .seo-card { border: 1px solid var(--border, #e5e7eb); border-radius: 6px; padding-block: 0.6rem; padding-inline: 0.8rem; }
    .seo-serp-title { color: var(--link, #1a0dab); font-size: 1.05rem; }
    .seo-serp-url { color: var(--success, #15803d); font-size: 0.85rem; text-align: start; }
    .seo-serp-desc, .seo-card-desc { color: var(--text-muted, #4b5563); font-size: 0.9rem; }
    .seo-card-title { font-weight: 600; }
    .seo-actions { display: flex; gap: 0.6rem; align-items: center; flex-wrap: wrap; }
    .seo-error { color: var(--danger, #b91c1c); }
  `],
})
export class SeoPanelComponent implements OnInit {
  private readonly seo = inject(SeoService);

  readonly pageId = input.required<string>();
  /** The page's own title, used by the previews when no search title is set. */
  readonly pageTitle = input<string>('');
  /** The page's address, shown in the search preview. */
  readonly pageUrl = input<string>('');
  /** A finding's block to scroll the editor to. */
  readonly goToBlock = output<string>();

  title = '';
  description = '';
  canonical = '';
  noindex = false;
  nofollow = false;
  ogTitle = '';
  ogDescription = '';
  /** Not edited here; kept so a save does not clear it. */
  private ogImageRef: string | null = null;

  readonly rowVersion = signal<number | null>(null);
  readonly saving = signal(false);
  readonly saved = signal(false);
  readonly auditing = signal(false);
  readonly score = signal<number | null>(null);
  readonly error = signal<string | null>(null);
  readonly audits = signal(0);

  readonly clip = clip;

  /** Arabic settings (or an Arabic page) preview right to left. */
  rtl(): boolean {
    return isArabic(this.title || this.pageTitle());
  }

  ngOnInit(): void {
    this.seo.pageSeo(this.pageId()).subscribe({
      next: view => {
        this.apply(view.settings);
        this.rowVersion.set(view.row_version);
      },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  length(text: string): number {
    return displayLength(text);
  }

  titleState(): LengthState {
    return lengthState(displayLength(this.title), TITLE_BAND.min, TITLE_BAND.max);
  }

  descriptionState(): LengthState {
    return lengthState(displayLength(this.description), DESCRIPTION_BAND.min, DESCRIPTION_BAND.max);
  }

  private apply(s: PageSeo): void {
    this.title = s.title ?? '';
    this.description = s.description ?? '';
    this.canonical = s.canonical_url ?? '';
    this.noindex = s.noindex ?? false;
    this.nofollow = s.nofollow ?? false;
    this.ogTitle = s.og_title ?? '';
    this.ogDescription = s.og_description ?? '';
    this.ogImageRef = s.og_image_ref ?? null;
  }

  private settings(): PageSeo {
    const text = (v: string) => (v.trim() ? v.trim() : null);
    return {
      title: text(this.title),
      description: text(this.description),
      canonical_url: text(this.canonical),
      noindex: this.noindex,
      nofollow: this.nofollow,
      og_title: text(this.ogTitle),
      og_description: text(this.ogDescription),
      og_image_ref: this.ogImageRef,
    };
  }

  save(): void {
    const version = this.rowVersion();
    if (version === null) return;
    this.saving.set(true);
    this.saved.set(false);
    this.error.set(null);
    this.seo.savePageSeo(this.pageId(), this.settings(), version).subscribe({
      next: view => {
        this.apply(view.settings);
        this.rowVersion.set(view.row_version);
        this.saving.set(false);
        this.saved.set(true);
      },
      error: (e: ApiError) => {
        this.saving.set(false);
        this.error.set(e.message);
      },
    });
  }

  runAudit(): void {
    this.auditing.set(true);
    this.seo.audit(this.pageId()).subscribe({
      next: run => {
        this.score.set(run.score);
        this.auditing.set(false);
        this.audits.update(n => n + 1);
      },
      error: (e: ApiError) => {
        this.auditing.set(false);
        this.error.set(e.message);
      },
    });
  }
}
