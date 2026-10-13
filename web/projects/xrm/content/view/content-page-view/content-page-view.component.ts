import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { DOCUMENT } from '@angular/common';
import { ActivatedRoute } from '@angular/router';
import { ApiError } from '@attome/base';
import { ContentPublicService, PublicPageView } from '../services/content-public.service';
import { ContentBlockViewComponent } from '../content-block-view/content-block-view.component';

/**
 * The public, anonymous page-view route — the host app's lowest-priority
 * wildcard route (`path: '**'`) lands here when nothing else in the SPA
 * matches, and this resolves the visited path against the bypass endpoint
 * `GET /api/v1/content/view`. No nginx/reverse-proxy change was needed for
 * this (see D-367): the SPA already owns every unmatched path once
 * `index.html` is served, exactly like any other deep link.
 */
@Component({
  selector: 'attome-content-page-view',
  standalone: true,
  imports: [ContentBlockViewComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls: ['./content-page-view.component.css'],
  templateUrl: './content-page-view.component.html',
})
export class ContentPageViewComponent {
  private readonly svc = inject(ContentPublicService);
  private readonly route = inject(ActivatedRoute);
  private readonly document = inject(DOCUMENT);

  readonly loading = signal(true);
  readonly page = signal<PublicPageView | null>(null);

  /** M37 Phase 2 (D-452) — 'idle' before a vote, 'sent' after one succeeds
   *  (buttons hide so a visitor cannot vote twice from the same render),
   *  'error' on failure (including a 429 — the service layer does not
   *  distinguish, and there is nothing more useful to tell an anonymous
   *  visitor than "try again shortly" either way). */
  readonly voteState = signal<'idle' | 'sent' | 'error'>('idle');

  private path = '';

  constructor() {
    // The wildcard route's own segment path IS the content path — e.g.
    // `/guide/templates` resolves via `route.snapshot.url` joined back
    // together, not a `:path` param (a `**` route carries no named params).
    const segments = this.route.snapshot.url.map(s => s.path).join('/');
    this.path = `/${segments}`;
    this.svc.view(this.path).subscribe({
      next: p => {
        this.page.set(p);
        this.loading.set(false);
        this.document.title = p.seo_title || p.title;
        this.setMetaDescription(p.seo_description);
      },
      error: (_e: ApiError) => {
        this.loading.set(false);
      },
    });
  }

  vote(useful: boolean): void {
    if (this.voteState() !== 'idle') return;
    this.svc.vote(this.path, useful).subscribe({
      next: () => this.voteState.set('sent'),
      error: () => this.voteState.set('error'),
    });
  }

  private setMetaDescription(description: string | null): void {
    if (!description) return;
    let tag = this.document.querySelector('meta[name="description"]');
    if (!tag) {
      tag = this.document.createElement('meta');
      tag.setAttribute('name', 'description');
      this.document.head.appendChild(tag);
    }
    tag.setAttribute('content', description);
  }
}
