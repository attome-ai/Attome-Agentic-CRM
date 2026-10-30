import { ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, effect, inject, signal, untracked } from '@angular/core';
import { ActivatedRoute, Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { ApiError, LangService, TranslatePipe } from '@attome/base';

import { PortalMe, PortalPageSummary, PortalSiteService } from './portal-site.service';

/** The portal's own pages, shown at fixed paths before any named page. */
export const RESERVED_PATHS = new Set(['login', 'profile', 'consent']);

/** The navigation entries for `pages`: every page but record pages, home first. Pure. */
export function navigation(pages: readonly PortalPageSummary[]): PortalPageSummary[] {
  const shown = pages.filter(p => p.page_type !== 'record' && !RESERVED_PATHS.has(p.name));
  return [...shown].sort((a, b) => (a.name === 'portal-home' ? -1 : b.name === 'portal-home' ? 1 : 0));
}

/**
 * G12-T1 — a web portal for its signed-in users, at `/p/:keyword`: the
 * portal's pages (T2 page definitions with a portal audience, shipped by
 * packs such as customer-service's home, my cases, case, knowledge and
 * services pages), the person's profile and consent, in Arabic or English.
 * Signing in and every call go through the portal's own API, never the staff
 * one. A visit without a session lands on the sign-in page; one whose
 * consent to the portal's current terms is missing, on the consent page.
 */
@Component({
  selector: 'xrm-portal-shell',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterOutlet, RouterLink, RouterLinkActive, TranslatePipe],
  template: `
    <div class="ps" [attr.dir]="lang.isRtl() ? 'rtl' : 'ltr'" data-testid="portal-shell">
      <header class="ps-head">
        <a class="ps-brand" [routerLink]="['/p', keyword()]">{{ 'portalSite.title' | translate }}</a>
        @if (me(); as person) {
          <nav class="ps-nav" [attr.aria-label]="'portalSite.navigation' | translate">
            @for (p of nav(); track p.name) {
              <a [routerLink]="p.name === 'portal-home' ? ['/p', keyword()] : ['/p', keyword(), p.name]"
                 routerLinkActive="active" [routerLinkActiveOptions]="{ exact: true }" [attr.data-page]="p.name">
                {{ titleOf(p) }}
              </a>
            }
            <a [routerLink]="['/p', keyword(), 'profile']" routerLinkActive="active">{{ 'portalSite.profile' | translate }}</a>
          </nav>
          <span class="ps-user" dir="auto">{{ person.name }}</span>
          <button type="button" (click)="signOut()" data-sign-out>{{ 'portalSite.signOut' | translate }}</button>
        }
        <button type="button" (click)="lang.toggle()" data-lang>{{ 'portalSite.language' | translate }}</button>
      </header>
      @if (error(); as message) { <p class="ps-error" role="alert">{{ message }}</p> }
      <main class="ps-main"><router-outlet /></main>
    </div>
  `,
  styles: [`
    :host { display: block; }
    .ps-head { display: flex; flex-wrap: wrap; align-items: center; gap: .75rem; padding-block: .75rem; padding-inline: 1rem;
               border-block-end: 1px solid var(--color-border, #ddd); }
    .ps-brand { font-weight: 700; text-decoration: none; color: inherit; }
    .ps-nav { display: flex; flex-wrap: wrap; gap: .75rem; flex: 1; }
    .ps-nav a { text-decoration: none; color: inherit; }
    .ps-nav a.active { font-weight: 700; text-decoration: underline; }
    .ps-main { padding-block: 1rem; padding-inline: 1rem; max-inline-size: 72rem; margin-inline: auto; }
    .ps-error { color: var(--color-danger, #c53030); margin-inline: 1rem; }
  `],
})
export class PortalShellComponent implements OnInit {
  protected readonly lang = inject(LangService);
  private readonly site = inject(PortalSiteService);
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);

  readonly keyword = computed(() => this.site.keyword() ?? '');
  readonly me = signal<PortalMe | null>(null);
  readonly pages = signal<PortalPageSummary[]>([]);
  readonly nav = computed(() => navigation(this.pages()));
  readonly error = signal<string | null>(null);

  constructor() {
    // A new portal, a sign-in or an accepted consent: read the session again.
    effect(() => {
      this.site.keyword();
      this.site.changed();
      untracked(() => this.refresh());
    });
  }

  ngOnInit(): void {
    const sub = this.route.paramMap.subscribe(params => {
      const keyword = params.get('keyword');
      if (keyword) this.site.keyword.set(keyword);
    });
    this.destroyRef.onDestroy(() => sub.unsubscribe());
  }

  /** Reads the session; signed out goes to sign-in, unconsented to consent. */
  refresh(): void {
    const keyword = this.keyword();
    if (!keyword) return;
    this.site.me(keyword).subscribe({
      next: person => {
        this.me.set(person);
        this.site.consent(keyword).subscribe({
          next: consent => {
            if (!consent.accepted) void this.router.navigate(['/p', keyword, 'consent']);
            else this.loadPages(keyword);
          },
          error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
        });
      },
      error: (e: ApiError) => {
        this.me.set(null);
        if (e.status === 401 || e.status === 403) void this.router.navigate(['/p', keyword, 'login']);
        else this.error.set(this.lang.errorText(e));
      },
    });
  }

  private loadPages(keyword: string): void {
    this.site.pages(keyword).subscribe({
      next: pages => this.pages.set(pages),
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }

  titleOf(page: PortalPageSummary): string {
    return (this.lang.isRtl() ? page.title_ar ?? page.title_en : page.title_en ?? page.title_ar) ?? page.name;
  }

  signOut(): void {
    const keyword = this.keyword();
    this.site.logout(keyword).subscribe({
      next: () => {
        this.me.set(null);
        this.pages.set([]);
        void this.router.navigate(['/p', keyword, 'login']);
      },
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }
}
