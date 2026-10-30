import { ChangeDetectionStrategy, Component, OnInit, computed, effect, inject, input, signal, untracked } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { EntityService } from '@attome/xrm/core/entity';
import { PageDataService, PageRuntimeComponent } from '@attome/xrm/core/page-runtime';
import type { PageDoc } from '@attome/xrm/core/page-runtime';
import { of } from 'rxjs';

import { PortalConsent, PortalMe, PortalPageData, PortalSiteService } from './portal-site.service';

/** What a record page offers for replying: the entity a reply is, its lookup to the record, its text field. */
export interface ReplyTarget {
  entity: string;
  lookup: string;
  body: string;
}

/** The reply a page's root asks for (`props.reply`), if it is well formed. Pure. */
export function replyOf(doc: PageDoc | null): ReplyTarget | null {
  const reply = doc?.root?.props?.['reply'] as Partial<ReplyTarget> | undefined;
  if (!reply || typeof reply !== 'object') return null;
  const ok = (v: unknown): v is string => typeof v === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(v);
  return ok(reply.entity) && ok(reply.lookup) && ok(reply.body)
    ? { entity: reply.entity, lookup: reply.lookup, body: reply.body }
    : null;
}

/**
 * G12-T1 — one portal page, by name (`/p/:keyword/:page`, the home page at
 * `/p/:keyword`), or a record page with its record (`/p/:keyword/:page/:id`).
 * The page runtime draws it with the portal's data source, so every list,
 * metric and record comes through the portal's record API under the portal
 * user's own plan. A record page whose root asks for replies
 * (`props.reply`) gets a reply box: the reply is a record of that entity
 * naming this one, which the portal plan checks like any write.
 */
@Component({
  selector: 'xrm-portal-page-host',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [PageRuntimeComponent, TranslatePipe],
  providers: [
    { provide: PageDataService, useClass: PortalPageData },
    // The portal has no staff schema; the runtime shows field names instead.
    { provide: EntityService, useValue: { getSchema: () => of(null) } },
  ],
  template: `
    @if (error(); as message) {
      <p class="pp-error" role="alert">{{ message }}</p>
    } @else if (doc(); as d) {
      @if (shown()) {
        <xrm-page-runtime [page]="d" [entity]="entityName() ?? undefined" [record]="recordId() ?? undefined" />
      }
      @if (reply() && recordId()) {
        <form class="pp-reply" (submit)="$event.preventDefault(); send()">
          <label for="pp-reply-text">{{ 'portalSite.reply' | translate }}</label>
          <textarea id="pp-reply-text" rows="4" dir="auto" [value]="text()" (input)="text.set($any($event.target).value)"></textarea>
          <button type="submit" [disabled]="busy() || !text().trim()" data-send>{{ 'portalSite.send' | translate }}</button>
          @if (sent()) { <p role="status">{{ 'portalSite.sent' | translate }}</p> }
        </form>
      }
    } @else {
      <p class="pp-muted">{{ 'portalSite.loading' | translate }}</p>
    }
  `,
  styles: [`
    :host { display: block; }
    .pp-reply { display: grid; gap: .5rem; margin-block-start: 1rem; max-inline-size: 40rem; }
    .pp-reply button { justify-self: start; }
    .pp-error { color: var(--color-danger, #c53030); }
    .pp-muted { color: var(--color-text-secondary, #666); }
  `],
})
export class PortalPageHostComponent {
  private readonly site = inject(PortalSiteService);
  private readonly lang = inject(LangService);

  /** The page's name; the portal's home page when absent. */
  readonly page = input<string | undefined>(undefined);
  /** A record page's record. */
  readonly id = input<string | undefined>(undefined);

  readonly doc = signal<PageDoc | null>(null);
  readonly entityName = signal<string | null>(null);
  readonly recordId = computed(() => this.id() ?? null);
  readonly reply = computed(() => replyOf(this.doc()));
  readonly error = signal<string | null>(null);
  readonly text = signal('');
  readonly busy = signal(false);
  readonly sent = signal(false);
  /** Re-drawn after a reply so its list shows it. */
  readonly shown = signal(true);

  constructor() {
    effect(() => {
      const name = this.page() ?? 'portal-home';
      const keyword = this.site.keyword();
      untracked(() => {
        if (keyword) this.load(keyword, name);
      });
    });
  }

  private load(keyword: string, name: string): void {
    this.doc.set(null);
    this.error.set(null);
    this.site.page(keyword, name).subscribe({
      next: p => {
        this.entityName.set(p.entity_name);
        this.doc.set(p.doc);
      },
      error: (e: ApiError) =>
        this.error.set(e.status === 404 ? this.lang.translate('pageRuntime.notFound') : this.lang.errorText(e)),
    });
  }

  send(): void {
    const target = this.reply();
    const id = this.recordId();
    const keyword = this.site.keyword();
    if (!target || !id || !keyword || !this.text().trim()) return;
    this.busy.set(true);
    this.sent.set(false);
    this.site.create(keyword, target.entity, { [target.lookup]: id, [target.body]: this.text().trim() }).subscribe({
      next: () => {
        this.busy.set(false);
        this.text.set('');
        this.sent.set(true);
        this.shown.set(false);
        queueMicrotask(() => this.shown.set(true));
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(this.lang.errorText(e));
      },
    });
  }
}

/** G12-T1 — the portal's sign-in page (`/p/:keyword/login`). */
@Component({
  selector: 'xrm-portal-login',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <form class="pl" (submit)="$event.preventDefault(); signIn()" data-testid="portal-login">
      <h1>{{ 'portalSite.signIn' | translate }}</h1>
      <label for="pl-login">{{ 'portalSite.login' | translate }}</label>
      <input id="pl-login" autocomplete="username" dir="ltr" [value]="login()" (input)="login.set($any($event.target).value)" />
      <label for="pl-password">{{ 'portalSite.password' | translate }}</label>
      <input id="pl-password" type="password" autocomplete="current-password" dir="ltr"
             [value]="password()" (input)="password.set($any($event.target).value)" />
      @if (needCode()) {
        <label for="pl-code">{{ 'portalSite.code' | translate }}</label>
        <input id="pl-code" inputmode="numeric" autocomplete="one-time-code" dir="ltr" (input)="code.set($any($event.target).value)" />
      }
      <button type="submit" [disabled]="busy() || !login() || !password()" data-sign-in>{{ 'portalSite.signIn' | translate }}</button>
      @if (error(); as message) { <p role="alert" class="pl-error">{{ message }}</p> }
    </form>
  `,
  styles: [`
    .pl { display: grid; gap: .5rem; max-inline-size: 24rem; }
    .pl button { justify-self: start; }
    .pl-error { color: var(--color-danger, #c53030); }
  `],
})
export class PortalLoginComponent {
  private readonly site = inject(PortalSiteService);
  private readonly router = inject(Router);
  private readonly lang = inject(LangService);

  readonly login = signal('');
  readonly password = signal('');
  readonly code = signal('');
  readonly needCode = signal(false);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);

  signIn(): void {
    const keyword = this.site.keyword();
    if (!keyword) return;
    this.busy.set(true);
    this.error.set(null);
    this.site.login(keyword, this.login().trim(), this.password(), this.code().trim()).subscribe({
      next: () => {
        this.busy.set(false);
        this.site.changed.update(n => n + 1);
        void this.router.navigate(['/p', keyword]);
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        if (e.code === 'mfa_required') {
          this.needCode.set(true);
          return;
        }
        this.error.set(e.status === 401 ? this.lang.translate('portalSite.badLogin') : this.lang.errorText(e));
      },
    });
  }
}

/** G12-T1 — the signed-in person's profile (`/p/:keyword/profile`): name, email and the fields the portal lets them edit. */
@Component({
  selector: 'xrm-portal-profile',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    @if (me(); as person) {
      <section class="pf" data-testid="portal-profile">
        <h1 dir="auto">{{ person.name }}</h1>
        @if (person.email) { <p dir="ltr">{{ person.email }}</p> }
        @for (f of fields(); track f) {
          <label [for]="'pf-' + f">{{ f }}</label>
          <input [id]="'pf-' + f" dir="auto" [value]="draft()[f] ?? ''" (input)="edit(f, $any($event.target).value)" />
        }
        @if (fields().length) {
          <button type="button" (click)="save()" [disabled]="busy()" data-save>{{ 'portalSite.save' | translate }}</button>
        }
        @if (saved()) { <p role="status">{{ 'portalSite.saved' | translate }}</p> }
        @if (error(); as message) { <p role="alert" class="pf-error">{{ message }}</p> }
      </section>
    }
  `,
  styles: [`
    .pf { display: grid; gap: .5rem; max-inline-size: 28rem; }
    .pf button { justify-self: start; }
    .pf-error { color: var(--color-danger, #c53030); }
  `],
})
export class PortalProfileComponent implements OnInit {
  private readonly site = inject(PortalSiteService);
  private readonly lang = inject(LangService);

  readonly me = signal<PortalMe | null>(null);
  readonly draft = signal<Record<string, string>>({});
  readonly fields = computed(() => Object.keys(this.me()?.profile ?? {}).filter(f => f !== 'id'));
  readonly busy = signal(false);
  readonly saved = signal(false);
  readonly error = signal<string | null>(null);

  ngOnInit(): void {
    const keyword = this.site.keyword();
    if (!keyword) return;
    this.site.me(keyword).subscribe({
      next: person => this.show(person),
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }

  private show(person: PortalMe): void {
    this.me.set(person);
    const draft: Record<string, string> = {};
    for (const [k, v] of Object.entries(person.profile ?? {})) draft[k] = v === null || v === undefined ? '' : String(v);
    this.draft.set(draft);
  }

  edit(field: string, value: string): void {
    this.draft.update(d => ({ ...d, [field]: value }));
    this.saved.set(false);
  }

  save(): void {
    const person = this.me();
    const keyword = this.site.keyword();
    if (!person || !keyword) return;
    const changes: Record<string, unknown> = {};
    for (const f of this.fields()) {
      const before = person.profile[f] === null || person.profile[f] === undefined ? '' : String(person.profile[f]);
      if (this.draft()[f] !== before) changes[f] = this.draft()[f];
    }
    if (!Object.keys(changes).length) return;
    this.busy.set(true);
    this.site.updateProfile(keyword, changes, person.row_version).subscribe({
      next: updated => {
        this.busy.set(false);
        this.saved.set(true);
        this.show(updated);
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(this.lang.errorText(e));
      },
    });
  }
}

/** G12-T1 — accepting the portal's current terms and privacy notice (`/p/:keyword/consent`). */
@Component({
  selector: 'xrm-portal-consent',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    @if (consent(); as c) {
      <section class="pc" data-testid="portal-consent">
        <h1>{{ 'portalSite.consent' | translate }}</h1>
        @if (c.accepted) {
          <p role="status">{{ 'portalSite.consentAccepted' | translate }}</p>
        } @else {
          <p>{{ 'portalSite.consentAsk' | translate: { terms: c.terms_version ?? '-', privacy: c.privacy_version ?? '-' } }}</p>
          <button type="button" (click)="accept(c)" [disabled]="busy()" data-accept>{{ 'portalSite.accept' | translate }}</button>
        }
        @if (error(); as message) { <p role="alert" class="pc-error">{{ message }}</p> }
      </section>
    }
  `,
  styles: [`
    .pc { display: grid; gap: .5rem; max-inline-size: 36rem; }
    .pc button { justify-self: start; }
    .pc-error { color: var(--color-danger, #c53030); }
  `],
})
export class PortalConsentComponent implements OnInit {
  private readonly site = inject(PortalSiteService);
  private readonly lang = inject(LangService);
  private readonly router = inject(Router);

  readonly consent = signal<PortalConsent | null>(null);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);

  ngOnInit(): void {
    const keyword = this.site.keyword();
    if (!keyword) return;
    this.site.consent(keyword).subscribe({
      next: c => this.consent.set(c),
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }

  accept(consent: PortalConsent): void {
    const keyword = this.site.keyword();
    if (!keyword) return;
    this.busy.set(true);
    this.site.acceptConsent(keyword, consent).subscribe({
      next: () => {
        this.busy.set(false);
        this.consent.set({ ...consent, accepted: true });
        this.site.changed.update(n => n + 1);
        void this.router.navigate(['/p', keyword]);
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(this.lang.errorText(e));
      },
    });
  }
}

/**
 * G12-T1 — `/p/-/...`: a page's navigate target cannot know the portal's
 * keyword, so it names `-`, and this sends the person to the same path in
 * the portal they are in.
 */
@Component({
  selector: 'xrm-portal-here',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: ``,
})
export class PortalHereComponent implements OnInit {
  private readonly site = inject(PortalSiteService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);

  ngOnInit(): void {
    const keyword = this.site.keyword();
    const rest = this.route.snapshot.url.map(s => s.path);
    void this.router.navigate(keyword ? ['/p', keyword, ...rest] : ['/'], { replaceUrl: true });
  }
}
