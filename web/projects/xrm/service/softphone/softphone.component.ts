import { DOCUMENT } from '@angular/common';
import {
  ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, input, signal,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { TranslatePipe } from '@attome/base';
import { SoftphoneConfig, SoftphoneService, popLink, recordFromUrl, telNumber } from './softphone.service';

/**
 * J6-T2: the softphone panel in the shell header. It starts the browser
 * softphone with the server's settings, shows an incoming call with its
 * screen pop (the matched record, a link to open it), and has a dial box
 * for calls from the open record. Any `tel:` link clicked while a record is
 * open calls that number about the record (click-to-call). Logical CSS only.
 */
@Component({
  selector: 'xrm-softphone',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, RouterLink, TranslatePipe],
  template: `
    <div class="sp" data-testid="softphone">
      <button type="button" class="sp-toggle" (click)="open.set(!open())"
              [attr.aria-expanded]="open()" [attr.aria-label]="'softphone.title' | translate"
              [class.sp-ringing]="phone.state() === 'incoming'">
        <i class="las la-phone" aria-hidden="true"></i>
      </button>
      @if (open() || phone.state() === 'incoming') {
        <section class="sp-panel" role="dialog" [attr.aria-label]="'softphone.title' | translate">
          <p class="sp-status" role="status">{{ ('softphone.state.' + phone.state()) | translate }}</p>
          @if (phone.state() === 'incoming' || phone.state() === 'in_call') {
            <p class="sp-caller"><bdi>{{ phone.caller() }}</bdi></p>
            @if (phone.pop(); as pop) {
              <a class="sp-pop" [routerLink]="link(pop).path" [queryParams]="link(pop).query" data-testid="softphone-pop">
                {{ pop.name || ('softphone.openRecord' | translate) }}
              </a>
            }
          }
          <div class="sp-actions">
            @switch (phone.state()) {
              @case ('incoming') {
                <button type="button" class="sp-btn sp-accept" (click)="phone.accept()" data-testid="softphone-accept">
                  {{ 'softphone.accept' | translate }}
                </button>
                <button type="button" class="sp-btn" (click)="phone.reject()">{{ 'softphone.reject' | translate }}</button>
              }
              @case ('calling') {
                <button type="button" class="sp-btn sp-end" (click)="phone.hangUp()">{{ 'softphone.hangUp' | translate }}</button>
              }
              @case ('in_call') {
                <button type="button" class="sp-btn sp-end" (click)="phone.hangUp()">{{ 'softphone.hangUp' | translate }}</button>
              }
              @default {
                <form class="sp-dial" (ngSubmit)="dial()">
                  <input name="number" type="tel" [(ngModel)]="number" dir="ltr"
                         [attr.aria-label]="'softphone.number' | translate" placeholder="+9665…"
                         data-testid="softphone-number" />
                  <button type="submit" class="sp-btn sp-accept" [disabled]="!canDial()" data-testid="softphone-dial">
                    {{ 'softphone.call' | translate }}
                  </button>
                </form>
                @if (!record()) { <p class="sp-hint">{{ 'softphone.openARecord' | translate }}</p> }
              }
            }
          </div>
          @if (phone.error(); as e) { <p class="sp-error" role="alert">{{ e }}</p> }
        </section>
      }
    </div>
  `,
  styles: [`
    .sp { position: relative; }
    .sp-toggle { background: none; border: none; color: inherit; cursor: pointer; font-size: 1.25rem;
      padding-block: 0.25rem; padding-inline: 0.375rem; border-radius: 0.375rem; }
    .sp-ringing { color: var(--color-accent, #2563eb); animation: sp-pulse 1s infinite; }
    @keyframes sp-pulse { 50% { opacity: 0.4; } }
    .sp-panel { position: absolute; inset-inline-end: 0; inset-block-start: calc(100% + 0.375rem); z-index: 30;
      inline-size: 16rem; background: var(--color-surface, #fff); color: var(--color-text-primary, inherit);
      border: 1px solid var(--color-border, #e3e5e8); border-radius: 0.5rem; padding-block: 0.75rem;
      padding-inline: 0.75rem; display: flex; flex-direction: column; gap: 0.5rem;
      box-shadow: var(--color-card-shadow, 0 4px 16px rgb(0 0 0 / 0.12)); }
    .sp-status { margin: 0; font-weight: 600; }
    .sp-caller { margin: 0; font-variant-numeric: tabular-nums; }
    .sp-pop { color: var(--color-accent, #2563eb); }
    .sp-actions { display: flex; flex-wrap: wrap; gap: 0.375rem; }
    .sp-dial { display: flex; gap: 0.375rem; inline-size: 100%; }
    .sp-dial input { flex: 1; min-inline-size: 0; padding-block: 0.375rem; padding-inline: 0.5rem;
      border: 1px solid var(--color-border, #e3e5e8); border-radius: 0.375rem; font: inherit; }
    .sp-btn { padding-block: 0.375rem; padding-inline: 0.75rem; border: 1px solid var(--color-border, #e3e5e8);
      border-radius: 0.375rem; background: var(--color-surface, #fff); color: inherit; cursor: pointer; }
    .sp-accept { background: var(--color-accent, #2563eb); border-color: var(--color-accent, #2563eb);
      color: var(--color-on-accent, #fff); }
    .sp-end { background: var(--color-danger, #b42318); border-color: var(--color-danger, #b42318);
      color: var(--color-on-accent, #fff); }
    .sp-btn:disabled { opacity: 0.6; cursor: not-allowed; }
    .sp-hint { margin: 0; color: var(--color-text-secondary, #5b616b); font-size: 0.8125rem; }
    .sp-error { margin: 0; color: var(--color-danger, #b42318); font-size: 0.8125rem; }
  `],
})
export class SoftphoneComponent implements OnInit {
  protected readonly phone = inject(SoftphoneService);
  private readonly router = inject(Router);
  private readonly doc = inject(DOCUMENT);
  private readonly destroyRef = inject(DestroyRef);

  /** The server's settings, from the shell's launcher. */
  readonly config = input.required<SoftphoneConfig>();

  readonly open = signal(false);
  readonly url = signal('');
  readonly record = computed(() => recordFromUrl(this.url()));
  number = '';

  private readonly onClick = (event: MouseEvent) => {
    const anchor = (event.target as Element | null)?.closest?.('a[href^="tel:"]');
    const tel = anchor ? telNumber(anchor.getAttribute('href') ?? '') : null;
    const record = recordFromUrl(this.router.url);
    if (!tel || !record) return;
    event.preventDefault();
    this.open.set(true);
    void this.phone.call(tel, record);
  };

  ngOnInit(): void {
    this.url.set(this.router.url);
    const sub = this.router.events.subscribe(() => this.url.set(this.router.url));
    this.doc.addEventListener('click', this.onClick, true);
    this.destroyRef.onDestroy(() => {
      sub.unsubscribe();
      this.doc.removeEventListener('click', this.onClick, true);
      this.phone.stop();
    });
    void this.phone.start(this.config());
  }

  canDial(): boolean {
    return !!this.record() && /^\+\d{8,15}$/.test(this.number.replace(/[\s-]/g, ''));
  }

  dial(): void {
    const record = this.record();
    if (!record || !this.canDial()) return;
    void this.phone.call(this.number.replace(/[\s-]/g, ''), record);
  }

  link(pop: { entity: string; id: string; name: string | null }) {
    return popLink(pop);
  }
}
