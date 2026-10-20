import {
  ChangeDetectionStrategy, Component, DestroyRef, computed, effect, inject, input, signal, untracked,
} from '@angular/core';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { EntityService } from '@attome/xrm/core/entity';
import { catchError, of } from 'rxjs';

import { CallHandle, ClaimedMember, DialerService } from './dialer.service';

/** The outcomes an agent records (call_attempt.outcome). */
export const OUTCOMES = [
  'connected', 'no_answer', 'busy', 'wrong_number', 'voicemail_left', 'call_back_later', 'not_interested',
] as const;

export type DialerPhase = 'idle' | 'countdown' | 'calling' | 'done';

/** One step of the list's script (a D26 playbook's steps). */
export interface ScriptStep {
  title: string;
  guidance: string | null;
}

/** The record shown before the call: its name and what it is. Pure. */
export function previewLines(data: Record<string, unknown>): { name: string; detail: string | null } {
  const text = (k: string) => (typeof data[k] === 'string' && data[k] ? data[k] as string : null);
  return {
    name: text('full_name') ?? text('name') ?? text('topic') ?? text('email') ?? '',
    detail: [text('job_title'), text('company_name') ?? text('company')].filter(Boolean).join(' · ') || null,
  };
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * The power dialer (roadmap D21-T11): takes the list's next member, shows
 * who they are, counts down (pausable) and rings the agent's phone then
 * theirs, then records the outcome and moves to the next. Skip passes a
 * member over with a reason; snooze is the "call back later" outcome. A
 * recorded voicemail can be dropped when the list allows it. The list's
 * script, when it names a playbook, shows its steps. Nothing dials without
 * the agent having started the list. Phone numbers stay left to right in
 * Arabic.
 */
@Component({
  selector: 'xrm-sales-dialer-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <section class="dp" [attr.dir]="lang.isRtl() ? 'rtl' : 'ltr'" aria-labelledby="dp-title" data-testid="dp">
      <header class="dp-head">
        <h2 id="dp-title">{{ 'salesDialer.title' | translate }} <span class="dp-list">{{ listName() }}</span></h2>
        @if (phase() === 'idle') {
          <button type="button" class="btn btn-primary" data-testid="dp-start" (click)="next()">
            {{ 'salesDialer.start' | translate }}</button>
        }
      </header>
      @if (error(); as message) { <p class="dp-error" role="alert">{{ message }}</p> }

      @if (phase() === 'done') {
        <p class="dp-muted" data-testid="dp-done">{{ 'salesDialer.done' | translate }}</p>
      }

      @if (member(); as m) {
        <article class="dp-card" data-testid="dp-member">
          <h3>{{ preview().name }}</h3>
          @if (preview().detail; as d) { <p class="dp-muted">{{ d }}</p> }
          @if (m.phone) { <p><span dir="ltr" class="dp-phone">{{ m.phone }}</span></p> }

          @if (phase() === 'countdown') {
            <p class="dp-count" role="timer" aria-live="polite" data-testid="dp-countdown">
              {{ 'salesDialer.callingIn' | translate }} {{ remaining() }}</p>
            <button type="button" data-testid="dp-pause" (click)="togglePause()">
              {{ (paused() ? 'salesDialer.resume' : 'salesDialer.pause') | translate }}</button>
            <button type="button" (click)="dialNow()">{{ 'salesDialer.callNow' | translate }}</button>
          }
          @if (phase() === 'calling') {
            <p class="dp-muted" role="status">{{ 'salesDialer.calling' | translate }}</p>
            @if (voicemailEnabled() && call()) {
              <div class="dp-vm">
                <label>{{ 'salesDialer.voicemailUrl' | translate }}
                  <input type="url" dir="ltr" [value]="voicemailUrl()" (input)="voicemailUrl.set(text($event))"></label>
                <button type="button" data-testid="dp-voicemail" [disabled]="busy() || !voicemailUrl()" (click)="dropVoicemail()">
                  {{ 'salesDialer.dropVoicemail' | translate }}</button>
              </div>
            }
          }

          <div class="dp-outcomes" role="group" [attr.aria-label]="'salesDialer.outcome' | translate">
            @for (o of outcomes; track o) {
              <button type="button" [attr.data-outcome]="o" [disabled]="busy()" (click)="record(o)">
                {{ 'salesDialer.outcomes.' + o | translate }}</button>
            }
          </div>
          <div class="dp-actions">
            <label>{{ 'salesDialer.skipReason' | translate }}
              <input [value]="skipReason()" (input)="skipReason.set(text($event))" data-testid="dp-skip-reason"></label>
            <button type="button" data-testid="dp-skip" [disabled]="busy() || !skipReason().trim()" (click)="skip()">
              {{ 'salesDialer.skip' | translate }}</button>
            <button type="button" data-testid="dp-snooze" [disabled]="busy()" (click)="record('call_back_later')">
              {{ 'salesDialer.snooze' | translate }}</button>
          </div>
        </article>
      }

      @if (script().length) {
        <aside class="dp-script" [attr.aria-label]="'salesDialer.script' | translate">
          <h3>{{ 'salesDialer.script' | translate }}</h3>
          <ol>
            @for (s of script(); track $index) {
              <li><strong>{{ s.title }}</strong> @if (s.guidance) { <span class="dp-muted">{{ s.guidance }}</span> }</li>
            }
          </ol>
        </aside>
      }
    </section>
  `,
  styles: [`
    .dp { display: flex; flex-direction: column; gap: var(--space-3, 12px); }
    .dp-head { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: var(--space-2, 8px); }
    .dp-card { border: 1px solid var(--color-border); padding: var(--space-3, 12px); display: flex; flex-direction: column; gap: var(--space-2, 8px); }
    .dp-card h3 { margin: 0; }
    .dp-outcomes, .dp-actions, .dp-vm { display: flex; flex-wrap: wrap; gap: var(--space-2, 8px); align-items: end; }
    .dp-count { font-size: 1.25rem; margin: 0; }
    .dp-script ol { margin: 0; padding-inline-start: var(--space-4, 16px); }
    .dp-muted { color: var(--color-text-secondary); margin: 0; }
    .dp-error { color: var(--color-danger); margin: 0; }
  `],
})
export class DialerPanelComponent {
  private readonly dialer = inject(DialerService);
  private readonly entities = inject(EntityService);
  protected readonly lang = inject(LangService);

  /** The call list (route parameter). */
  readonly id = input.required<string>();

  readonly outcomes = OUTCOMES;
  readonly listName = signal('');
  readonly countdownSeconds = signal(10);
  readonly voicemailEnabled = signal(false);
  readonly script = signal<ScriptStep[]>([]);
  readonly phase = signal<DialerPhase>('idle');
  readonly member = signal<ClaimedMember | null>(null);
  readonly memberData = signal<Record<string, unknown>>({});
  readonly remaining = signal(0);
  readonly paused = signal(false);
  readonly call = signal<CallHandle | null>(null);
  readonly voicemailUrl = signal('');
  readonly voicemailDropped = signal(false);
  readonly skipReason = signal('');
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  readonly preview = computed(() => previewLines(this.memberData()));

  private timer: ReturnType<typeof setInterval> | null = null;
  private startedAt = 0;

  constructor() {
    inject(DestroyRef).onDestroy(() => this.stopTimer());
    effect(() => {
      const id = this.id();
      untracked(() => this.loadList(id));
    });
  }

  text(event: Event): string {
    return (event.target as HTMLInputElement).value;
  }

  /** Takes the next member and starts its countdown. */
  next(): void {
    this.stopTimer();
    this.call.set(null);
    this.voicemailDropped.set(false);
    this.skipReason.set('');
    this.error.set(null);
    this.busy.set(true);
    this.dialer.claim(this.id()).subscribe({
      next: result => {
        this.busy.set(false);
        const m = result.member ?? null;
        this.member.set(m);
        if (!m) {
          this.memberData.set({});
          this.phase.set('done');
          return;
        }
        this.entities.get(m.entity_name, m.record_id).pipe(catchError(() => of(null))).subscribe(r =>
          this.memberData.set((r?.data ?? {}) as Record<string, unknown>));
        this.startCountdown();
      },
      error: (e: ApiError) => this.fail(e),
    });
  }

  togglePause(): void {
    this.paused.update(p => !p);
  }

  dialNow(): void {
    this.stopTimer();
    this.dial();
  }

  /** Saves the outcome and moves on. */
  record(outcome: string): void {
    const m = this.member();
    if (!m) return;
    this.stopTimer();
    this.busy.set(true);
    this.dialer.outcome(m.member_id, {
      outcome,
      activity_id: this.call()?.activity_id ?? null,
      duration_seconds: this.startedAt ? Math.round((Date.now() - this.startedAt) / 1000) : null,
      voicemail_dropped: this.voicemailDropped(),
    }).subscribe({
      next: () => this.next(),
      error: (e: ApiError) => this.fail(e),
    });
  }

  skip(): void {
    const m = this.member();
    const reason = this.skipReason().trim();
    if (!m || !reason) return;
    this.stopTimer();
    this.busy.set(true);
    this.dialer.skip(m.member_id, reason).subscribe({
      next: () => this.next(),
      error: (e: ApiError) => this.fail(e),
    });
  }

  dropVoicemail(): void {
    const call = this.call();
    const url = this.voicemailUrl().trim();
    if (!call || !url) return;
    this.busy.set(true);
    this.dialer.voicemail(this.id(), call.call_id, url).subscribe({
      next: () => {
        this.voicemailDropped.set(true);
        this.record('voicemail_left');
      },
      error: (e: ApiError) => this.fail(e),
    });
  }

  private startCountdown(): void {
    this.phase.set('countdown');
    this.paused.set(false);
    this.remaining.set(Math.max(0, this.countdownSeconds()));
    if (this.remaining() === 0) {
      this.dial();
      return;
    }
    this.timer = setInterval(() => {
      if (this.paused()) return;
      const left = this.remaining() - 1;
      this.remaining.set(left);
      if (left <= 0) {
        this.stopTimer();
        this.dial();
      }
    }, 1000);
  }

  private dial(): void {
    const m = this.member();
    if (!m) return;
    this.phase.set('calling');
    if (!m.phone) return;
    this.startedAt = Date.now();
    this.dialer.dial(this.id(), { to: m.phone, entity_name: m.entity_name, record_id: m.record_id }).subscribe({
      next: handle => this.call.set(handle),
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }

  private stopTimer(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  private fail(e: ApiError): void {
    this.busy.set(false);
    this.error.set(this.lang.errorText(e));
  }

  private loadList(id: string): void {
    this.entities.get('call_list', id).subscribe({
      next: r => {
        const d = r.data as Record<string, unknown>;
        this.listName.set(String(d['name'] ?? ''));
        const seconds = Number(d['countdown_seconds']);
        this.countdownSeconds.set(Number.isFinite(seconds) && d['countdown_seconds'] != null ? seconds : 10);
        this.voicemailEnabled.set(d['voicemail_enabled'] === true);
        const script = typeof d['script_ref'] === 'string' ? d['script_ref'].trim() : '';
        if (UUID.test(script)) this.loadScript(script);
      },
      error: (e: ApiError) => this.fail(e),
    });
  }

  private loadScript(playbook: string): void {
    this.entities.list('playbook_step', {
      filters: [{ field: 'playbook_ref', op: 'eq', value: playbook }],
      sorts: [{ field: 'step_order', dir: 'asc' }],
      limit: 50,
    }).pipe(catchError(() => of(null))).subscribe(res => this.script.set((res?.data ?? []).map(s => ({
      title: String(s.data['title'] ?? ''),
      guidance: typeof s.data['guidance'] === 'string' ? s.data['guidance'] : null,
    }))));
  }
}
