import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal, untracked } from '@angular/core';
import { ApiError, ApiService, LangService, TranslatePipe } from '@attome/base';
import { catchError, of } from 'rxjs';

/** A document in the envelope (`EnvelopeDocument`). */
export interface SignDocument {
  document_id: string;
  name: string;
  sha256: string;
}

/** What the signer sees (`GET /api/v1/esign/sign/{token}`). */
export interface SignerView {
  envelope_title: string;
  envelope_status: string;
  signer_name: string;
  signer_status: string;
  may_sign: boolean;
  documents: SignDocument[];
}

/** The answer to an action (`POST /api/v1/esign/sign/{token}`). */
export interface SignerActionDone {
  result: 'code_sent' | 'signed' | 'declined';
  envelope_status: string;
}

type Stage = 'loading' | 'ready' | 'working' | 'invalid' | 'done';

/** Whether the code looks complete: six digits, Arabic-Indic digits counted. Pure. */
export function codeComplete(code: string): boolean {
  const digits = code.replace(/[٠-٩]/g, d => String(d.charCodeAt(0) - 0x0660)).replace(/\D/g, '');
  return digits.length === 6;
}

/**
 * The signing page a signer's emailed link opens (roadmap K4-T1): the
 * envelope and the fingerprint of each document, then "email me a code",
 * and with the six-digit code and their typed name, sign, or decline with a
 * reason. No sign-in: the link and the emailed code are the authority. A
 * signer whose turn has not come, or who has signed, sees where things
 * stand. Arabic mirrors the page; codes and fingerprints stay left to right.
 */
@Component({
  selector: 'xrm-esign-sign-page',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <main class="es" [attr.dir]="lang.isRtl() ? 'rtl' : 'ltr'" data-testid="es">
      @switch (stage()) {
        @case ('loading') { <p>{{ 'esignSign.loading' | translate }}</p> }
        @case ('invalid') { <p role="alert" data-testid="es-invalid">{{ 'esignSign.invalid' | translate }}</p> }
        @default {
          @if (view(); as v) {
            <h1>{{ v.envelope_title }}</h1>
            <p>{{ 'esignSign.hello' | translate }} {{ v.signer_name }}</p>
            <ul class="es-docs">
              @for (d of v.documents; track d.document_id) {
                <li>{{ d.name }} <code dir="ltr" class="es-hash">{{ d.sha256.slice(0, 16) }}…</code></li>
              }
            </ul>
            @if (stage() === 'done' || !v.may_sign) {
              <p data-testid="es-status">{{ statusKey() | translate }}</p>
            } @else {
              <div class="es-act">
                <button type="button" data-testid="es-code" [disabled]="working()" (click)="requestCode()">
                  {{ 'esignSign.sendCode' | translate }}</button>
                @if (codeSent()) { <p role="status" data-testid="es-code-sent">{{ 'esignSign.codeSent' | translate }}</p> }
                <label>{{ 'esignSign.code' | translate }}
                  <input dir="ltr" inputmode="numeric" autocomplete="one-time-code" data-testid="es-code-input"
                         [value]="code()" (input)="code.set(text($event))"></label>
                <label>{{ 'esignSign.typedName' | translate }}
                  <input data-testid="es-name" [value]="typedName()" (input)="typedName.set(text($event))"></label>
                <button type="button" data-testid="es-sign" [disabled]="!canSign()" (click)="act('sign')">
                  {{ 'esignSign.sign' | translate }}</button>
                <label>{{ 'esignSign.reason' | translate }}
                  <input data-testid="es-reason" [value]="reason()" (input)="reason.set(text($event))"></label>
                <button type="button" data-testid="es-decline" [disabled]="!codeComplete(code()) || working()" (click)="act('decline')">
                  {{ 'esignSign.decline' | translate }}</button>
              </div>
            }
          }
          @if (error(); as message) { <p class="es-error" role="alert">{{ message }}</p> }
        }
      }
    </main>
  `,
  styles: [`
    .es { max-inline-size: 40rem; margin-inline: auto; padding: var(--space-4, 1rem); display: grid; gap: var(--space-3, .75rem); }
    .es-docs { padding-inline-start: 1.25rem; }
    .es-hash { color: var(--color-text-secondary, #666); margin-inline-start: .5rem; }
    .es-act { display: grid; gap: var(--space-2, .5rem); }
    .es-error { color: var(--color-danger, #c53030); }
  `],
})
export class SignPageComponent {
  private readonly api = inject(ApiService);
  protected readonly lang = inject(LangService);
  protected readonly codeComplete = codeComplete;

  /** The signer's link token (route parameter). */
  readonly token = input.required<string>();

  protected readonly view = signal<SignerView | null>(null);
  protected readonly stage = signal<Stage>('loading');
  protected readonly error = signal<string | null>(null);
  protected readonly code = signal('');
  protected readonly typedName = signal('');
  protected readonly reason = signal('');
  protected readonly codeSent = signal(false);
  protected readonly working = computed(() => this.stage() === 'working');
  protected readonly canSign = computed(
    () => !this.working() && codeComplete(this.code()) && this.typedName().trim().length > 0,
  );
  protected readonly statusKey = computed(() => {
    const v = this.view();
    if (!v) return 'esignSign.loading';
    if (v.signer_status === 'signed') return 'esignSign.signed';
    if (v.signer_status === 'declined' || v.envelope_status === 'declined') return 'esignSign.declined';
    if (v.envelope_status === 'completed') return 'esignSign.completed';
    return 'esignSign.notYourTurn';
  });

  constructor() {
    effect(() => {
      const token = this.token();
      untracked(() => this.load(token));
    });
  }

  protected text(event: Event): string {
    return (event.target as HTMLInputElement).value;
  }

  protected requestCode(): void {
    this.post({ action: 'code' }, () => this.codeSent.set(true));
  }

  protected act(action: 'sign' | 'decline'): void {
    const body = action === 'sign'
      ? { action, code: this.code(), typed_name: this.typedName().trim() }
      : { action, code: this.code(), reason: this.reason().trim() || null };
    this.post(body, () => this.load(this.token(), 'done'));
  }

  private path(): string {
    return `/api/v1/esign/sign/${encodeURIComponent(this.token())}`;
  }

  private post(body: object, then: () => void): void {
    this.error.set(null);
    this.stage.set('working');
    this.api.post<SignerActionDone>(this.path(), body).pipe(
      catchError((e: unknown) => {
        this.error.set(this.lang.errorText(e as ApiError));
        return of(null);
      }),
    ).subscribe(done => {
      this.stage.set('ready');
      if (done) then();
    });
  }

  private load(token: string, after: Stage = 'ready'): void {
    this.api.get<SignerView>(`/api/v1/esign/sign/${encodeURIComponent(token)}`).pipe(
      catchError(() => of(null)),
    ).subscribe(view => {
      if (!view) {
        this.stage.set('invalid');
        return;
      }
      this.view.set(view);
      this.stage.set(after);
    });
  }
}
