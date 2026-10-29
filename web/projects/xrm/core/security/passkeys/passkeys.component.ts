import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import {
  ApiError, ApiService, LangService, LocalDatePipe, PASSKEY_BROWSER, TranslatePipe, isPasskeyCancelled,
} from '@attome/base';
import { ConfirmService } from '@attome/base/dialog';
import { StepUpService } from '@attome/base/step-up';
import { firstValueFrom } from 'rxjs';

/** One of the caller's passkeys (`GET /api/v1/auth/passkeys`, Q6-T1). */
export interface MyPasskey {
  id: string;
  label: string | null;
  transports: string[];
  created_at: string;
  last_used_at: string | null;
}

interface PasskeyPage {
  items: MyPasskey[];
  total: number;
  page: number;
  page_size: number;
}

/** The step-up operation adding or removing a passkey needs. */
export const PASSKEY_MANAGE = 'passkey_manage';

/**
 * Q6-T2: the person's own passkeys: the list, adding one (named, through the
 * browser's passkey prompt) and removing one. Both changes need a fresh
 * step-up, which `StepUpService.run` asks for when the server says so.
 */
@Component({
  selector: 'xrm-passkeys',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, TranslatePipe],
  styleUrls: ['../../../styles/admin-page.css'],
  template: `
    <section class="card" aria-labelledby="passkeys-title">
      <h2 id="passkeys-title">{{ 'passkeys.title' | translate }}</h2>
      <p class="subtitle">{{ 'passkeys.subtitle' | translate }}</p>
      @if (error(); as message) { <p class="error-msg" role="alert">{{ message }}</p> }
      @if (notice(); as message) { <p class="state-msg" role="status">{{ message }}</p> }

      @if (loading()) {
        <p class="state-msg">{{ 'passkeys.loading' | translate }}</p>
      } @else if (passkeys().length === 0) {
        <p class="state-msg" data-testid="passkeys-empty">{{ 'passkeys.empty' | translate }}</p>
      } @else {
        <table class="data-table">
          <thead>
            <tr>
              <th scope="col">{{ 'passkeys.colName' | translate }}</th>
              <th scope="col">{{ 'passkeys.colAdded' | translate }}</th>
              <th scope="col">{{ 'passkeys.colLastUsed' | translate }}</th>
              <th scope="col"><span class="sr-only">{{ 'passkeys.colActions' | translate }}</span></th>
            </tr>
          </thead>
          <tbody>
            @for (p of passkeys(); track p.id) {
              <tr data-testid="passkey-row">
                <td>{{ p.label || ('passkeys.unnamed' | translate) }}</td>
                <td>{{ p.created_at | localDate: { dateStyle: 'medium', timeStyle: 'short' } }}</td>
                <td>{{ p.last_used_at ? (p.last_used_at | localDate: { dateStyle: 'medium', timeStyle: 'short' }) : ('passkeys.never' | translate) }}</td>
                <td>
                  <button type="button" class="btn-ghost" [disabled]="busy()" (click)="remove(p)"
                          [attr.aria-label]="('passkeys.remove' | translate) + ' ' + (p.label || '')">
                    <i class="las la-trash" aria-hidden="true"></i> {{ 'passkeys.remove' | translate }}
                  </button>
                </td>
              </tr>
            }
          </tbody>
        </table>
      }

      @if (supported) {
        <div class="field">
          <label for="passkey-label">{{ 'passkeys.label' | translate }}</label>
          <input id="passkey-label" type="text" maxlength="100" [value]="label()"
                 [placeholder]="'passkeys.labelPlaceholder' | translate"
                 (input)="label.set($any($event.target).value)" />
        </div>
        <button type="button" class="btn-primary" [disabled]="busy()" (click)="add()" data-testid="passkey-add">
          <i class="las la-key" aria-hidden="true"></i> {{ 'passkeys.add' | translate }}
        </button>
      } @else {
        <p class="state-msg" data-testid="passkeys-unsupported">{{ 'passkeys.unsupported' | translate }}</p>
      }
    </section>
  `,
})
export class PasskeysComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);
  private readonly confirm = inject(ConfirmService);
  private readonly stepUp = inject(StepUpService);
  private readonly browser = inject(PASSKEY_BROWSER);

  readonly supported = this.browser.supported();
  readonly passkeys = signal<MyPasskey[]>([]);
  readonly loading = signal(true);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  readonly notice = signal<string | null>(null);
  readonly label = signal('');

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.loading.set(true);
    this.api.get<PasskeyPage>('/api/v1/auth/passkeys', { page_size: '200' }).subscribe({
      next: (page) => {
        this.passkeys.set(page.items);
        this.loading.set(false);
      },
      error: (e: ApiError) => {
        this.error.set(this.lang.errorText(e));
        this.loading.set(false);
      },
    });
  }

  /** Step up if needed, let the browser create the passkey, then store it. */
  async add(): Promise<void> {
    this.begin();
    try {
      const started = await firstValueFrom(this.stepUp.run(PASSKEY_MANAGE, () =>
        this.api.post<{ options: unknown }>('/api/v1/auth/passkeys/register/start', {})));
      const response = await this.browser.create(started.options);
      const label = this.label().trim();
      await firstValueFrom(this.api.post('/api/v1/auth/passkeys/register/finish', {
        ...(label ? { label } : {}),
        response,
      }));
      this.label.set('');
      this.notice.set(this.lang.translate('passkeys.added'));
      this.load();
    } catch (e) {
      this.fail(e);
    } finally {
      this.busy.set(false);
    }
  }

  async remove(passkey: MyPasskey): Promise<void> {
    const ok = await this.confirm.confirm({
      title: this.lang.translate('passkeys.remove'),
      message: this.lang.translate('passkeys.confirmRemove'),
      confirmText: this.lang.translate('passkeys.remove'),
      cancelText: this.lang.translate('passkeys.cancel'),
      variant: 'danger',
    });
    if (!ok) return;
    this.begin();
    try {
      await firstValueFrom(this.stepUp.run(PASSKEY_MANAGE, () =>
        this.api.delete(`/api/v1/auth/passkeys/${encodeURIComponent(passkey.id)}`)));
      this.notice.set(this.lang.translate('passkeys.removed'));
      this.load();
    } catch (e) {
      this.fail(e);
    } finally {
      this.busy.set(false);
    }
  }

  private begin(): void {
    this.busy.set(true);
    this.error.set(null);
    this.notice.set(null);
  }

  /** A cancelled browser prompt is not an error; anything else is shown. */
  private fail(e: unknown): void {
    if (isPasskeyCancelled(e)) return;
    const apiError = e as ApiError;
    this.error.set(apiError && typeof apiError === 'object' && 'kind' in apiError
      ? this.lang.errorText(apiError)
      : this.lang.translate('passkeys.failed'));
  }
}
