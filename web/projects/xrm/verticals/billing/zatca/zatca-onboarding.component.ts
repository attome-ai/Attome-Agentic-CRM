import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { ApiError, ApiService, LangService, TranslatePipe } from '@attome/base';

/** `attome_einvoice::device::DeviceSummary`. */
export interface EinvoiceDevice {
  id: string;
  name: string;
  environment: 'sandbox' | 'simulation' | 'production' | string;
  status: 'new' | 'compliance' | 'active' | 'failed' | 'retired' | string;
  egs_serial: string;
  invoice_types: string;
  last_icv: number;
  has_production_csid: boolean;
  last_error: string | null;
}

/** What creating a device sends. */
export interface NewEinvoiceDevice {
  name: string;
  environment: string;
  organization_unit: string;
  location: string;
  industry: string;
  invoice_types: string;
}

/** Whether a device may be onboarded with an OTP now. */
export function canOnboard(device: EinvoiceDevice): boolean {
  return device.status === 'new' || device.status === 'failed';
}

/**
 * ZATCA e-invoicing devices (roadmap AG2-T4): the devices with their state,
 * a form to add one (its key and certificate request are made on the
 * server), and onboarding with the OTP the Fatoora portal shows. A failed
 * step shows ZATCA's reason and can be tried again with a new OTP. Text
 * from the catalogue, logical CSS only, the page in the language's
 * direction.
 */
@Component({
  selector: 'xrm-zatca-onboarding',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <section class="zob" [attr.dir]="dir()" aria-labelledby="zob-title">
      <h2 id="zob-title">{{ 'zatcaOnboarding.title' | translate }}</h2>
      <p class="zob-muted">{{ 'zatcaOnboarding.intro' | translate }}</p>
      @if (error(); as message) { <p class="zob-error" role="alert">{{ message }}</p> }

      <ul class="zob-list">
        @for (device of devices(); track device.id) {
          <li [attr.data-device]="device.id">
            <div class="zob-head">
              <strong>{{ device.name }}</strong>
              <span class="zob-badge" [attr.data-status]="device.status">{{ 'zatcaOnboarding.status.' + device.status | translate }}</span>
              <small>{{ 'zatcaOnboarding.environment.' + device.environment | translate }}</small>
              <small>{{ 'zatcaOnboarding.documents' | translate: { count: device.last_icv } }}</small>
            </div>
            @if (device.last_error) { <p class="zob-error">{{ device.last_error }}</p> }
            @if (canOnboard(device)) {
              <form class="zob-otp" (submit)="$event.preventDefault(); onboard(device)">
                <label>{{ 'zatcaOnboarding.otp' | translate }}
                  <input inputmode="numeric" autocomplete="one-time-code" maxlength="12"
                         [value]="otp()[device.id] ?? ''" (input)="setOtp(device.id, $event)">
                </label>
                <button type="submit" [disabled]="busy() || !(otp()[device.id] ?? '').trim()">{{ 'zatcaOnboarding.onboard' | translate }}</button>
              </form>
            }
          </li>
        } @empty {
          <li class="zob-muted">{{ 'zatcaOnboarding.none' | translate }}</li>
        }
      </ul>

      <form class="zob-new" (submit)="$event.preventDefault(); create()">
        <h3>{{ 'zatcaOnboarding.add' | translate }}</h3>
        <label>{{ 'zatcaOnboarding.name' | translate }}
          <input required maxlength="64" [value]="draft().name" (input)="edit('name', $event)">
        </label>
        <label>{{ 'zatcaOnboarding.environmentLabel' | translate }}
          <select [value]="draft().environment" (change)="edit('environment', $event)">
            <option value="sandbox">{{ 'zatcaOnboarding.environment.sandbox' | translate }}</option>
            <option value="simulation">{{ 'zatcaOnboarding.environment.simulation' | translate }}</option>
            <option value="production">{{ 'zatcaOnboarding.environment.production' | translate }}</option>
          </select>
        </label>
        <label>{{ 'zatcaOnboarding.unit' | translate }}
          <input required [value]="draft().organization_unit" (input)="edit('organization_unit', $event)">
        </label>
        <label>{{ 'zatcaOnboarding.location' | translate }}
          <input required [value]="draft().location" (input)="edit('location', $event)">
        </label>
        <label>{{ 'zatcaOnboarding.industry' | translate }}
          <input required [value]="draft().industry" (input)="edit('industry', $event)">
        </label>
        <label>{{ 'zatcaOnboarding.types' | translate }}
          <select [value]="draft().invoice_types" (change)="edit('invoice_types', $event)">
            <option value="1100">{{ 'zatcaOnboarding.typesBoth' | translate }}</option>
            <option value="1000">{{ 'zatcaOnboarding.typesStandard' | translate }}</option>
            <option value="0100">{{ 'zatcaOnboarding.typesSimplified' | translate }}</option>
          </select>
        </label>
        <button type="submit" [disabled]="busy() || !ready()">{{ 'zatcaOnboarding.create' | translate }}</button>
      </form>
    </section>
  `,
  styles: [`
    :host { display: block; padding-block: 1rem; padding-inline: 1rem; }
    .zob { display: flex; flex-direction: column; gap: 1rem; max-inline-size: 56rem; }
    .zob h2 { margin-block: 0; font-size: 1.125rem; }
    .zob-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.5rem; }
    .zob-list li { padding-block: 0.5rem; border-block-end: 1px solid var(--color-border); }
    .zob-head { display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: center; }
    .zob-badge { padding-inline: 0.5rem; border-radius: 0.75rem; background: var(--color-surface-alt, transparent); font-size: 0.75rem; }
    .zob-badge[data-status="active"] { color: var(--color-success); }
    .zob-badge[data-status="failed"] { color: var(--color-danger); }
    .zob-otp, .zob-new { display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: end; }
    .zob-new h3 { flex-basis: 100%; margin-block: 0; font-size: 1rem; }
    label { display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.8125rem; }
    .zob-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .zob-error { color: var(--color-danger); }
  `],
})
export class ZatcaOnboardingComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);

  readonly devices = signal<EinvoiceDevice[]>([]);
  readonly error = signal<string | null>(null);
  readonly busy = signal(false);
  readonly otp = signal<Record<string, string>>({});
  readonly draft = signal<NewEinvoiceDevice>({
    name: '', environment: 'sandbox', organization_unit: '', location: '', industry: '', invoice_types: '1100',
  });

  readonly dir = computed(() => (this.lang.isRtl() ? 'rtl' : 'ltr'));
  readonly ready = computed(() => {
    const d = this.draft();
    return [d.name, d.organization_unit, d.location, d.industry].every(v => v.trim().length > 0);
  });
  readonly canOnboard = canOnboard;

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.api.get<{ items: EinvoiceDevice[] }>('/api/v1/einvoice/devices').subscribe({
      next: page => this.devices.set(page.items),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  edit(field: keyof NewEinvoiceDevice, event: Event): void {
    const value = (event.target as HTMLInputElement | HTMLSelectElement).value;
    this.draft.update(d => ({ ...d, [field]: value }));
  }

  setOtp(id: string, event: Event): void {
    const value = (event.target as HTMLInputElement).value.replace(/\D/g, '');
    this.otp.update(o => ({ ...o, [id]: value }));
  }

  create(): void {
    if (!this.ready()) return;
    this.busy.set(true);
    this.error.set(null);
    this.api.post<EinvoiceDevice>('/api/v1/einvoice/devices', this.draft()).subscribe({
      next: () => {
        this.busy.set(false);
        this.draft.update(d => ({ ...d, name: '' }));
        this.load();
      },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  onboard(device: EinvoiceDevice): void {
    const otp = (this.otp()[device.id] ?? '').trim();
    if (!otp) return;
    this.busy.set(true);
    this.error.set(null);
    this.api.post<EinvoiceDevice>(`/api/v1/einvoice/devices/${encodeURIComponent(device.id)}/onboard`, { otp }).subscribe({
      next: () => {
        this.busy.set(false);
        this.otp.update(o => ({ ...o, [device.id]: '' }));
        this.load();
      },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); this.load(); },
    });
  }
}
