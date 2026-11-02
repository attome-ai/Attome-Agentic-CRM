import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, SdkService, AuthService, LocalDatePipe, TranslatePipe } from '@attome/base';

/** `whatsapp_templates::WhatsAppNumber`. */
export interface WhatsAppNumber {
  id: string;
  name: string;
  phone_number_id: string | null;
  waba_id: string | null;
  templates: number;
  synced_at: string | null;
}

/** `whatsapp_templates::WhatsAppTemplate`. */
export interface WhatsAppTemplate {
  id: string;
  name: string;
  language: string;
  category: string;
  variables: string[];
  variable_map: Record<string, string>;
  synced_at: string;
  row_version: number;
}

/** `whatsapp_templates::SyncResult`. */
export interface SyncResult { added: number; updated: number; removed: number; }

/** A number to connect, as the form holds it. */
export interface NumberDraft {
  name: string;
  phone_number_id: string;
  waba_id: string;
  access_token: string;
  app_secret: string;
  verify_token: string;
  unknown_sender: 'lead' | 'contact' | 'none';
}

interface Page<T> { items: T[]; total: number; }

/** The integration-system body that connects `d`, run by `principal`. Pure. */
export function systemBody(d: NumberDraft, principal: string): Record<string, unknown> {
  const config = {
    social: 'whatsapp',
    phone_number_id: d.phone_number_id.trim(),
    waba_id: d.waba_id.trim(),
    verify_token: d.verify_token.trim(),
    inbound_key: crypto.randomUUID().replace(/-/g, ''),
    unknown_sender: d.unknown_sender,
  };
  return {
    name: d.name.trim(),
    kind: 'channel',
    base_url: 'https://graph.facebook.com',
    auth_type: 'api_key',
    service_principal_ref: principal,
    config: JSON.stringify(config),
    credential_value: JSON.stringify({ access_token: d.access_token, app_secret: d.app_secret }),
  };
}

const EMPTY: NumberDraft = {
  name: '', phone_number_id: '', waba_id: '', access_token: '', app_secret: '', verify_token: '',
  unknown_sender: 'lead',
};

/**
 * J5-T3 — WhatsApp numbers and their templates.
 *
 * - Connect a number: its Meta ids, access token and app secret (sealed by
 *   the server and never shown again) and the verify token Meta's webhook
 *   subscription checks; it is an integration system with
 *   `"social": "whatsapp"`.
 * - Sync a number's approved templates from Meta, then map each template
 *   variable to the attribute that fills it, saved under the template's row
 *   version.
 */
@Component({
  selector: 'xrm-whatsapp-setup',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, LocalDatePipe, TranslatePipe],
  styles: [`
    .wa { display: grid; gap: 1rem; }
    .wa-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr)); gap: .5rem; }
    .wa-row { display: flex; gap: .5rem; align-items: center; flex-wrap: wrap; }
    .wa-muted { color: var(--color-text-secondary); }
    table { inline-size: 100%; border-collapse: collapse; }
    td, th { text-align: start; padding-block: .25rem; padding-inline: .4rem; vertical-align: top; }
  `],
  template: `
    <section class="wa">
      <header>
        <h2>{{ 'whatsappSetup.title' | translate }}</h2>
        <p class="wa-muted">{{ 'whatsappSetup.subtitle' | translate }}</p>
      </header>
      @if (error(); as e) { <p role="alert">{{ e }}</p> }

      <form class="wa-grid" data-testid="wa-connect" (ngSubmit)="connect()">
        <label>{{ 'whatsappSetup.name' | translate }}<input name="name" [(ngModel)]="draft.name" required /></label>
        <label>{{ 'whatsappSetup.phoneNumberId' | translate }}<input name="pnid" dir="ltr" [(ngModel)]="draft.phone_number_id" required /></label>
        <label>{{ 'whatsappSetup.wabaId' | translate }}<input name="waba" dir="ltr" [(ngModel)]="draft.waba_id" required /></label>
        <label>{{ 'whatsappSetup.accessToken' | translate }}<input name="token" type="password" autocomplete="off" [(ngModel)]="draft.access_token" required /></label>
        <label>{{ 'whatsappSetup.appSecret' | translate }}<input name="secret" type="password" autocomplete="off" [(ngModel)]="draft.app_secret" required /></label>
        <label>{{ 'whatsappSetup.verifyToken' | translate }}<input name="verify" dir="ltr" [(ngModel)]="draft.verify_token" required /></label>
        <label>{{ 'whatsappSetup.unknownSender' | translate }}
          <select name="unknown" [(ngModel)]="draft.unknown_sender">
            <option value="lead">{{ 'whatsappSetup.unknown_lead' | translate }}</option>
            <option value="contact">{{ 'whatsappSetup.unknown_contact' | translate }}</option>
            <option value="none">{{ 'whatsappSetup.unknown_none' | translate }}</option>
          </select></label>
        <div class="wa-row"><button type="submit" [disabled]="busy()">{{ 'whatsappSetup.connect' | translate }}</button></div>
      </form>

      <table data-testid="wa-numbers">
        <thead><tr>
          <th>{{ 'whatsappSetup.name' | translate }}</th><th>{{ 'whatsappSetup.phoneNumberId' | translate }}</th>
          <th>{{ 'whatsappSetup.templates' | translate }}</th><th>{{ 'whatsappSetup.synced' | translate }}</th><th></th>
        </tr></thead>
        <tbody>
          @for (n of numbers(); track n.id) {
            <tr>
              <td>{{ n.name }}</td><td><bdi dir="ltr">{{ n.phone_number_id ?? '' }}</bdi></td>
              <td>{{ n.templates }}</td><td>{{ n.synced_at ? (n.synced_at | localDate) : '' }}</td>
              <td class="wa-row">
                <button type="button" data-testid="wa-sync" [disabled]="busy()" (click)="sync(n)">{{ 'whatsappSetup.sync' | translate }}</button>
                <button type="button" data-testid="wa-open" (click)="open(n)">{{ 'whatsappSetup.showTemplates' | translate }}</button>
              </td>
            </tr>
          } @empty {
            <tr><td colspan="5" class="wa-muted">{{ 'whatsappSetup.noNumbers' | translate }}</td></tr>
          }
        </tbody>
      </table>
      @if (synced(); as s) {
        <p role="status">{{ 'whatsappSetup.syncedSummary' | translate: { added: s.added, updated: s.updated, removed: s.removed } }}</p>
      }

      @if (selected(); as n) {
        <section data-testid="wa-templates">
          <h3>{{ 'whatsappSetup.templatesOf' | translate: { name: n.name } }}</h3>
          @for (t of templates(); track t.id) {
            <article>
              <h4><bdi dir="ltr">{{ t.name }}</bdi> · {{ t.language }} · {{ t.category }}</h4>
              @if (t.variables.length === 0) {
                <p class="wa-muted">{{ 'whatsappSetup.noVariables' | translate }}</p>
              } @else {
                <div class="wa-grid">
                  @for (v of t.variables; track v) {
                    <label><bdi dir="ltr">{{ v }}</bdi>
                      <input [name]="t.id + v" dir="ltr" [placeholder]="'whatsappSetup.attribute' | translate"
                             [ngModel]="t.variable_map[v] ?? ''" (ngModelChange)="setVar(t, v, $event)" /></label>
                  }
                </div>
                <div class="wa-row"><button type="button" data-testid="wa-save-map" (click)="saveMap(t)">{{ 'whatsappSetup.saveMap' | translate }}</button></div>
              }
            </article>
          } @empty {
            <p class="wa-muted">{{ 'whatsappSetup.noTemplates' | translate }}</p>
          }
        </section>
      }
    </section>
  `,
})
export class WhatsAppSetupComponent implements OnInit {
  private readonly sdk = inject(SdkService);
  private readonly auth = inject(AuthService);

  draft: NumberDraft = { ...EMPTY };
  readonly numbers = signal<WhatsAppNumber[]>([]);
  readonly selected = signal<WhatsAppNumber | null>(null);
  readonly templates = signal<WhatsAppTemplate[]>([]);
  readonly synced = signal<SyncResult | null>(null);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);

  ngOnInit(): void {
    this.load();
  }

  private load(): void {
    this.sdk.get<Page<WhatsAppNumber>>('/api/v1/admin/integrations/whatsapp/numbers').subscribe({
      next: p => this.numbers.set(p.items),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  connect(): void {
    const principal = this.auth.userId();
    if (!principal) return;
    this.busy.set(true);
    this.error.set(null);
    this.sdk.post('/api/v1/admin/integrations/systems', { body: systemBody(this.draft, principal) }).subscribe({
      next: () => { this.busy.set(false); this.draft = { ...EMPTY }; this.load(); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  sync(n: WhatsAppNumber): void {
    this.busy.set(true);
    this.error.set(null);
    this.sdk.post<SyncResult>(`/api/v1/admin/integrations/whatsapp/${n.id}/templates/sync`, { body: {} }).subscribe({
      next: r => { this.busy.set(false); this.synced.set(r); this.load(); this.open(n); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  open(n: WhatsAppNumber): void {
    this.selected.set(n);
    this.sdk.get<Page<WhatsAppTemplate>>(`/api/v1/admin/integrations/whatsapp/${n.id}/templates`).subscribe({
      next: p => this.templates.set(p.items),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  setVar(t: WhatsAppTemplate, variable: string, attribute: string): void {
    const kept = Object.entries(t.variable_map).filter(([key]) => key !== variable);
    const map: Record<string, string> = Object.fromEntries(
      attribute.trim() ? [...kept, [variable, attribute.trim()]] : kept,
    );
    this.templates.update(ts => ts.map(x => x.id === t.id ? { ...x, variable_map: map } : x));
  }

  saveMap(t: WhatsAppTemplate): void {
    const current = this.templates().find(x => x.id === t.id) ?? t;
    this.sdk.put<WhatsAppTemplate>(
      `/api/v1/admin/integrations/whatsapp/templates/${t.id}/variables`,
      { body: { variable_map: current.variable_map } },
      { ifMatch: current.row_version },
    ).subscribe({
      next: saved => this.templates.update(ts => ts.map(x => x.id === saved.id ? saved : x)),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }
}
