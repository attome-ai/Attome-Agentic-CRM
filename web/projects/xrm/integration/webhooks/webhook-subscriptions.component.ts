import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, ApiService, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';

/** `attome_events::admin::SubscriptionListItem`. */
export interface SubscriptionItem {
  id: string;
  name: string;
  kind: string;
  is_active: boolean;
  target_url: string | null;
  owner_ref: string;
  created_at: string;
}

/** `attome_events::admin::SubscriptionDetail` (the fields this screen edits). */
export interface SubscriptionDetail extends SubscriptionItem {
  payload_shape: 'id' | 'changes' | 'full';
  ordered: boolean;
  paused_at: string | null;
  paused_reason: string | null;
  target_auth_header: string | null;
  row_version: number;
}

/** `attome_events::admin::DeliveryListItem`. */
export interface DeliveryItem {
  id: string;
  event_id: string;
  event_entity_logicalname: string;
  event_operation: string;
  status: string;
  attempts: number;
  last_error: string | null;
  response_status: number | null;
  last_attempted_at: string | null;
  created_at: string;
}

/** `SubscriptionCreatedResponse`: the secret, shown once. */
export interface CreatedSubscription {
  id: string;
  webhook_secret: string;
  webhook_secret_standard: string;
}

/** A draft as the form holds it. */
export interface SubscriptionDraft {
  name: string;
  target_url: string;
  owner_ref: string;
  payload_shape: 'id' | 'changes' | 'full';
  ordered: boolean;
  is_active: boolean;
}

export const PAYLOAD_SHAPES = ['full', 'changes', 'id'] as const;

/** The create body for a draft; `null` when a required field is missing. */
export function createBody(d: SubscriptionDraft): Record<string, unknown> | null {
  if (!d.name.trim() || !/^https?:\/\//.test(d.target_url.trim()) || !d.owner_ref.trim()) return null;
  return {
    name: d.name.trim(), kind: 'webhook', target_url: d.target_url.trim(), owner_ref: d.owner_ref.trim(),
    payload_shape: d.payload_shape, ordered: d.ordered,
  };
}

/** A `datetime-local` value as the UTC instant the replay route takes. */
export function replayFrom(local: string): string | null {
  if (!local) return null;
  const at = new Date(local);
  return Number.isNaN(at.getTime()) ? null : at.toISOString();
}

const BASE = '/api/v1/admin/events/subscriptions';

function emptyDraft(): SubscriptionDraft {
  return { name: '', target_url: '', owner_ref: '', payload_shape: 'full', ordered: false, is_active: true };
}

/**
 * Webhook subscriptions (roadmap M13-T4): create and edit subscriptions,
 * send a test event, read each delivery attempt, and send again everything
 * since a time. The signing secret is shown once, at creation. Logical CSS
 * only.
 */
@Component({
  selector: 'xrm-webhook-subscriptions',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, LocalDatePipe, TranslatePipe],
  template: `
    <section class="wh">
      <div class="wh-head">
        <h3>{{ 'webhooksPage.title' | translate }}</h3>
        <button type="button" (click)="startNew()">{{ 'webhooksPage.new' | translate }}</button>
      </div>
      <p class="wh-muted">{{ 'webhooksPage.intro' | translate }}</p>
      @if (error(); as message) { <p class="wh-error" role="alert">{{ message }}</p> }
      @if (notice(); as message) { <p class="wh-muted" role="status">{{ message }}</p> }
      @if (created(); as c) {
        <div class="wh-secret" data-created>
          <p>{{ 'webhooksPage.secretOnce' | translate }}</p>
          <code dir="ltr">{{ c.webhook_secret }}</code>
          <code dir="ltr">{{ c.webhook_secret_standard }}</code>
          <button type="button" (click)="created.set(null)">{{ 'webhooksPage.dismiss' | translate }}</button>
        </div>
      }

      <div class="wh-grid">
        <ul class="wh-list">
          @for (s of items(); track s.id) {
            <li>
              <button type="button" class="wh-item" [class.wh-selected]="selected()?.id === s.id"
                      [attr.data-subscription]="s.id" (click)="select(s)">
                <span>{{ s.name }}</span>
                <span class="wh-muted" dir="ltr">{{ s.target_url }}</span>
                @if (!s.is_active) { <span class="wh-badge">{{ 'webhooksPage.inactive' | translate }}</span> }
              </button>
            </li>
          } @empty {
            <li class="wh-muted">{{ 'webhooksPage.none' | translate }}</li>
          }
        </ul>

        @if (editing()) {
          <form class="wh-form" (ngSubmit)="save()">
            <label>{{ 'webhooksPage.name' | translate }}
              <input name="name" [(ngModel)]="draft.name" required /></label>
            <label>{{ 'webhooksPage.targetUrl' | translate }}
              <input name="target_url" [(ngModel)]="draft.target_url" dir="ltr" required /></label>
            @if (!selected()) {
              <label>{{ 'webhooksPage.owner' | translate }}
                <input name="owner_ref" [(ngModel)]="draft.owner_ref" dir="ltr" required /></label>
            }
            <label>{{ 'webhooksPage.shape' | translate }}
              <select name="payload_shape" [(ngModel)]="draft.payload_shape">
                @for (shape of shapes; track shape) {
                  <option [value]="shape">{{ 'webhooksPage.shapes.' + shape | translate }}</option>
                }
              </select></label>
            <label><input type="checkbox" name="ordered" [(ngModel)]="draft.ordered" />
              {{ 'webhooksPage.ordered' | translate }}</label>
            @if (selected()) {
              <label><input type="checkbox" name="is_active" [(ngModel)]="draft.is_active" />
                {{ 'webhooksPage.active' | translate }}</label>
            }
            <div class="wh-actions">
              <button type="submit" [disabled]="busy()">{{ 'webhooksPage.save' | translate }}</button>
              <button type="button" (click)="editing.set(false)">{{ 'webhooksPage.cancel' | translate }}</button>
            </div>
          </form>
        } @else if (selected(); as s) {
          <div class="wh-detail" data-detail>
            <h4>{{ s.name }}</h4>
            <p class="wh-muted" dir="ltr">{{ s.target_url }}</p>
            <p>{{ 'webhooksPage.shapes.' + s.payload_shape | translate }}
              @if (s.ordered) { · {{ 'webhooksPage.ordered' | translate }} }</p>
            @if (s.paused_at) {
              <p class="wh-error">{{ 'webhooksPage.paused' | translate }} {{ s.paused_at | localDate }} — {{ s.paused_reason }}</p>
            }
            <div class="wh-actions">
              <button type="button" (click)="edit()">{{ 'webhooksPage.edit' | translate }}</button>
              <button type="button" (click)="sendTest()" [disabled]="busy()">{{ 'webhooksPage.test' | translate }}</button>
              <label>{{ 'webhooksPage.replayFrom' | translate }}
                <input type="datetime-local" name="replay" [(ngModel)]="replayAt" /></label>
              <button type="button" (click)="replay()" [disabled]="busy() || !replayAt">{{ 'webhooksPage.replay' | translate }}</button>
            </div>
            <h4>{{ 'webhooksPage.log' | translate }}</h4>
            <table class="wh-table">
              <thead>
                <tr>
                  <th scope="col">{{ 'webhooksPage.when' | translate }}</th>
                  <th scope="col">{{ 'webhooksPage.event' | translate }}</th>
                  <th scope="col">{{ 'webhooksPage.status' | translate }}</th>
                  <th scope="col">{{ 'webhooksPage.attempts' | translate }}</th>
                  <th scope="col">{{ 'webhooksPage.lastError' | translate }}</th>
                </tr>
              </thead>
              <tbody>
                @for (d of deliveries(); track d.id) {
                  <tr [attr.data-delivery]="d.id">
                    <td>{{ (d.last_attempted_at ?? d.created_at) | localDate }}</td>
                    <td dir="ltr">{{ d.event_entity_logicalname }} · {{ d.event_operation }}</td>
                    <td>{{ d.status }} @if (d.response_status) { ({{ d.response_status }}) }</td>
                    <td>{{ d.attempts }}</td>
                    <td class="wh-muted">{{ d.last_error ?? '' }}</td>
                  </tr>
                } @empty {
                  <tr><td colspan="5" class="wh-muted">{{ 'webhooksPage.noDeliveries' | translate }}</td></tr>
                }
              </tbody>
            </table>
          </div>
        }
      </div>
    </section>
  `,
  styles: [`
    :host { display: block; }
    .wh { display: flex; flex-direction: column; gap: 0.5rem; }
    .wh-head { display: flex; justify-content: space-between; align-items: center; gap: 0.5rem; }
    .wh h3 { margin-block: 0; font-size: 1rem; }
    .wh-grid { display: grid; grid-template-columns: minmax(12rem, 1fr) 3fr; gap: 1rem; }
    .wh-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.25rem; }
    .wh-item { inline-size: 100%; text-align: start; display: flex; flex-direction: column; gap: 0.125rem;
      padding: 0.375rem; border: 1px solid var(--color-border); background: none; cursor: pointer; }
    .wh-selected { border-color: var(--color-primary); }
    .wh-form, .wh-detail { display: flex; flex-direction: column; gap: 0.5rem; }
    .wh-form label { display: flex; flex-direction: column; gap: 0.125rem; }
    .wh-actions { display: flex; flex-wrap: wrap; gap: 0.375rem; align-items: end; }
    .wh-table { inline-size: 100%; border-collapse: collapse; font-size: 0.8125rem; }
    .wh-table th, .wh-table td { text-align: start; padding: 0.25rem 0.5rem; border-block-end: 1px solid var(--color-border); }
    .wh-secret { display: flex; flex-direction: column; gap: 0.25rem; padding: 0.5rem; border: 1px solid var(--color-border); }
    .wh-badge { font-size: 0.75rem; color: var(--color-text-secondary); }
    .wh-muted { color: var(--color-text-secondary); font-size: 0.8125rem; overflow-wrap: anywhere; }
    .wh-error { color: var(--color-danger); }
  `],
})
export class WebhookSubscriptionsComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);

  readonly shapes = PAYLOAD_SHAPES;
  readonly items = signal<SubscriptionItem[]>([]);
  readonly selected = signal<SubscriptionDetail | null>(null);
  readonly deliveries = signal<DeliveryItem[]>([]);
  readonly created = signal<CreatedSubscription | null>(null);
  readonly editing = signal(false);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  readonly notice = signal<string | null>(null);
  draft: SubscriptionDraft = emptyDraft();
  replayAt = '';

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.api.get<{ items: SubscriptionItem[] }>(BASE, { kind: 'webhook', page_size: '200' }).subscribe({
      next: page => this.items.set(page.items),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  select(item: SubscriptionItem): void {
    this.editing.set(false);
    this.error.set(null);
    this.api.get<SubscriptionDetail>(`${BASE}/${item.id}`).subscribe({
      next: detail => this.selected.set(detail),
      error: (e: ApiError) => this.error.set(e.message),
    });
    this.loadDeliveries(item.id);
  }

  private loadDeliveries(id: string): void {
    this.api.get<{ items: DeliveryItem[] }>(`${BASE}/${id}/deliveries`, { page_size: '50' }).subscribe({
      next: page => this.deliveries.set(page.items),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  startNew(): void {
    this.selected.set(null);
    this.draft = emptyDraft();
    this.editing.set(true);
  }

  edit(): void {
    const s = this.selected();
    if (!s) return;
    this.draft = {
      name: s.name, target_url: s.target_url ?? '', owner_ref: s.owner_ref,
      payload_shape: s.payload_shape, ordered: s.ordered, is_active: s.is_active,
    };
    this.editing.set(true);
  }

  save(): void {
    const current = this.selected();
    this.error.set(null);
    if (!current) {
      const body = createBody(this.draft);
      if (!body) {
        this.error.set(this.lang.translate('webhooksPage.required'));
        return;
      }
      this.busy.set(true);
      this.api.post<CreatedSubscription>(BASE, body).subscribe({
        next: created => {
          this.busy.set(false);
          this.editing.set(false);
          this.created.set(created);
          this.load();
        },
        error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
      });
      return;
    }
    this.busy.set(true);
    this.api.patch<SubscriptionDetail>(`${BASE}/${current.id}`, {
      name: this.draft.name, target_url: this.draft.target_url, is_active: this.draft.is_active,
      payload_shape: this.draft.payload_shape, ordered: this.draft.ordered, row_version: current.row_version,
    }).subscribe({
      next: detail => {
        this.busy.set(false);
        this.editing.set(false);
        this.selected.set(detail);
        this.load();
      },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  sendTest(): void {
    const s = this.selected();
    if (!s) return;
    this.busy.set(true);
    this.api.post<{ queued: number }>(`${BASE}/${s.id}/test`, {}).subscribe({
      next: () => { this.busy.set(false); this.loadDeliveries(s.id); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  replay(): void {
    const s = this.selected();
    const from = replayFrom(this.replayAt);
    if (!s || !from) return;
    this.busy.set(true);
    this.api.post<{ queued: number }>(`${BASE}/${s.id}/replay`, { from }).subscribe({
      next: result => {
        this.busy.set(false);
        this.notice.set(this.lang.translate('webhooksPage.replayed', { count: result.queued }));
        this.loadDeliveries(s.id);
      },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }
}
