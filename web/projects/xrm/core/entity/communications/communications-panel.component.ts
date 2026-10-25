import {
  ChangeDetectionStrategy, Component, DestroyRef, computed, effect, inject, input, signal, untracked,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Router } from '@angular/router';
import { LocalDatePipe, TranslatePipe } from '@attome/base';

import { EntityService } from '../services/entity.service';
import { EmailComposerComponent } from './email-composer.component';
import { entityFormRoute } from '../services/entity-url.utils';

/** One message as the panel shows it: only what a reader scans for. */
export interface CommunicationRow {
  id: string;
  channel: string;
  direction: string | null;
  /** The subject, or the start of the body when there is none. */
  title: string;
  /** The receiver(s): `to_addresses`. */
  to: string;
  status: string | null;
  sentAt: string | null;
}

const PAGE_SIZE = 25;
const PREVIEW_CHARS = 90;

const CHANNEL_ICONS: Record<string, string> = {
  email: 'las la-envelope',
  internal: 'las la-comment',
  web_chat: 'las la-comments',
  portal: 'las la-globe',
  call: 'las la-phone',
  meeting: 'las la-calendar',
};

/**
 * Drop-in "Communications" section for any record form. Lists the
 * \`communication\` rows attached to this record (the polymorphic
 * \`entity_name\`/\`record_id\` pair \`note\` also uses), newest first, as a
 * compact message list: channel, direction, subject (or a body preview),
 * recipients, date and status. The generic grid printed every column,
 * including ones that are the same on every row here (\`entity_name\`,
 * \`record_id\`) and threading internals (\`thread_id\`, \`message_id\`,
 * \`references_header\`); the full message is one click away on its own
 * form. Renders nothing until a record exists, and hides itself on
 * \`communication\`'s own form.
 */
@Component({
  selector: 'xrm-communications-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe, LocalDatePipe, EmailComposerComponent],
  templateUrl: './communications-panel.component.html',
  styleUrl: './communications-panel.component.css',
})
export class CommunicationsPanelComponent {
  private readonly entities = inject(EntityService);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);

  readonly entityName = input.required<string>();
  readonly recordId   = input<string | null>(null);

  private static readonly SELF_ENTITY = 'communication';

  readonly rows = signal<CommunicationRow[]>([]);
  readonly total = signal(0);
  readonly loading = signal(false);
  readonly failed = signal(false);
  /** J1-T2: the email composer is open. */
  readonly composing = signal(false);

  readonly enabled = computed(() =>
    !!this.recordId() && this.entityName() !== CommunicationsPanelComponent.SELF_ENTITY);

  constructor() {
    effect(() => {
      const entity = this.entityName();
      const id = this.recordId();
      if (!this.enabled() || !id) return;
      untracked(() => this.load(entity, id));
    });
  }

  /** J1-T2: an email went out; the list shows it. */
  onSent(): void {
    this.composing.set(false);
    const id = this.recordId();
    if (id) this.load(this.entityName(), id);
  }

  channelIcon(channel: string): string {
    return CHANNEL_ICONS[channel] ?? 'las la-comment-dots';
  }

  open(row: CommunicationRow): void {
    void this.router.navigate(entityFormRoute(CommunicationsPanelComponent.SELF_ENTITY), {
      queryParams: { id: row.id },
    });
  }

  private load(entity: string, id: string): void {
    this.loading.set(true);
    this.failed.set(false);
    this.entities.list(CommunicationsPanelComponent.SELF_ENTITY, {
      filters: [
        { field: 'entity_name', op: 'eq', value: entity },
        { field: 'record_id', op: 'eq', value: id },
      ],
      sorts: [{ field: 'sent_at', dir: 'desc' }],
      limit: PAGE_SIZE,
    }).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: res => {
        this.rows.set(res.data.map(r => toRow(r.id, r.data as Record<string, unknown>)));
        this.total.set(res.meta.total);
        this.loading.set(false);
      },
      error: () => {
        this.failed.set(true);
        this.loading.set(false);
      },
    });
  }
}

function text(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

export function toRow(id: string, d: Record<string, unknown>): CommunicationRow {
  const subject = text(d['subject']);
  const body = text(d['body'])?.replace(/\s+/g, ' ') ?? '';
  const preview = body.length > PREVIEW_CHARS ? body.slice(0, PREVIEW_CHARS) + '…' : body;
  const direction = text(d['direction']);
  return {
    id,
    channel: text(d['channel']) ?? 'other',
    direction,
    title: subject ?? preview,
    to: text(d['to_addresses']) ?? '',
    status: text(d['status']),
    sentAt: text(d['sent_at']) ?? text(d['created_at']),
  };
}
