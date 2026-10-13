import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal, untracked } from '@angular/core';
import { CommonModule } from '@angular/common';
import { EntityService } from '../services/entity.service';
import { RelatedGridComponent, RelatedGridFilter } from '../related-grid/related-grid.component';
import { ConsentAdminService } from './consent-admin.service';

interface ConsentPurposeRow {
  id: string;
  key: string;
  description: string | null;
}

interface ConsentEventRow {
  purpose_ref: string;
  status: string;
  subject_reference: string;
  created_at: string;
}

export interface PurposeStatus {
  purpose: ConsentPurposeRow;
  /** `null` when this subject has no `audit_consent` row for this purpose at all. */
  status: string | null;
  subjectReference: string | null;
}

/**
 * Drop-in "Consent" section for any record form (M24, D-428) — generic
 * across every entity, exactly like `CommunicationsPanelComponent`/
 * `NotesPanelComponent`: it links to its subject via the same polymorphic
 * `regarding_entity`/`regarding_id` pair `note` uses for `entity_name`/
 * `record_id`, not a per-entity lookup field.
 *
 * Two halves, deliberately split by what each is best at:
 * - The status summary above computes "is this purpose currently granted?"
 *   from the same append-only `audit_consent` timeline (latest row per
 *   `purpose_ref`, by `created_at` — a later withdrawal always supersedes an
 *   earlier grant, D-428) and offers the one action the generic entity
 *   engine cannot express: withdrawal, via the dedicated
 *   `POST /api/v1/consents/withdraw` (`ConsentAdminService`).
 * - The history grid below is an ordinary `RelatedGridComponent` over
 *   `audit_consent` with `allowCreate` — recording a new grant is just an
 *   ordinary entity create, same as any other related record, and
 *   `audit_consent` being append-only (no PATCH/DELETE surface on it at all)
 *   already keeps every past event immutable without this component doing
 *   anything special.
 */
@Component({
  selector: 'xrm-consent-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [CommonModule, RelatedGridComponent],
  styleUrls: ['./consent-panel.component.css'],
  templateUrl: './consent-panel.component.html',
})
export class ConsentPanelComponent {
  readonly entityName = input.required<string>();
  readonly recordId = input.required<string>();

  private readonly entityService = inject(EntityService);
  private readonly consentAdmin = inject(ConsentAdminService);

  readonly loading = signal(true);
  /** The `purpose.id` currently mid-withdrawal, or `null`. */
  readonly withdrawing = signal<string | null>(null);
  readonly errorMessage = signal<string | null>(null);

  private readonly purposes = signal<ConsentPurposeRow[]>([]);
  private readonly events = signal<ConsentEventRow[]>([]);

  readonly filters = computed<RelatedGridFilter[]>(() => [
    { field: 'regarding_entity', value: this.entityName() },
    { field: 'regarding_id', value: this.recordId() },
  ]);

  readonly statuses = computed<PurposeStatus[]>(() => {
    const events = this.events(); // sorted desc by created_at — see fetchEvents
    return this.purposes().map(purpose => {
      const latest = events.find(e => e.purpose_ref === purpose.id) ?? null;
      return {
        purpose,
        status: latest?.status ?? null,
        subjectReference: latest?.subject_reference ?? null,
      };
    });
  });

  constructor() {
    effect(() => {
      const e = this.entityName();
      const r = this.recordId();
      untracked(() => {
        if (e && r) this.load();
      });
    });
  }

  load(): void {
    this.loading.set(true);
    this.errorMessage.set(null);
    this.entityService.list('audit_consent_purpose', { limit: 100 }).subscribe({
      next: res => {
        this.purposes.set(res.data.map(item => {
          const raw = item.data as Record<string, unknown>;
          return {
            id: item.id,
            key: String(raw['key'] || ''),
            description: (raw['description'] as string | undefined) ?? null,
          };
        }));
        this.fetchEvents();
      },
      error: err => {
        this.loading.set(false);
        this.errorMessage.set(err?.message || 'Failed to load consent purposes.');
      },
    });
  }

  private fetchEvents(): void {
    this.entityService.list('audit_consent', {
      filters: [
        { field: 'regarding_entity', op: 'eq', value: this.entityName() },
        { field: 'regarding_id', op: 'eq', value: this.recordId() },
      ],
      sorts: [{ field: 'created_at', dir: 'desc' }],
      limit: 200,
    }).subscribe({
      next: res => {
        this.events.set(res.data.map(item => {
          const raw = item.data as Record<string, unknown>;
          return {
            purpose_ref: String(raw['purpose_ref'] || ''),
            status: String(raw['status'] || ''),
            subject_reference: String(raw['subject_reference'] || ''),
            created_at: item.created_at || '',
          };
        }));
        this.loading.set(false);
      },
      error: err => {
        this.loading.set(false);
        this.errorMessage.set(err?.message || 'Failed to load consent history.');
      },
    });
  }

  withdraw(entry: PurposeStatus): void {
    if (!entry.subjectReference || entry.status !== 'granted') return;
    this.withdrawing.set(entry.purpose.id);
    this.errorMessage.set(null);
    this.consentAdmin.withdraw({
      purpose_key: entry.purpose.key,
      subject_reference: entry.subjectReference,
      regarding_entity: this.entityName(),
      regarding_id: this.recordId(),
    }).subscribe({
      next: () => {
        this.withdrawing.set(null);
        this.fetchEvents();
      },
      error: err => {
        this.withdrawing.set(null);
        this.errorMessage.set(err?.message || 'Failed to withdraw consent.');
      },
    });
  }
}
