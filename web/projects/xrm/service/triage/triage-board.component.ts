import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { ApiError, TranslatePipe } from '@attome/base';

import {
  ConversionMapOption,
  ServiceAdminService,
  TRIAGE_STATUSES,
  TriageItem,
  triageColumns,
} from '../services/service-admin.service';

/**
 * G2-T4: the triage board. Work requests in columns by status (new,
 * triaged, converted, rejected); a new request can be accepted (moved to
 * triaged) or rejected, and a new or triaged one converted with a
 * conversion map (G2-T3). Status changes go through the generic record API
 * against the request's version, so a request someone else changed first
 * answers a conflict and the board reloads.
 */
@Component({
  selector: 'attome-service-triage-board',
  standalone: true,
  imports: [TranslatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls: ['../../styles/admin-page.css', './triage-board.component.css'],
  templateUrl: './triage-board.component.html',
})
export class TriageBoardComponent implements OnInit {
  private readonly svc = inject(ServiceAdminService);

  readonly statuses = TRIAGE_STATUSES;
  readonly items = signal<TriageItem[]>([]);
  readonly maps = signal<ConversionMapOption[]>([]);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  /** The request an action is running for. */
  readonly busy = signal<string | null>(null);
  /** The map chosen per request, for converting. */
  readonly chosenMap = signal<Record<string, string>>({});

  readonly columns = computed(() => triageColumns(this.items()));

  ngOnInit(): void {
    this.reload();
    this.svc.listConversionMaps().subscribe({
      next: maps => this.maps.set(maps),
      // A deployment without conversion maps still triages.
      error: () => this.maps.set([]),
    });
  }

  reload(): void {
    this.loading.set(true);
    this.svc.listWorkRequests().subscribe({
      next: items => {
        this.items.set(items);
        this.loading.set(false);
        this.error.set(null);
      },
      error: (e: ApiError) => {
        this.error.set(e.message);
        this.loading.set(false);
      },
    });
  }

  canAccept(item: TriageItem): boolean {
    return item.status === 'new';
  }

  canReject(item: TriageItem): boolean {
    return item.status === 'new' || item.status === 'triaged';
  }

  canConvert(item: TriageItem): boolean {
    return (item.status === 'new' || item.status === 'triaged') && this.maps().length > 0;
  }

  chooseMap(item: TriageItem, mapId: string): void {
    this.chosenMap.update(chosen => ({ ...chosen, [item.id]: mapId }));
  }

  accept(item: TriageItem): void {
    this.run(item, this.svc.setWorkRequestStatus(item, 'triaged'));
  }

  reject(item: TriageItem): void {
    this.run(item, this.svc.setWorkRequestStatus(item, 'rejected'));
  }

  convert(item: TriageItem): void {
    const mapId = this.chosenMap()[item.id] ?? this.maps()[0]?.id;
    if (!mapId) return;
    this.run(item, this.svc.convertWorkRequest(item.id, mapId));
  }

  private run(item: TriageItem, action: ReturnType<ServiceAdminService['convertWorkRequest']>): void {
    this.busy.set(item.id);
    action.subscribe({
      next: () => {
        this.busy.set(null);
        this.reload();
      },
      error: (e: ApiError) => {
        this.busy.set(null);
        this.error.set(e.message);
        this.reload();
      },
    });
  }
}
