import {
  ChangeDetectionStrategy, Component, DestroyRef, Injectable, OnInit, computed, inject, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import type { Observable } from 'rxjs';
import { ApiService, LangService, LocalDatePipe, LocalNumberPipe, TranslatePipe } from '@attome/base';
import type { ApiError, Page } from '@attome/base';
import { ConfirmService } from '@attome/base/dialog';

/** One recorded metadata version (`GET /api/v1/admin/metadata/versions`). */
export interface MetadataVersion {
  version: number;
  published_at: string;
  published_by: string | null;
  current: boolean;
  nodes: number;
}

/** One node's switch to a version (`…/versions/{version}/nodes`). */
export interface NodeSwitch {
  node_id: string;
  switched_at: string;
}

/** What a switch or rollback moved the pointer from and to. */
export interface VersionSwitch {
  from: number | null;
  to: number;
}

const BASE = '/api/v1/admin/metadata';

/**
 * Y8-T4/T10/T12 — the metadata version routes
 * (`crates/engine/attome-api/src/model_admin.rs`): the recorded versions,
 * each one's node switches, and the rollback to the version before the
 * current one.
 */
@Injectable({ providedIn: 'root' })
export class MetadataVersionsService {
  private readonly api = inject(ApiService);

  list(page = 1, pageSize = 20): Observable<Page<MetadataVersion>> {
    return this.api.get<Page<MetadataVersion>>(`${BASE}/versions`, {
      page: String(page), page_size: String(pageSize),
    });
  }

  nodes(version: number): Observable<Page<NodeSwitch>> {
    return this.api.get<Page<NodeSwitch>>(`${BASE}/versions/${version}/nodes`, {
      page: '1', page_size: '100',
    });
  }

  rollback(): Observable<VersionSwitch> {
    return this.api.post<VersionSwitch>(`${BASE}/rollback`, {});
  }
}

/**
 * Y8-T12 — `/xrm/admin/metadata-versions`: the published metadata versions,
 * newest first, the current one marked, each with the nodes that switched to
 * it and when, and a Rollback button (after a confirmation) that points the
 * deployment back at the version before the current one; every node follows
 * on its next catch-up.
 */
@Component({
  selector: 'xrm-metadata-versions',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, LocalNumberPipe, TranslatePipe],
  styleUrls: ['../../../styles/admin-page.css', './metadata-versions.component.css'],
  templateUrl: './metadata-versions.component.html',
})
export class MetadataVersionsComponent implements OnInit {
  private readonly svc = inject(MetadataVersionsService);
  private readonly confirm = inject(ConfirmService);
  private readonly lang = inject(LangService);
  private readonly destroyRef = inject(DestroyRef);

  readonly dateFmt: Intl.DateTimeFormatOptions = { dateStyle: 'medium', timeStyle: 'medium' };
  readonly pageSize = 20;

  readonly versions = signal<MetadataVersion[]>([]);
  readonly total = signal(0);
  readonly page = signal(1);
  readonly loading = signal(true);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  readonly rolledBack = signal<VersionSwitch | null>(null);
  /** The version whose nodes are shown, and those nodes. */
  readonly opened = signal<number | null>(null);
  readonly nodes = signal<NodeSwitch[]>([]);
  readonly nodesLoading = signal(false);

  readonly pages = computed(() => Math.max(1, Math.ceil(this.total() / this.pageSize)));
  readonly current = computed(() => this.versions().find(v => v.current) ?? null);
  /** A rollback needs a current version with one recorded before it. */
  readonly canRollBack = computed(() => {
    const cur = this.current();
    return cur !== null && this.total() > 1 && !this.busy();
  });

  ngOnInit(): void {
    this.load();
  }

  previous(): void {
    if (this.page() <= 1 || this.loading()) return;
    this.page.update(p => p - 1);
    this.load();
  }

  next(): void {
    if (this.page() >= this.pages() || this.loading()) return;
    this.page.update(p => p + 1);
    this.load();
  }

  toggle(version: number): void {
    if (this.opened() === version) {
      this.opened.set(null);
      return;
    }
    this.opened.set(version);
    this.nodes.set([]);
    this.nodesLoading.set(true);
    this.svc.nodes(version).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: res => { this.nodes.set(res.items); this.nodesLoading.set(false); },
      error: (err: ApiError) => { this.nodesLoading.set(false); this.error.set(this.lang.errorText(err)); },
    });
  }

  async rollback(): Promise<void> {
    if (!this.canRollBack()) return;
    const ok = await this.confirm.confirm({
      title: this.lang.translate('metadataVersions.rollbackTitle'),
      message: this.lang.translate('metadataVersions.rollbackConfirm', {
        version: this.current()?.version ?? '',
      }),
      confirmText: this.lang.translate('metadataVersions.rollback'),
      cancelText: this.lang.translate('metadataVersions.cancel'),
      variant: 'warning',
    });
    if (!ok) return;
    this.busy.set(true);
    this.error.set(null);
    this.svc.rollback().pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: moved => {
        this.busy.set(false);
        this.rolledBack.set(moved);
        this.opened.set(null);
        this.load();
      },
      error: (err: ApiError) => {
        this.busy.set(false);
        this.error.set(this.lang.errorText(err));
      },
    });
  }

  private load(): void {
    this.loading.set(true);
    this.svc.list(this.page(), this.pageSize).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: res => {
        this.versions.set(res.items);
        this.total.set(res.total);
        this.loading.set(false);
      },
      error: (err: ApiError) => {
        this.loading.set(false);
        this.error.set(this.lang.errorText(err));
      },
    });
  }
}
