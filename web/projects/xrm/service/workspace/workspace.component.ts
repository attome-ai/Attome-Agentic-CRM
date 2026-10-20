import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiError, TranslatePipe } from '@attome/base';
import { SlaBadgeComponent } from '@attome/xrm/service';
import { ArticleSuggestComponent, caseQuery } from './article-suggest.component';
import { ComposerComponent } from './composer/composer.component';
import { PresenceComponent } from './presence.component';
import { CaseSummaryComponent } from './case-summary.component';

import {
  ConversationSummary,
  QueueSummary,
  RecordView,
  SessionTab,
  WorkItem,
  WorkspaceService,
  openSession,
} from './workspace.service';

const STORE = 'attome-service-workspace';

/**
 * G5-T1: the service workspace. The home tab lists the agent's open cases,
 * the queues and the web chat conversations waiting; each case or
 * conversation opens in its own session tab, which keeps its state (the
 * loaded record and an unsent note) while the agent moves between tabs and
 * across reloads of the page. A session's context panel shows the SLA
 * (`SlaBadgeComponent`) and who is asking; quick actions open a new request,
 * the catalog and the triage board.
 */
@Component({
  selector: 'attome-service-workspace',
  standalone: true,
  imports: [TranslatePipe, RouterLink, SlaBadgeComponent, ArticleSuggestComponent, ComposerComponent, PresenceComponent, CaseSummaryComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls: ['../../styles/admin-page.css', './workspace.component.css'],
  templateUrl: './workspace.component.html',
})
export class WorkspaceComponent implements OnInit {
  private readonly svc = inject(WorkspaceService);

  readonly work = signal<WorkItem[]>([]);
  readonly queues = signal<QueueSummary[]>([]);
  readonly conversations = signal<ConversationSummary[]>([]);
  readonly error = signal<string | null>(null);

  readonly tabs = signal<SessionTab[]>(this.restore());
  /** The open tab's key; `null` is home. */
  readonly active = signal<string | null>(null);
  /** Records loaded per session, kept while their tab is open. */
  readonly records = signal<Record<string, RecordView>>({});

  readonly activeTab = computed(() => this.tabs().find(t => t.key === this.active()) ?? null);
  readonly activeRecord = computed(() => {
    const tab = this.activeTab();
    return tab ? this.records()[tab.key] ?? null : null;
  });

  ngOnInit(): void {
    this.svc.myWork().subscribe({
      next: items => this.work.set(items),
      error: (e: ApiError) => this.error.set(e.message),
    });
    this.svc.queues().subscribe({ next: q => this.queues.set(q), error: () => this.queues.set([]) });
    this.svc.conversations().subscribe({
      next: c => this.conversations.set(c),
      error: () => this.conversations.set([]),
    });
  }

  open(entity: string, recordId: string, title: string): void {
    this.tabs.update(tabs => openSession(tabs, entity, recordId, title));
    this.select(`${entity}:${recordId}`);
    this.persist();
  }

  select(key: string | null): void {
    this.active.set(key);
    const tab = this.activeTab();
    if (tab && !this.records()[tab.key]) {
      this.svc.record(tab.entity, tab.recordId).subscribe({
        next: record => this.records.update(all => ({ ...all, [tab.key]: record })),
        error: (e: ApiError) => this.error.set(e.message),
      });
    }
  }

  close(key: string): void {
    this.tabs.update(tabs => tabs.filter(t => t.key !== key));
    this.records.update(all => {
      const next = { ...all };
      delete next[key];
      return next;
    });
    if (this.active() === key) this.active.set(null);
    this.persist();
  }

  setDraft(key: string, draft: string): void {
    this.tabs.update(tabs => tabs.map(t => (t.key === key ? { ...t, draft } : t)));
    this.persist();
  }

  /** G11-T2: the case text articles are suggested for. */
  caseText(record: RecordView | null): string {
    return caseQuery(this.field(record, 'title'), this.field(record, 'description'));
  }

  field(record: RecordView | null, name: string): string {
    const value = record?.data?.[name];
    return value === null || value === undefined ? '' : String(value);
  }

  private persist(): void {
    try {
      sessionStorage.setItem(STORE, JSON.stringify(this.tabs()));
    } catch {
      // Storage blocked: the sessions last until the page reloads.
    }
  }

  private restore(): SessionTab[] {
    try {
      const raw = sessionStorage.getItem(STORE);
      const parsed: unknown = raw ? JSON.parse(raw) : [];
      return Array.isArray(parsed) ? (parsed as SessionTab[]).filter(t => t && typeof t.key === 'string') : [];
    } catch {
      return [];
    }
  }
}
