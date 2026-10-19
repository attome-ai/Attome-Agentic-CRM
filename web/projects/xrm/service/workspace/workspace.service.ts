import { inject, Injectable } from '@angular/core';
import { Observable, map } from 'rxjs';
import { ApiService } from '@attome/base';

/** One item of the caller's work (`GET /api/v1/my-work/{provider}`). */
export interface WorkItem {
  provider:      string;
  source_entity: string;
  record_id:     string;
  title:         string;
  state:         string;
  due_date?:     string | null;
}

/** A work queue the caller can open. */
export interface QueueSummary {
  id:   string;
  name: string;
}

/** A conversation waiting on the service desk (a web chat request). */
export interface ConversationSummary {
  id:         string;
  title:      string;
  reference:  string | null;
  created_at: string | null;
}

/** A record as a session tab shows it. */
export interface RecordView {
  id:          string;
  row_version: number;
  data:        Record<string, unknown>;
}

/** One open session: a case or conversation in its own tab. */
export interface SessionTab {
  key:      string;
  entity:   string;
  recordId: string;
  title:    string;
  /** What the person typed in this session and has not sent: kept per tab. */
  draft:    string;
}

/** Most sessions open at once. */
export const MAX_SESSIONS = 8;

/** The session key of a record. Pure. */
export function sessionKey(entity: string, recordId: string): string {
  return `${entity}:${recordId}`;
}

/**
 * The tabs after opening a record: an open one is kept (with its state), a
 * new one is added at the end, and past [`MAX_SESSIONS`] the oldest is
 * dropped. Pure.
 */
export function openSession(tabs: SessionTab[], entity: string, recordId: string, title: string): SessionTab[] {
  const key = sessionKey(entity, recordId);
  if (tabs.some(t => t.key === key)) return tabs;
  const next = [...tabs, { key, entity, recordId, title, draft: '' }];
  return next.length > MAX_SESSIONS ? next.slice(next.length - MAX_SESSIONS) : next;
}

/** G5-T1: the workspace's reads, over routes that already exist. */
@Injectable({ providedIn: 'root' })
export class WorkspaceService {
  private readonly api = inject(ApiService);

  /** The caller's open cases (the `service` My Work provider). */
  myWork(): Observable<WorkItem[]> {
    return this.api
      .get<{ items: WorkItem[] }>('/api/v1/my-work/service', { limit: '50' })
      .pipe(map(page => page.items ?? []));
  }

  /** The work queues there are. */
  queues(): Observable<QueueSummary[]> {
    return this.api
      .get<{ items: Record<string, unknown>[] }>('/api/v1/service_work_queue', {
        select: 'id,name',
        sort: 'name',
        page_size: '100',
      })
      .pipe(map(page => (page.items ?? []).map(row => ({
        id: String(row['id']),
        name: String(row['name'] ?? row['id']),
      }))));
  }

  /** Web chat requests not yet converted, newest first. */
  conversations(): Observable<ConversationSummary[]> {
    return this.api
      .get<{ items: Record<string, unknown>[] }>('/api/v1/service_work_request', {
        select: 'id,title,reference,status,channel,created_at',
        sort: '-created_at',
        page_size: '100',
      })
      .pipe(map(page => (page.items ?? [])
        .filter(row => row['channel'] === 'web_chat' && (row['status'] === 'new' || row['status'] === 'triaged'))
        .map(row => ({
          id: String(row['id']),
          title: String(row['title'] ?? ''),
          reference: row['reference'] === null || row['reference'] === undefined ? null : String(row['reference']),
          created_at: row['created_at'] === null || row['created_at'] === undefined ? null : String(row['created_at']),
        }))));
  }

  /** One record, for a session tab. */
  record(entity: string, id: string): Observable<RecordView> {
    return this.api.get<RecordView>(`/api/v1/${entity}/${id}`);
  }
}
