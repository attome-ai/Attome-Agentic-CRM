import { Injectable, inject } from '@angular/core';
import { ApiService } from '@attome/base';
import { Observable } from 'rxjs';

import type { ActionOutcome } from '../services/ai-actions.service';

/** `attome_ai::meeting::routes::MeetingBriefView`. */
export interface MeetingBrief {
  id: string;
  meeting_id: string;
  status: 'ready' | 'failed' | string | null;
  language: 'ar' | 'en' | string | null;
  brief_text: string | null;
  generated_at: string | null;
  row_version: number;
}

/** `attome_ai::meeting::routes::MeetingNotesQueued`. */
export interface MeetingNotesQueued {
  meeting_id: string;
  transcript_ref: string;
  job_key: string;
  queued: boolean;
}

/** One action item of the notes (`attome_ai::meeting::notes::ActionItem`). */
export interface MeetingActionItem {
  text: string;
  owner_hint?: string | null;
  due_hint?: string | null;
}

/** One proposed record update, with the transcript words behind it. */
export interface MeetingRecordUpdate {
  entity: string;
  record_id: string;
  attribute: string;
  value: unknown;
  quote: string;
}

/** An `ai_meeting_notes` record as the notes panel reads it. */
export interface MeetingNotes {
  id: string;
  row_version: number;
  meeting_id: string | null;
  status: 'draft' | 'confirmed' | string | null;
  language: 'ar' | 'en' | string | null;
  summary: string;
  decisions: string[];
  action_items: MeetingActionItem[];
  record_updates: MeetingRecordUpdate[];
}

/** The generic record read of `ai_meeting_notes`. */
export interface NotesRecord {
  id: string;
  row_version: number;
  data: Record<string, unknown>;
}

/**
 * The items stored in a notes row's `action_items_json`
 * (`{action_items, record_updates}`); anything unreadable is no items.
 */
export function parseNotesItems(raw: unknown): {
  action_items: MeetingActionItem[];
  record_updates: MeetingRecordUpdate[];
} {
  if (typeof raw !== 'string' || raw.trim() === '') {
    return { action_items: [], record_updates: [] };
  }
  try {
    const parsed = JSON.parse(raw) as {
      action_items?: MeetingActionItem[];
      record_updates?: MeetingRecordUpdate[];
    };
    return {
      action_items: Array.isArray(parsed.action_items) ? parsed.action_items : [],
      record_updates: Array.isArray(parsed.record_updates) ? parsed.record_updates : [],
    };
  } catch {
    return { action_items: [], record_updates: [] };
  }
}

/** A notes record read as the panel needs it. */
export function toMeetingNotes(record: NotesRecord): MeetingNotes {
  const data = record.data ?? {};
  const text = (key: string) => (typeof data[key] === 'string' ? (data[key] as string) : '');
  const items = parseNotesItems(data['action_items_json']);
  return {
    id: record.id,
    row_version: Number(record.row_version ?? 0),
    meeting_id: text('meeting_id') || null,
    status: text('status') || null,
    language: text('language') || null,
    summary: text('summary'),
    decisions: text('decisions')
      .split('\n')
      .map(d => d.trim())
      .filter(d => d !== ''),
    action_items: items.action_items,
    record_updates: items.record_updates,
  };
}

/** The positions that are checked, in order. */
export function checkedIndexes(checks: readonly boolean[]): number[] {
  return checks.flatMap((checked, i) => (checked ? [i] : []));
}

/**
 * AI6-T7: the meeting brief and notes routes (AI6-T6) and the notes
 * record read.
 */
@Injectable({ providedIn: 'root' })
export class AiMeetingService {
  private readonly api = inject(ApiService);

  private base(meetingId: string): string {
    return `/api/v1/ai/meetings/${encodeURIComponent(meetingId)}`;
  }

  brief(meetingId: string): Observable<MeetingBrief> {
    return this.api.get<MeetingBrief>(`${this.base(meetingId)}/brief`);
  }

  regenerateBrief(meetingId: string): Observable<ActionOutcome> {
    return this.api.post<ActionOutcome>(`${this.base(meetingId)}/brief/regenerate`, {});
  }

  requestNotes(meetingId: string, transcriptRef: string): Observable<MeetingNotesQueued> {
    return this.api.post<MeetingNotesQueued>(`${this.base(meetingId)}/notes`, {
      transcript_ref: transcriptRef,
    });
  }

  notes(notesId: string): Observable<NotesRecord> {
    return this.api.get<NotesRecord>(`/api/v1/ai_meeting_notes/${encodeURIComponent(notesId)}`);
  }

  confirmNotes(
    meetingId: string,
    notes: Pick<MeetingNotes, 'id' | 'row_version'>,
    actionItemIndexes: number[],
    recordUpdateIndexes: number[],
  ): Observable<ActionOutcome> {
    return this.api.post<ActionOutcome>(
      `${this.base(meetingId)}/notes/confirm`,
      {
        notes_id: notes.id,
        action_item_indexes: actionItemIndexes,
        record_update_indexes: recordUpdateIndexes,
      },
      { ifMatch: notes.row_version },
    );
  }
}
