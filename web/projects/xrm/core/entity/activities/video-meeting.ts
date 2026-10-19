import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from '@attome/base';

/** J7-T1's providers, as `POST /api/v1/me/meetings` names them. */
export const MEETING_PROVIDERS = ['teams', 'meet', 'zoom', 'jitsi'] as const;
export type MeetingProvider = (typeof MEETING_PROVIDERS)[number];

/** A meeting's length when the person gives none. */
export const DEFAULT_MEETING_MINUTES = 30;
/** How early before its start the join button shows. */
const JOIN_EARLY_MS = 15 * 60_000;

export interface MeetingRequest {
  provider: MeetingProvider;
  subject: string;
  start: string;
  end: string;
}

export interface CreatedMeeting {
  provider: string;
  id: string;
  join_url: string;
}

/**
 * The meeting to create for an activity: from its due time (a
 * `datetime-local` value) for `minutes`, or `null` when the time is not
 * valid. Pure.
 */
export function meetingRequest(
  provider: MeetingProvider,
  subject: string,
  dueLocal: string,
  minutes: number | null = null,
): MeetingRequest | null {
  const start = new Date(dueLocal);
  if (!dueLocal || Number.isNaN(start.getTime())) return null;
  const length = minutes && minutes > 0 ? minutes : DEFAULT_MEETING_MINUTES;
  return {
    provider,
    subject,
    start: start.toISOString(),
    end: new Date(start.getTime() + length * 60_000).toISOString(),
  };
}

/** The activity's meeting fields from the created meeting. Pure. */
export function meetingFields(meeting: CreatedMeeting, minutes: number): Record<string, unknown> {
  return {
    meeting_provider: meeting.provider,
    meeting_id: meeting.id,
    meeting_url: meeting.join_url,
    duration_minutes: minutes,
  };
}

/** Only http(s) links are shown as a join button. Pure. */
export function safeJoinUrl(url: string | null | undefined): string | null {
  if (!url) return null;
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:' ? parsed.href : null;
  } catch {
    return null;
  }
}

/**
 * Whether the join button shows: an open meeting with a link, from 15
 * minutes before its start until it ends (an undated one always). Pure.
 */
export function canJoin(
  row: { status: string; meeting_url?: string | null; due_at: string | null; duration_minutes?: number | null },
  now: number = Date.now(),
): boolean {
  if (row.status !== 'open' || !safeJoinUrl(row.meeting_url)) return false;
  if (!row.due_at) return true;
  const start = Date.parse(row.due_at);
  if (Number.isNaN(start)) return true;
  const end = start + (row.duration_minutes || DEFAULT_MEETING_MINUTES) * 60_000;
  return now >= start - JOIN_EARLY_MS && now <= end;
}

/** J7-T2: creates the online meeting behind a "video meeting" activity. */
@Injectable({ providedIn: 'root' })
export class VideoMeetingService {
  private readonly api = inject(ApiService);

  create(request: MeetingRequest): Observable<CreatedMeeting> {
    return this.api.post<CreatedMeeting>('/api/v1/me/meetings', request);
  }
}
