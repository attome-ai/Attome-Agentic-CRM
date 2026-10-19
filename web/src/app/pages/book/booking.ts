import { firstValueFrom } from 'rxjs';
import { ApiService } from '@attome/base';
import { solvePow } from '../login/pow';

/** `GET /api/v1/booking/{slug}`. */
export interface BookingPageView {
  name: string;
  description: string | null;
  duration_minutes: number;
  slots: { start: string; end: string }[];
}

/** `GET /api/v1/booking/manage/{token}` and the cancel/reschedule answers. */
export interface ManagedBooking {
  page_name: string;
  slug: string;
  start: string;
  end: string;
  status: 'booked' | 'cancelled';
}

/** One day's slots, labelled in the reader's language and time zone. */
export interface SlotDay {
  key: string;
  label: string;
  slots: { start: string; end: string; label: string }[];
}

/**
 * Slots grouped by the day they start on in `timeZone`, in order, each with
 * its start time as text. Pure.
 */
export function groupByDay(
  slots: readonly { start: string; end: string }[],
  locale: string,
  timeZone?: string,
): SlotDay[] {
  const dayKey = new Intl.DateTimeFormat('en-CA', { timeZone, year: 'numeric', month: '2-digit', day: '2-digit' });
  const dayLabel = new Intl.DateTimeFormat(locale, { timeZone, weekday: 'long', day: 'numeric', month: 'long' });
  const time = new Intl.DateTimeFormat(locale, { timeZone, hour: 'numeric', minute: '2-digit' });
  const days: SlotDay[] = [];
  for (const s of [...slots].sort((a, b) => Date.parse(a.start) - Date.parse(b.start))) {
    const at = new Date(s.start);
    if (Number.isNaN(at.getTime())) continue;
    const key = dayKey.format(at);
    let day = days.find(d => d.key === key);
    if (!day) {
      day = { key, label: dayLabel.format(at), slots: [] };
      days.push(day);
    }
    day.slots.push({ start: s.start, end: s.end, label: time.format(at) });
  }
  return days;
}

/** A meeting's time as one line, in the reader's language. Pure. */
export function meetingTime(start: string, end: string, locale: string, timeZone?: string): string {
  const from = new Intl.DateTimeFormat(locale, {
    timeZone, weekday: 'long', day: 'numeric', month: 'long', hour: 'numeric', minute: '2-digit',
  });
  const to = new Intl.DateTimeFormat(locale, { timeZone, hour: 'numeric', minute: '2-digit' });
  return `${from.format(new Date(start))} – ${to.format(new Date(end))}`;
}

/**
 * The challenge answer when the deployment asks for proof-of-work, else
 * none: no challenge in force answers 404 and the booking goes without.
 */
export async function challengeToken(api: ApiService): Promise<string | undefined> {
  let challenge: { challenge: string; nonce: string; difficulty: number };
  try {
    challenge = await firstValueFrom(api.get<{ challenge: string; nonce: string; difficulty: number }>(
      '/api/v1/auth/challenge',
    ));
  } catch {
    return undefined;
  }
  const answer = await solvePow(challenge.nonce, challenge.difficulty);
  return `${challenge.challenge}:${answer}`;
}
