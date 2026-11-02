import {
  ChangeDetectionStrategy, Component, DestroyRef, ElementRef, Injectable, OnInit, computed, inject,
  input, signal, viewChild,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import type { Observable } from 'rxjs';
import { LangService, LocalNumberPipe, SdkService, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';

/** One finding (`GET /api/v1/callintel/calls/{id}`). */
export interface CallFinding {
  id: string;
  kind: string | null;
  text: string | null;
  start_ms: number | null;
  task_ref: string | null;
}

/** One scorecard answer. */
export interface CallAnswer {
  id: string;
  question_key: string | null;
  proposed_value: string | null;
  confirmed_value: string | null;
  row_version: number;
}

/** One transcript segment (redacted). */
export interface CallSegment {
  start_ms: number;
  end_ms?: number;
  speaker?: string | null;
  text: string;
}

/** The call page (D22-T8). */
export interface CallPage {
  activity_id: string;
  analysis_id: string;
  status: string | null;
  /** Only for the call's owner and their managers. */
  talk: Record<string, number | null> | null;
  findings: CallFinding[];
  scorecard: CallAnswer[];
  transcript: CallSegment[];
}

const BASE = '/api/v1/callintel';

/** The D22-T8 call routes (`crates/engine/attome-callintel/src/analysis/routes.rs`). */
@Injectable({ providedIn: 'root' })
export class CallintelService {
  private readonly sdk = inject(SdkService);

  page(activityId: string): Observable<CallPage> {
    return this.sdk.get<CallPage>(`${BASE}/calls/${activityId}`);
  }

  recording(activityId: string): Observable<{ download_url: string; expires_in_secs: number }> {
    return this.sdk.get(`${BASE}/calls/${activityId}/recording`);
  }

  comment(activityId: string, atMs: number, body: string): Observable<{ comment_id: string }> {
    return this.sdk.post(`${BASE}/calls/${activityId}/comments`, { body: { at_ms: atMs, body } });
  }

  confirm(answerId: string, value: string, rowVersion: number): Observable<unknown> {
    return this.sdk.post(`${BASE}/scorecard-answers/${answerId}/confirm`, {
      body: { value, row_version: rowVersion },
    });
  }

  task(findingId: string): Observable<{ task_id: string }> {
    return this.sdk.post(`${BASE}/findings/${findingId}/task`, { body: {} });
  }
}

/** `mm:ss` of a moment in milliseconds. Pure. */
export function clock(ms: number | null | undefined): string {
  const total = Math.max(0, Math.floor((ms ?? 0) / 1000));
  const m = Math.floor(total / 60);
  const s = total % 60;
  return `${m}:${s.toString().padStart(2, '0')}`;
}

/**
 * D22-T12 — a call: the recording player, the transcript (each line `dir="auto"`, so Arabic reads
 * right to left), the findings as a timeline that seeks the player, the scorecard (confirm only for
 * managers, by the API's answer), the talk patterns as a coaching aid when the API shows them, and
 * comments at the current moment.
 */
@Component({
  selector: 'xrm-call-page',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalNumberPipe, TranslatePipe],
  styleUrls: ['./call-page.component.css'],
  templateUrl: './call-page.component.html',
  host: { '[attr.dir]': "lang.isRtl() ? 'rtl' : 'ltr'" },
})
export class CallPageComponent implements OnInit {
  readonly activityId = input.required<string>();

  protected readonly lang = inject(LangService);
  private readonly svc = inject(CallintelService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly player = viewChild<ElementRef<HTMLAudioElement>>('player');

  readonly page = signal<CallPage | null>(null);
  readonly audioUrl = signal<string | null>(null);
  readonly error = signal<string | null>(null);
  readonly loading = signal(true);
  readonly note = signal('');
  readonly posted = signal(false);

  readonly timeline = computed(() =>
    (this.page()?.findings ?? []).filter(f => f.start_ms !== null),
  );
  readonly talkRows = computed(() =>
    Object.entries(this.page()?.talk ?? {}).filter(
      (row): row is [string, number] => typeof row[1] === 'number',
    ),
  );

  readonly clock = clock;

  ngOnInit(): void {
    this.svc.page(this.activityId()).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: page => { this.page.set(page); this.loading.set(false); },
      error: (err: ApiError) => { this.loading.set(false); this.error.set(this.lang.errorText(err)); },
    });
  }

  /** Loads the recording on first play: each load is an audited playback. */
  play(): void {
    if (this.audioUrl()) return;
    this.svc.recording(this.activityId()).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: r => this.audioUrl.set(r.download_url),
      error: (err: ApiError) => this.error.set(this.lang.errorText(err)),
    });
  }

  /** Moves the player to a moment. */
  seek(ms: number | null): void {
    const audio = this.player()?.nativeElement;
    if (!audio || ms === null) return;
    audio.currentTime = ms / 1000;
  }

  now(): number {
    return Math.round((this.player()?.nativeElement.currentTime ?? 0) * 1000);
  }

  postComment(): void {
    const body = this.note().trim();
    if (!body) return;
    this.svc.comment(this.activityId(), this.now(), body)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => { this.note.set(''); this.posted.set(true); },
        error: (err: ApiError) => this.error.set(this.lang.errorText(err)),
      });
  }

  confirm(answer: CallAnswer, value: string): void {
    this.svc.confirm(answer.id, value, answer.row_version)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => this.page.update(p => p && {
          ...p,
          scorecard: p.scorecard.map(a => a.id === answer.id
            ? { ...a, confirmed_value: value, row_version: a.row_version + 1 } : a),
        }),
        error: (err: ApiError) => this.error.set(this.lang.errorText(err)),
      });
  }

  task(finding: CallFinding): void {
    this.svc.task(finding.id).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: made => this.page.update(p => p && {
        ...p,
        findings: p.findings.map(f => f.id === finding.id ? { ...f, task_ref: made.task_id } : f),
      }),
      error: (err: ApiError) => this.error.set(this.lang.errorText(err)),
    });
  }

  onNote(event: Event): void {
    this.note.set((event.target as HTMLTextAreaElement).value);
  }
}
