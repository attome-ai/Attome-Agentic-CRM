import { ChangeDetectionStrategy, Component, OnInit, inject, input, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, LangService, TranslatePipe } from '@attome/base';

import { textDir } from './ai-meeting-brief.component';
import {
  AiMeetingService,
  MeetingNotes,
  MeetingRecordUpdate,
  checkedIndexes,
  toMeetingNotes,
} from './ai-meeting.service';

/** A proposed update's value as one line of text. */
export function valueText(value: unknown): string {
  if (value === null || value === undefined) return '';
  return typeof value === 'string' ? value : JSON.stringify(value);
}

/**
 * AI6-T7: a meeting's notes. Asks for notes from a recording (its document
 * id), shows the draft's summary and decisions, and lists its action items
 * and proposed record updates with checkboxes — each update with the
 * transcript words it came from. Confirm sends only the checked ones, under
 * the notes' `row_version`; a checked update is still only proposed, through
 * `record.update_field`'s approval. The notes run in their own language's
 * direction.
 */
@Component({
  selector: 'xrm-ai-meeting-notes',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  template: `
    <section class="amn">
      <h3>{{ 'aiMeeting.notes.title' | translate }}</h3>
      <form class="amn-ask" (ngSubmit)="requestNotes()">
        <label>
          {{ 'aiMeeting.notes.recording' | translate }}
          <input name="transcriptRef" [(ngModel)]="transcriptRef" autocomplete="off" />
        </label>
        <button type="submit" [disabled]="busy() || !transcriptRef.trim()">{{ 'aiMeeting.notes.make' | translate }}</button>
      </form>
      @if (queued()) { <p class="amn-muted" role="status" data-notes-queued>{{ 'aiMeeting.notes.queued' | translate }}</p> }
      @if (error(); as message) { <p class="amn-error" role="alert">{{ message }}</p> }

      @if (notes(); as n) {
        <div class="amn-body" [attr.dir]="dir(n.language)" [attr.lang]="n.language">
          <p class="amn-summary">{{ n.summary }}</p>
          @if (n.decisions.length) {
            <h4>{{ 'aiMeeting.notes.decisions' | translate }}</h4>
            <ul>
              @for (d of n.decisions; track $index) { <li>{{ d }}</li> }
            </ul>
          }
          <h4>{{ 'aiMeeting.notes.actionItems' | translate }}</h4>
          <ul class="amn-checks">
            @for (item of n.action_items; track $index; let i = $index) {
              <li>
                <label>
                  <input type="checkbox" [attr.data-item]="i" [checked]="itemChecks()[i]"
                    [disabled]="confirmed(n)" (change)="toggleItem(i)" />
                  {{ item.text }}
                  @if (item.owner_hint) { <small class="amn-muted">· {{ item.owner_hint }}</small> }
                  @if (item.due_hint) { <small class="amn-muted">· {{ item.due_hint }}</small> }
                </label>
              </li>
            } @empty {
              <li class="amn-muted">{{ 'aiMeeting.notes.noItems' | translate }}</li>
            }
          </ul>
          @if (n.record_updates.length) {
            <h4>{{ 'aiMeeting.notes.updates' | translate }}</h4>
            <p class="amn-muted">{{ 'aiMeeting.notes.updatesHint' | translate }}</p>
            <ul class="amn-checks">
              @for (u of n.record_updates; track $index; let i = $index) {
                <li>
                  <label>
                    <input type="checkbox" [attr.data-update]="i" [checked]="updateChecks()[i]"
                      [disabled]="confirmed(n)" (change)="toggleUpdate(i)" />
                    <code>{{ u.entity }}.{{ u.attribute }}</code> → <strong>{{ value(u) }}</strong>
                  </label>
                  <blockquote class="amn-quote" [attr.data-quote]="i">{{ u.quote }}</blockquote>
                </li>
              }
            </ul>
          }
        </div>
        @if (confirmed(n)) {
          <p class="amn-muted" data-notes-confirmed>{{ 'aiMeeting.notes.confirmed' | translate }}</p>
        } @else {
          <button type="button" class="amn-confirm" (click)="confirm()" [disabled]="busy()">
            {{ 'aiMeeting.notes.confirm' | translate }}
          </button>
        }
        @if (result(); as r) { <p class="amn-muted" role="status">{{ 'aiMeeting.notes.done' | translate: r }}</p> }
      }
    </section>
  `,
  styles: [`
    :host { display: block; }
    .amn { display: flex; flex-direction: column; gap: 0.5rem; }
    .amn h3 { margin-block: 0; font-size: 1rem; }
    .amn h4 { margin-block: 0.5rem 0.25rem; font-size: 0.875rem; }
    .amn-ask { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: end; }
    .amn-ask label { display: flex; flex-direction: column; gap: 0.25rem; flex: 1 1 16rem; }
    .amn-body { text-align: start; }
    .amn-summary { white-space: pre-wrap; line-height: 1.5; }
    .amn-checks { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.375rem; }
    .amn-checks label { display: flex; flex-wrap: wrap; gap: 0.375rem; align-items: baseline; }
    .amn-quote { margin-block: 0.25rem 0; margin-inline: 1.5rem 0; padding-inline-start: 0.5rem;
      border-inline-start: 2px solid var(--color-border); color: var(--color-text-secondary); }
    .amn-confirm { align-self: flex-start; }
    .amn-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .amn-error { color: var(--color-danger); }
  `],
})
export class AiMeetingNotesComponent implements OnInit {
  private readonly meetings = inject(AiMeetingService);
  private readonly lang = inject(LangService);

  /** The meeting activity's id. */
  readonly meetingId = input.required<string>();
  /** The notes to review, when there are some. */
  readonly notesId = input<string | null>(null);

  transcriptRef = '';
  readonly notes = signal<MeetingNotes | null>(null);
  readonly itemChecks = signal<boolean[]>([]);
  readonly updateChecks = signal<boolean[]>([]);
  readonly error = signal<string | null>(null);
  readonly busy = signal(false);
  readonly queued = signal(false);
  readonly result = signal<{ tasks: number; updates: number } | null>(null);
  readonly dir = textDir;
  readonly value = (u: MeetingRecordUpdate) => valueText(u.value);
  readonly confirmed = (n: MeetingNotes) => n.status === 'confirmed';

  ngOnInit(): void {
    const id = this.notesId();
    if (id) this.load(id);
  }

  load(notesId: string): void {
    this.meetings.notes(notesId).subscribe({
      next: record => {
        const notes = toMeetingNotes(record);
        this.notes.set(notes);
        // Action items start chosen; record updates start unchosen, since
        // each one changes a record.
        this.itemChecks.set(notes.action_items.map(() => true));
        this.updateChecks.set(notes.record_updates.map(() => false));
      },
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }

  toggleItem(i: number): void {
    this.itemChecks.update(checks => checks.map((c, j) => (j === i ? !c : c)));
  }

  toggleUpdate(i: number): void {
    this.updateChecks.update(checks => checks.map((c, j) => (j === i ? !c : c)));
  }

  requestNotes(): void {
    const ref = this.transcriptRef.trim();
    if (!ref) return;
    this.busy.set(true);
    this.queued.set(false);
    this.meetings.requestNotes(this.meetingId(), ref).subscribe({
      next: () => { this.busy.set(false); this.queued.set(true); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(this.lang.errorText(e)); },
    });
  }

  confirm(): void {
    const notes = this.notes();
    if (!notes) return;
    const items = checkedIndexes(this.itemChecks());
    const updates = checkedIndexes(this.updateChecks());
    this.busy.set(true);
    this.meetings.confirmNotes(this.meetingId(), notes, items, updates).subscribe({
      next: () => {
        this.busy.set(false);
        this.result.set({ tasks: items.length, updates: updates.length });
        this.load(notes.id);
      },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(this.lang.errorText(e)); },
    });
  }
}
