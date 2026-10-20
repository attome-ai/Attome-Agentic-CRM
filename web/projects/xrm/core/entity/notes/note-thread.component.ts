import {
  ChangeDetectionStrategy, Component, computed, inject, input, linkedSignal, output, signal,
} from '@angular/core';
import { ApiError, AuthService, LangService, TranslatePipe } from '@attome/base';
import { EntityService } from '../services/entity.service';

/** The reactions a note or reply offers. */
export const REACTIONS = ['👍', '❤️', '🎉', '✅', '👀'] as const;

/** Reaction to the users who gave it. */
export type ReactionMap = Record<string, string[]>;

/** The stored `reactions` text (JSON) as a map; anything else is empty. Pure. */
export function parseReactions(raw: unknown): ReactionMap {
  let value: unknown = raw;
  if (typeof raw === 'string') {
    try {
      value = raw.trim() ? JSON.parse(raw) : {};
    } catch {
      return {};
    }
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const out: ReactionMap = {};
  for (const [emoji, users] of Object.entries(value as Record<string, unknown>)) {
    if (Array.isArray(users)) {
      const ids = users.filter((u): u is string => typeof u === 'string');
      if (ids.length) out[emoji] = ids;
    }
  }
  return out;
}

/** `map` with `user`'s `emoji` reaction added, or removed if given. Pure. */
export function toggleReaction(map: ReactionMap, emoji: string, user: string): ReactionMap {
  const users = map[emoji] ?? [];
  const next = users.includes(user) ? users.filter(u => u !== user) : [...users, user];
  const out: ReactionMap = { ...map };
  if (next.length) out[emoji] = next; else delete out[emoji];
  return out;
}

/** One note or reply the thread toolbar acts on. */
export interface ThreadItem {
  entity: 'note' | 'note_reply';
  id: string;
  reactions?: unknown;
  rowVersion?: number;
  /** Notes only. */
  isResolved?: boolean;
  resolvedAt?: string | null;
}

/** One earlier text of the item. */
export interface TextVersion {
  changedOn: string;
  actor: string;
  text: string;
}

/**
 * The thread toolbar under a note or a reply (roadmap C1-T2): reactions
 * any reader can toggle, the item's edit history (its earlier texts, from
 * the record's field history), and, on a note, resolving or reopening the
 * thread. Every change is a generic update at the item's row version; a
 * stale version reloads the item and applies the change once more, so two
 * people reacting at once both count.
 */
@Component({
  selector: 'xrm-note-thread',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <div class="nt" [class.nt-resolved]="resolved()">
      <div class="nt-reactions" role="group" [attr.aria-label]="'notes.thread.reactions' | translate">
        @for (emoji of reactionChoices; track emoji) {
          <button type="button" class="nt-reaction" data-testid="nt-reaction"
            [class.nt-mine]="mine(emoji)" [attr.aria-pressed]="mine(emoji)"
            [disabled]="busy()" (click)="react(emoji)">
            <span aria-hidden="true">{{ emoji }}</span>
            @if (count(emoji) > 0) { <span class="nt-count">{{ count(emoji) }}</span> }
          </button>
        }
      </div>
      <button type="button" class="nt-link" data-testid="nt-history" (click)="toggleHistory()">
        {{ 'notes.thread.history' | translate }}</button>
      @if (resolvable()) {
        <button type="button" class="nt-link" data-testid="nt-resolve" [disabled]="busy()" (click)="toggleResolved()">
          {{ (resolved() ? 'notes.thread.reopen' : 'notes.thread.resolve') | translate }}</button>
        @if (resolved()) {
          <span class="nt-badge" data-testid="nt-resolved">{{ 'notes.thread.resolved' | translate }}</span>
        }
      }
      @if (error(); as message) { <p class="nt-error" role="alert">{{ message }}</p> }
      @if (showHistory()) {
        <ol class="nt-history" data-testid="nt-history-list">
          @for (v of history(); track v.changedOn) {
            <li><time>{{ v.changedOn }}</time> <span class="nt-old">{{ v.text }}</span></li>
          } @empty {
            <li class="nt-muted">{{ 'notes.thread.noEdits' | translate }}</li>
          }
        </ol>
      }
    </div>
  `,
  styles: [`
    .nt { display: flex; flex-wrap: wrap; align-items: center; gap: var(--space-2, 8px); margin-block-start: var(--space-1, 4px); }
    .nt-reactions { display: flex; gap: var(--space-1, 4px); }
    .nt-reaction { border: 1px solid var(--color-border); border-radius: 999px; background: none; padding-inline: var(--space-2, 8px); cursor: pointer; }
    .nt-mine { border-color: var(--color-primary); }
    .nt-count { margin-inline-start: var(--space-1, 4px); }
    .nt-link { background: none; border: none; color: var(--color-primary); cursor: pointer; padding: 0; }
    .nt-badge { color: var(--color-success); }
    .nt-history { flex-basis: 100%; margin: 0; padding-inline-start: var(--space-4, 16px); }
    .nt-old { color: var(--color-text-secondary); }
    .nt-muted { color: var(--color-text-secondary); list-style: none; }
    .nt-error { color: var(--color-danger); margin: 0; flex-basis: 100%; }
  `],
})
export class NoteThreadComponent {
  private readonly entities = inject(EntityService);
  private readonly auth = inject(AuthService);
  private readonly lang = inject(LangService);

  readonly item = input.required<ThreadItem>();
  /** Show resolve and reopen (a note, not a reply). */
  readonly resolvable = input(false);
  /** The item's new row version after a change. */
  readonly changed = output<number>();

  readonly reactionChoices = REACTIONS;
  readonly reactions = linkedSignal(() => parseReactions(this.item().reactions));
  readonly rowVersion = linkedSignal(() => this.item().rowVersion);
  readonly resolved = linkedSignal(() => this.item().isResolved === true);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  readonly showHistory = signal(false);
  readonly history = signal<TextVersion[]>([]);

  private readonly me = computed(() => this.auth.userId() ?? '');

  count(emoji: string): number {
    return this.reactions()[emoji]?.length ?? 0;
  }

  mine(emoji: string): boolean {
    return this.reactions()[emoji]?.includes(this.me()) ?? false;
  }

  react(emoji: string): void {
    const user = this.me();
    if (!user) return;
    this.change(current => ({ reactions: JSON.stringify(toggleReaction(parseReactions(current['reactions']), emoji, user)) }));
  }

  toggleResolved(): void {
    const resolve = !this.resolved();
    this.change(() => ({
      is_resolved: resolve,
      resolved_at: resolve ? new Date().toISOString() : null,
      resolved_by: resolve ? this.me() || null : null,
    }));
  }

  toggleHistory(): void {
    const open = !this.showHistory();
    this.showHistory.set(open);
    if (!open) return;
    const { entity, id } = this.item();
    this.entities.fieldHistory(entity, id, 'note_text').subscribe({
      next: page => this.history.set(page.items.flatMap(change => change.fields
        .filter(f => f.field_name === 'note_text' && !f.masked)
        .map(f => ({
          changedOn: new Date(change.changed_on).toLocaleString(this.lang.intlLocale()),
          actor: change.actor,
          text: f.old_display_value ?? f.old_value ?? '',
        }))
        .filter(v => v.text))),
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }

  /**
   * Saves the patch `build` makes from the item's current values, at its
   * row version; on a stale version, reloads the item and builds again
   * once.
   */
  private change(build: (current: Record<string, unknown>) => Record<string, unknown>, retried = false): void {
    const { entity, id } = this.item();
    const current: Record<string, unknown> = { reactions: JSON.stringify(this.reactions()) };
    this.busy.set(true);
    this.error.set(null);
    this.entities.update(entity, id, build(current), this.rowVersion()).subscribe({
      next: r => this.applied(r.data, r.row_version),
      error: (e: ApiError) => {
        if (!retried && e.status === 409) {
          this.entities.get(entity, id).subscribe({
            next: fresh => {
              this.applied(fresh.data, fresh.row_version, false);
              this.change(build, true);
            },
            error: (again: ApiError) => this.failed(again),
          });
          return;
        }
        this.failed(e);
      },
    });
  }

  private applied(data: Record<string, unknown>, rowVersion: number, done = true): void {
    this.reactions.set(parseReactions(data['reactions']));
    if ('is_resolved' in data) this.resolved.set(data['is_resolved'] === true);
    this.rowVersion.set(rowVersion);
    if (done) {
      this.busy.set(false);
      this.changed.emit(rowVersion);
    }
  }

  private failed(e: ApiError): void {
    this.busy.set(false);
    this.error.set(this.lang.errorText(e));
  }
}
