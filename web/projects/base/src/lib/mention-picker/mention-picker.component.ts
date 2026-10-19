import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  effect,
  inject,
  input,
  output,
  signal,
} from '@angular/core';
import { Observable, Subject, catchError, of, switchMap, timer } from 'rxjs';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { TranslatePipe } from '../translate.pipe';

/** Something that can be mentioned. */
export interface MentionCandidate {
  kind: 'user' | 'team' | 'record';
  id: string;
  /** What the list shows. */
  label: string;
  /** A second line: an email, a team's size, a record's entity. */
  detail?: string;
  /** A record's entity. */
  entity?: string;
}

/** Looks up candidates for what follows the `@`. */
export type MentionSearch = (query: string) => Observable<MentionCandidate[]>;

/** The `@query` being typed: where it starts and what it says. */
export interface ActiveMention {
  start: number;
  query: string;
}

/** Longest query looked up. */
const MAX_QUERY = 40;

/**
 * The `@query` ending at `caret`, if one is being typed: an `@` at the start
 * or after a space, followed by no space. Pure.
 */
export function activeMention(text: string, caret: number): ActiveMention | null {
  const before = text.slice(0, caret);
  const at = before.lastIndexOf('@');
  if (at < 0) return null;
  if (at > 0 && !/\s/.test(before.charAt(at - 1))) return null;
  const query = before.slice(at + 1);
  if (query.startsWith('[') || /\s/.test(query) || query.length > MAX_QUERY) return null;
  return { start: at, query };
}

/**
 * The token a mention is saved as (`attome-api` C4-T1 reads `user` and
 * `team`; a record mention is a link). Ids, never names, so a rename keeps
 * the mention. Pure.
 */
export function mentionToken(c: MentionCandidate): string {
  switch (c.kind) {
    case 'user': return `@[user:${c.id}]`;
    case 'team': return `@[team:${c.id}]`;
    case 'record': return `@[record:${c.entity ?? ''}/${c.id}]`;
  }
}

let nextId = 0;

/**
 * C4-T2: a mention picker for any text editor. Point `target` at a textarea
 * or input; typing `@` and a few letters there lists matching people, teams
 * and records from `search`, and choosing one (click, Enter or Tab) puts its
 * token in place of the `@query`. Arrow keys move, Escape closes. The editor
 * gets an `input` event, so whatever model it is bound to sees the change.
 */
@Component({
  selector: 'base-mention-picker',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    @if (open()) {
      <ul class="mp-list" role="listbox" [id]="listId"
          [attr.aria-label]="'mentionPicker.label' | translate" data-testid="mention-list">
        @if (searching() && candidates().length === 0) {
          <li class="mp-note" role="presentation">{{ 'mentionPicker.searching' | translate }}</li>
        } @else if (candidates().length === 0) {
          <li class="mp-note" role="presentation" data-testid="mention-none">{{ 'mentionPicker.none' | translate }}</li>
        }
        @for (c of candidates(); track c.kind + c.id; let i = $index) {
          <li class="mp-option" role="option" [id]="listId + '-' + i"
              [attr.aria-selected]="i === active()" [class.mp-active]="i === active()"
              (mousedown)="$event.preventDefault(); choose(c)" data-testid="mention-option">
            <span class="mp-label">{{ c.label }}</span>
            <span class="mp-detail">{{ ('mentionPicker.kind.' + c.kind) | translate }}@if (c.detail) { · {{ c.detail }} }</span>
          </li>
        }
      </ul>
    }
  `,
  styles: [`
    :host { position: relative; display: block; }
    .mp-list {
      position: absolute; inset-inline-start: 0; inset-block-start: 4px; z-index: 20;
      min-inline-size: 240px; max-block-size: 260px; overflow-y: auto;
      margin: 0; padding-block: 4px; padding-inline: 0; list-style: none;
      background: var(--color-bg); color: var(--color-text-primary);
      border: 1px solid var(--color-border); border-radius: 8px;
      box-shadow: 0 4px 16px var(--color-card-shadow);
    }
    .mp-option, .mp-note { display: grid; gap: 2px; padding-block: 6px; padding-inline: 12px; }
    .mp-option { cursor: pointer; }
    .mp-active, .mp-option:hover { background: var(--color-bg-alt); }
    .mp-label { font-weight: 600; }
    .mp-detail, .mp-note { font-size: 12px; color: var(--color-text-secondary); }
  `],
})
export class MentionPickerComponent {
  /** The editor to watch. */
  readonly target = input.required<HTMLTextAreaElement | HTMLInputElement>();
  /** Where candidates come from. */
  readonly search = input.required<MentionSearch>();
  /** Wait this long after typing stops before looking up. */
  readonly debounceMs = input(150);

  /** A candidate was put into the text. */
  readonly mentioned = output<MentionCandidate>();

  readonly open = signal(false);
  readonly searching = signal(false);
  readonly candidates = signal<MentionCandidate[]>([]);
  readonly active = signal(0);
  readonly listId = `base-mention-list-${nextId++}`;

  private current: ActiveMention | null = null;
  private readonly queries = new Subject<string>();

  constructor() {
    const destroyRef = inject(DestroyRef);
    this.queries.pipe(
      switchMap(q => timer(this.debounceMs()).pipe(
        switchMap(() => this.search()(q).pipe(catchError(() => of([] as MentionCandidate[])))),
      )),
      takeUntilDestroyed(destroyRef),
    ).subscribe(found => {
      this.searching.set(false);
      this.candidates.set(found);
      this.active.set(0);
    });

    effect(onCleanup => {
      const el = this.target();
      el.setAttribute('aria-autocomplete', 'list');
      el.setAttribute('aria-controls', this.listId);
      const onInput = () => this.onInput(el);
      const onKey = (e: Event) => this.onKeydown(e as KeyboardEvent, el);
      const onBlur = () => this.close(el);
      el.addEventListener('input', onInput);
      el.addEventListener('keydown', onKey);
      el.addEventListener('blur', onBlur);
      onCleanup(() => {
        el.removeEventListener('input', onInput);
        el.removeEventListener('keydown', onKey);
        el.removeEventListener('blur', onBlur);
      });
    });
  }

  private onInput(el: HTMLTextAreaElement | HTMLInputElement): void {
    const found = activeMention(el.value, el.selectionStart ?? el.value.length);
    this.current = found;
    if (!found) {
      this.close(el);
      return;
    }
    this.open.set(true);
    el.setAttribute('aria-expanded', 'true');
    this.searching.set(true);
    this.queries.next(found.query);
  }

  private onKeydown(e: KeyboardEvent, el: HTMLTextAreaElement | HTMLInputElement): void {
    if (!this.open()) return;
    const n = this.candidates().length;
    switch (e.key) {
      case 'ArrowDown':
        if (n) this.move((this.active() + 1) % n, el);
        e.preventDefault();
        break;
      case 'ArrowUp':
        if (n) this.move((this.active() - 1 + n) % n, el);
        e.preventDefault();
        break;
      case 'Enter':
      case 'Tab': {
        const c = this.candidates()[this.active()];
        if (c) {
          e.preventDefault();
          this.choose(c);
        }
        break;
      }
      case 'Escape':
        e.preventDefault();
        this.close(el);
        break;
    }
  }

  private move(i: number, el: HTMLTextAreaElement | HTMLInputElement): void {
    this.active.set(i);
    el.setAttribute('aria-activedescendant', `${this.listId}-${i}`);
  }

  /** Puts `c`'s token where the `@query` is. */
  choose(c: MentionCandidate): void {
    const el = this.target();
    const at = this.current;
    if (!at) return;
    const token = `${mentionToken(c)} `;
    const end = at.start + 1 + at.query.length;
    el.value = el.value.slice(0, at.start) + token + el.value.slice(end);
    const caret = at.start + token.length;
    el.setSelectionRange(caret, caret);
    this.close(el);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    this.mentioned.emit(c);
  }

  private close(el: HTMLTextAreaElement | HTMLInputElement): void {
    this.open.set(false);
    this.searching.set(false);
    this.candidates.set([]);
    this.current = null;
    el.setAttribute('aria-expanded', 'false');
    el.removeAttribute('aria-activedescendant');
  }
}
