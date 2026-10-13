import { ChangeDetectionStrategy, Component, computed, input, output } from '@angular/core';
import { RouterLink } from '@angular/router';
import { TranslatePipe } from '@attome/base';
import type { CitationView, MessageView, Vote } from '../services/chat.service';

/** The knowledge article entity a citation's `item_id` names. */
const KNOWLEDGE_ITEM_FORM = '/xrm/knowledge/data/item/form';

/**
 * One transcript message.
 *
 * **Model output is untrusted plain text.** `content` is rendered by text
 * interpolation only — never `[innerHTML]`, never parsed. A citation exists
 * only when the server's `citations[]` carries it, which it builds from the
 * turn's executed retrieval (row A-56); `[E1]` typed by a model stays text.
 */
@Component({
  selector: 'attome-ai-chat-message',
  standalone: true,
  imports: [RouterLink, TranslatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls: ['./chat-message.component.css'],
  templateUrl: './chat-message.component.html',
})
export class ChatMessageComponent {
  readonly message = input.required<MessageView>();
  /** Client-measured wall clock for the turn this message closes, when known. */
  readonly latencyMs = input<number | undefined>(undefined);
  /** A thumbs vote on this answer (C10-B). The panel records it. */
  readonly voted = output<Vote>();

  readonly role = computed(() => this.message().role);
  /** A turn's final assistant message: the one carrying grounding and provenance. */
  readonly isTurnFinal = computed(
    () => this.message().role === 'assistant' && this.message().terminal_state != null,
  );
  readonly citations = computed<CitationView[]>(() => this.message().citations ?? []);
  readonly grounding = computed(() => this.message().grounding ?? null);
  readonly terminalState = computed(() => this.message().terminal_state ?? null);
  /** Only an answer that completed is rated: a stopped or failed turn has nothing to judge. */
  readonly rateable = computed(() => this.terminalState() === 'completed');
  readonly vote = computed<Vote | null>(() => this.message().feedback ?? null);

  cast(vote: Vote): void {
    if (this.vote() !== vote) this.voted.emit(vote);
  }

  citationLink(): string {
    return KNOWLEDGE_ITEM_FORM;
  }

  headingPath(c: CitationView): string {
    return c.heading_path.join(' › ');
  }
}
