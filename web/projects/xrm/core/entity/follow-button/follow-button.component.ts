import { ChangeDetectionStrategy, Component, effect, inject, input, signal } from '@angular/core';
import { ApiError, AuthService, LangService, TranslatePipe } from '@attome/base';
import { EntityService } from '../services/entity.service';

/** The platform entity a follow is stored in (`platform-bundles/attome-api-follow.json`). */
export const FOLLOW_ENTITY = 'follow';

/**
 * C2-T2: "Follow" on the record form header. A follow is a `follow` record
 * for the signed-in person naming this record; while it exists they hear
 * about the record's changes (C2-T1) and see them in their feed (C3-T1).
 * Pressing again removes it. The server decides who may follow what: a
 * record they cannot read cannot be followed.
 */
@Component({
  selector: 'xrm-follow-button',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styleUrls: ['./follow-button.component.css'],
  templateUrl: './follow-button.component.html',
})
export class FollowButtonComponent {
  private readonly entities = inject(EntityService);
  private readonly auth     = inject(AuthService);
  private readonly lang     = inject(LangService);

  /** Logical name of the record's entity. */
  readonly entity   = input.required<string>();
  /** The record's id. */
  readonly recordId = input.required<string>();

  /** The caller's follow of this record, when there is one. */
  readonly followId = signal<string | null>(null);
  readonly loaded   = signal(false);
  readonly busy     = signal(false);
  readonly error    = signal<string | null>(null);

  constructor() {
    effect(() => {
      const entity = this.entity();
      const record = this.recordId();
      const user = this.auth.userId();
      this.loaded.set(false);
      this.followId.set(null);
      if (!user) return;
      this.entities.list(FOLLOW_ENTITY, {
        filters: [
          { field: 'user_id', op: 'eq', value: user },
          { field: 'entity_name', op: 'eq', value: entity },
          { field: 'record_id', op: 'eq', value: record },
        ],
        limit: 1,
      }).subscribe({
        next: page => {
          this.followId.set(page.data[0]?.id || null);
          this.loaded.set(true);
        },
        // Following is an addition to the form: if it cannot be read, the
        // button stays hidden rather than failing the form.
        error: () => this.loaded.set(false),
      });
    });
  }

  toggle(): void {
    const user = this.auth.userId();
    if (this.busy() || !user) return;
    this.busy.set(true);
    this.error.set(null);
    const current = this.followId();
    if (current) {
      this.entities.delete(FOLLOW_ENTITY, current).subscribe({
        next: () => {
          this.followId.set(null);
          this.busy.set(false);
        },
        error: (e: ApiError) => this.fail(e),
      });
      return;
    }
    this.entities.create(FOLLOW_ENTITY, {
      user_id:     user,
      entity_name: this.entity(),
      record_id:   this.recordId(),
    }).subscribe({
      next: res => {
        this.followId.set(res.id || null);
        this.busy.set(false);
      },
      error: (e: ApiError) => this.fail(e),
    });
  }

  private fail(e: ApiError): void {
    this.busy.set(false);
    this.error.set(
      e.kind === 'forbidden' || e.kind === 'not_found'
        ? this.lang.translate('follow.error.notAllowed')
        : this.lang.translate('follow.error.failed'),
    );
  }
}
