import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { AuthService, LangService, TranslatePipe } from '@attome/base';
import { EntityService } from '../services/entity.service';
import { FOLLOW_ENTITY } from './follow-button.component';

/** One record the person follows. */
export interface FollowedRecord {
  followId: string;
  entity: string;
  recordId: string;
  since: string;
}

/** Most follows listed. */
const MAX_FOLLOWS = 200;

/**
 * C2-T2: the records the signed-in person follows, newest first, each
 * linking to its record with a way to stop following it.
 */
@Component({
  selector: 'xrm-following-list',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe, RouterLink],
  styleUrls: ['./follow-button.component.css'],
  template: `
    <section class="fl-page" [attr.aria-label]="'follow.listTitle' | translate">
      <h1 class="fl-title">{{ 'follow.listTitle' | translate }}</h1>
      @if (error(); as message) {
        <p class="fb-error" role="alert">{{ message }}</p>
      } @else if (!loaded()) {
        <p role="status">{{ 'follow.loading' | translate }}</p>
      } @else if (rows().length === 0) {
        <p data-testid="following-empty">{{ 'follow.empty' | translate }}</p>
      } @else {
        <ul class="fl-list">
          @for (row of rows(); track row.followId) {
            <li class="fl-row" data-testid="following-row">
              <a [routerLink]="['/xrm/entity', row.entity, 'form']" [queryParams]="{ id: row.recordId }">{{ row.entity }} · {{ row.recordId }}</a>
              <button type="button" class="fb-btn" (click)="unfollow(row)"
                      [attr.aria-label]="'follow.unfollowHint' | translate">
                <i class="las la-bell-slash" aria-hidden="true"></i>
                {{ 'follow.unfollow' | translate }}
              </button>
            </li>
          }
        </ul>
      }
    </section>
  `,
  styles: [`
    .fl-page { padding-block: 24px; padding-inline: 24px; display: grid; gap: 16px; }
    .fl-title { margin: 0; font-size: 20px; }
    .fl-list { list-style: none; margin: 0; padding: 0; display: grid; gap: 8px; }
    .fl-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
  `],
})
export class FollowingListComponent implements OnInit {
  private readonly entities = inject(EntityService);
  private readonly auth     = inject(AuthService);
  private readonly lang     = inject(LangService);

  readonly rows   = signal<FollowedRecord[]>([]);
  readonly loaded = signal(false);
  readonly error  = signal<string | null>(null);

  ngOnInit(): void {
    const user = this.auth.userId();
    if (!user) {
      this.loaded.set(true);
      return;
    }
    this.entities.list(FOLLOW_ENTITY, {
      filters: [{ field: 'user_id', op: 'eq', value: user }],
      sorts: [{ field: 'created_at', dir: 'desc' }],
      limit: MAX_FOLLOWS,
    }).subscribe({
      next: page => {
        this.rows.set(page.data.map(r => ({
          followId: r.id,
          entity: String(r.data['entity_name'] ?? ''),
          recordId: String(r.data['record_id'] ?? ''),
          since: r.created_at,
        })));
        this.loaded.set(true);
      },
      error: () => this.error.set(this.lang.translate('follow.error.failed')),
    });
  }

  unfollow(row: FollowedRecord): void {
    this.entities.delete(FOLLOW_ENTITY, row.followId).subscribe({
      next: () => this.rows.update(rows => rows.filter(r => r.followId !== row.followId)),
      error: () => this.error.set(this.lang.translate('follow.error.failed')),
    });
  }
}
