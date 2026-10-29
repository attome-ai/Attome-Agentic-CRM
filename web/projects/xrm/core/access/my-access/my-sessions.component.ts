import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { ApiError, ApiService, LocalDatePipe, TranslatePipe } from '@attome/base';

/** One of the caller's own sessions (`GET /api/v1/auth/sessions`, Q8-T4). */
export interface MySession {
  id: string;
  device_label: string | null;
  user_agent: string | null;
  sign_in_method: string | null;
  client_kind: string;
  created_at: string;
  last_activity_at: string | null;
  is_current: boolean;
}

interface SessionPage {
  items: MySession[];
  total: number;
  page: number;
  page_size: number;
}

/**
 * Q8-T9 step 1: the person's own sessions, with "this device" marked, and
 * ending one or every other. Ending the current session is not offered here:
 * that is signing out.
 */
@Component({
  selector: 'xrm-my-sessions',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, TranslatePipe],
  styleUrls: ['../../../styles/admin-page.css', './my-sessions.component.css'],
  templateUrl: './my-sessions.component.html',
})
export class MySessionsComponent implements OnInit {
  private readonly api = inject(ApiService);

  readonly sessions = signal<MySession[]>([]);
  readonly loading = signal(true);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.loading.set(true);
    this.api.get<SessionPage>('/api/v1/auth/sessions', { page_size: '200' }).subscribe({
      next: (page) => {
        this.sessions.set(page.items);
        this.error.set(null);
        this.loading.set(false);
      },
      error: (e: ApiError) => {
        this.error.set(e.message);
        this.loading.set(false);
      },
    });
  }

  hasOthers(): boolean {
    return this.sessions().some((s) => !s.is_current);
  }

  end(session: MySession): void {
    this.run(this.api.delete(`/api/v1/auth/sessions/${encodeURIComponent(session.id)}`));
  }

  endOthers(): void {
    this.run(this.api.post<void>('/api/v1/auth/sessions/end-others', {}));
  }

  private run(call: ReturnType<ApiService['delete']>): void {
    this.busy.set(true);
    call.subscribe({
      next: () => {
        this.busy.set(false);
        this.load();
      },
      error: (e: ApiError) => {
        this.error.set(e.message);
        this.busy.set(false);
      },
    });
  }
}
