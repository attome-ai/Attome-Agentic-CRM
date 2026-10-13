import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from '@attome/base';

// ── Response types (mirror attome_jobs::DeadLetterJobRow / attome_api::jobs_admin exactly) ──

export interface DeadLetterJobItem {
  id:           string;
  variant:      string;
  attempts:     number;
  max_attempts: number;
  last_error:   string | null;
  run_at:       string;
  done_at:      string | null;
}

export interface DeadLetterJobsPage {
  items:     DeadLetterJobItem[];
  total:     number;
  page:      number;
  page_size: number;
}

export interface ReplayResponse {
  replayed: boolean;
}

@Injectable({ providedIn: 'root' })
export class JobsAdminService {
  private readonly api = inject(ApiService);

  /** `queue`: `"fast"` (default) or `"batch"` — see `EngineJob::is_batch`. */
  listDeadLetter(queue: 'fast' | 'batch', page = 1, pageSize = 50): Observable<DeadLetterJobsPage> {
    return this.api.get<DeadLetterJobsPage>('/api/v1/admin/jobs/dead-letter', {
      queue, page: String(page), page_size: String(pageSize),
    });
  }

  replay(id: string): Observable<ReplayResponse> {
    return this.api.post<ReplayResponse>(`/api/v1/admin/jobs/${id}/replay`, {});
  }
}
