import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { ApiError, ApiService } from '@attome/base';

interface SecurityContext {
  user_id:    string;
  is_admin:   boolean;
  privileges: string[];
}

@Component({
  selector:   'xrm-my-access',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls:  ['../../../styles/admin-page.css', './my-access.component.css'],
  templateUrl: './my-access.component.html',
})
export class MyAccessComponent implements OnInit {
  private readonly api = inject(ApiService);

  readonly ctx     = signal<SecurityContext | null>(null);
  readonly loading = signal(true);
  readonly error   = signal<string | null>(null);

  ngOnInit(): void {
    this.api.get<SecurityContext>('/api/v1/admin/security/whoami').subscribe({
      next:  c => { this.ctx.set(c); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }
}
