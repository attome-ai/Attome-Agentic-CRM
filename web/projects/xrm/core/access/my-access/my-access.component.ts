import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { ApiError, SdkService } from '@attome/base';
import { MySessionsComponent } from './my-sessions.component';

interface SecurityContext {
  user_id:    string;
  is_admin:   boolean;
  privileges: string[];
}

@Component({
  selector:   'xrm-my-access',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [MySessionsComponent],
  styleUrls:  ['../../../styles/admin-page.css', './my-access.component.css'],
  templateUrl: './my-access.component.html',
})
export class MyAccessComponent implements OnInit {
  private readonly sdk = inject(SdkService);

  readonly ctx     = signal<SecurityContext | null>(null);
  readonly loading = signal(true);
  readonly error   = signal<string | null>(null);

  ngOnInit(): void {
    this.sdk.get<SecurityContext>('/api/v1/admin/security/whoami').subscribe({
      next:  c => { this.ctx.set(c); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }
}
