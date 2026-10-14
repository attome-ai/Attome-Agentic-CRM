import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { ApiError, ApiService, LocalDatePipe, TranslatePipe, type Page } from '@attome/base';

/** One switched scope (`scope_switch::ScopeSwitchView`). */
export interface ScopeSwitch {
  scope_kind: string;
  scope_key:  string;
  enabled:    boolean;
  cause:      string;
  reason:     string | null;
  changed_by: string | null;
  changed_at: string;
}

export const SCOPE_KINDS = ['agent', 'model', 'provider', 'tool', 'channel'] as const;

/**
 * Scoped AI switches (roadmap N31-T2): what is off, why, and who did it;
 * turn a scope off, or back on (the server requires a different
 * administrator from the one who turned it off). Logical CSS only.
 */
@Component({
  selector:        'xrm-ai-scope-switches',
  standalone:      true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:         [LocalDatePipe, TranslatePipe],
  templateUrl:     './ai-scope-switches.component.html',
  styleUrls:       ['./ai-scope-switches.component.css'],
})
export class AiScopeSwitchesComponent implements OnInit {
  private readonly api = inject(ApiService);

  readonly kinds    = SCOPE_KINDS;
  readonly switches = signal<ScopeSwitch[]>([]);
  readonly error    = signal<string | null>(null);
  readonly busy     = signal(false);
  readonly newKind  = signal<string>('tool');
  readonly newKey   = signal('');
  readonly newReason = signal('');

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.api.get<Page<ScopeSwitch>>('/api/v1/admin/ai/switches').subscribe({
      next: page => this.switches.set(page.items ?? []),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  set(kind: string, key: string, enabled: boolean, reason: string | null): void {
    if (!key.trim()) return;
    this.busy.set(true);
    this.error.set(null);
    this.api.put<void>(
      `/api/v1/admin/ai/switches/${encodeURIComponent(kind)}/${encodeURIComponent(key.trim())}`,
      { enabled, reason },
    ).subscribe({
      next: () => { this.busy.set(false); this.newKey.set(''); this.newReason.set(''); this.load(); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  switchOff(): void {
    this.set(this.newKind(), this.newKey(), false, this.newReason().trim() || null);
  }
}
