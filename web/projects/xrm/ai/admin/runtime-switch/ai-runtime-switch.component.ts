import {
  ChangeDetectionStrategy, Component, DestroyRef, OnInit, inject, signal,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { LocalDatePipe, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import { AdminAiService } from '../../services/admin-ai.service';
import type { SurfaceSwitchView } from '../../services/admin-ai.service';

/**
 * The runtime AI switch (C11 B5, row A-85): turn an AI surface off — or back
 * on — without a restart.
 *
 * **It can only narrow.** Each row shows what the configuration allows beside
 * what the runtime switch says, and the effect of the two together, so "off in
 * the configuration" and "off at runtime" can never be confused: turning a
 * surface back on here restores what the configuration allows and nothing
 * more. A switch whose state could not be read shows as unknown, and every AI
 * surface treats that as off.
 *
 * Shown only to administrators: the read is `system.admin`, and a 403 hides
 * the whole card rather than showing a control that would be refused.
 */
@Component({
  selector: 'attome-ai-runtime-switch',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, LocalDatePipe, TranslatePipe],
  styleUrls: ['./ai-runtime-switch.component.css'],
  templateUrl: './ai-runtime-switch.component.html',
})
export class AiRuntimeSwitchComponent implements OnInit {
  private readonly adminAi = inject(AdminAiService);
  private readonly destroyRef = inject(DestroyRef);

  readonly surfaces = signal<SurfaceSwitchView[]>([]);
  /** False until the first read answers; a 403 keeps the card hidden. */
  readonly visible = signal(false);
  readonly busy = signal<string | null>(null);
  readonly error = signal<string | null>(null);
  readonly reason = signal('');
  /** The surface whose switch-off waits for its reason and confirmation. */
  readonly confirming = signal<string | null>(null);

  ngOnInit(): void {
    this.adminAi
      .runtimeSwitch()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (view) => {
          this.surfaces.set(view.surfaces);
          this.visible.set(true);
        },
        error: (err: ApiError) => {
          // Not an administrator, or the route is not there: no card at all.
          if (err.status !== 403 && err.status !== 404) this.error.set(err.message);
        },
      });
  }

  /** Switching off asks for a reason first; switching on does not. */
  toggle(surface: SurfaceSwitchView): void {
    if (surface.runtime_enabled === false) {
      this.set(surface.surface, true);
    } else {
      this.reason.set('');
      this.confirming.set(surface.surface);
    }
  }

  confirmOff(): void {
    const surface = this.confirming();
    if (!surface) return;
    this.set(surface, false, this.reason().trim() || null);
  }

  cancel(): void {
    this.confirming.set(null);
  }

  private set(surface: string, enabled: boolean, reason: string | null = null): void {
    this.busy.set(surface);
    this.error.set(null);
    this.adminAi
      .setRuntimeSwitch(surface, enabled, reason)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (view) => {
          this.surfaces.set(view.surfaces);
          this.busy.set(null);
          this.confirming.set(null);
        },
        error: (err: ApiError) => {
          this.busy.set(null);
          this.error.set(err.message);
        },
      });
  }
}
