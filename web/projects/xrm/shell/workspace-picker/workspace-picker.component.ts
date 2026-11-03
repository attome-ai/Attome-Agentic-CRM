import { DOCUMENT } from '@angular/common';
import { ChangeDetectionStrategy, Component, DestroyRef, computed, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { SdkService, TranslatePipe, WORKSPACE_ROUTES, WorkspaceState } from '@attome/base';
import { AccessService } from '@attome/xrm/core/access/data';
import { EMPTY, switchMap } from 'rxjs';

/** Who builds in workspaces (T1-T3): administrators, data modellers and builders. */
const BUILDER_PRIVILEGES = ['system.admin', 'admin.data_model', 'develop.build'];

/** One workspace, as `GET /api/v1/admin/workspaces` lists it. */
interface WorkspaceRow {
  id: string;
  name: string;
  status: string;
}

interface WorkspacePage {
  items: WorkspaceRow[];
}

let nextId = 0;

/**
 * T5-T7 — the header's workspace picker: work on live or inside one of the
 * open Develop workspaces, or make a new one and enter it. Choosing sets
 * `WorkspaceState` (every later request names it) and reloads the page so
 * every screen reads from where it now works. Builders only (T1-T3): the
 * workspace routes refuse anyone else, so nobody else asks.
 */
@Component({
  selector: 'xrm-workspace-picker',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    @if (visible()) {
      <div class="wp" role="group" [attr.aria-label]="'workspaces.picker.label' | translate"
           [class.wp-inside]="state.inside()">
        <i class="las la-layer-group wp-icon" aria-hidden="true"></i>
        @if (failed()) {
          <span class="wp-text" role="alert">{{ 'workspaces.picker.failed' | translate }}</span>
        } @else {
          <label class="visually-hidden" [for]="selectId">{{ 'workspaces.picker.label' | translate }}</label>
          <select class="wp-select" [id]="selectId" (change)="onPick($event)">
            <option value="" [selected]="!state.active()">{{ 'workspaces.picker.live' | translate }}</option>
            @for (w of open(); track w.id) {
              <option [value]="w.id" [selected]="w.id === state.active()?.id">{{ w.name }}</option>
            }
          </select>
        }
        @if (creating()) {
          <label class="visually-hidden" [for]="nameId">{{ 'workspaces.picker.name' | translate }}</label>
          <input class="wp-name" [id]="nameId" type="text" maxlength="100"
                 [placeholder]="'workspaces.picker.name' | translate"
                 [value]="draftName()" (input)="draftName.set($any($event.target).value)" />
          <button type="button" class="wp-create" (click)="create()"
                  [disabled]="busy() || !draftName().trim()">
            {{ 'workspaces.picker.create' | translate }}
          </button>
          <button type="button" class="wp-cancel" (click)="creating.set(false)">
            {{ 'workspaces.picker.cancel' | translate }}
          </button>
        } @else {
          <button type="button" class="wp-new" (click)="creating.set(true)"
                  [attr.aria-label]="'workspaces.picker.new' | translate"
                  [title]="'workspaces.picker.new' | translate">
            <i class="las la-plus" aria-hidden="true"></i>
          </button>
        }
        @if (createFailed()) {
          <span class="wp-text" role="alert">{{ 'workspaces.picker.createFailed' | translate }}</span>
        }
      </div>
    }
  `,
  styles: [`
    .wp { display: flex; align-items: center; gap: 0.375rem; font-size: 0.8125rem; }
    .wp-inside .wp-icon { color: var(--color-warning, #b45309); }
    .wp-select, .wp-name { max-inline-size: 12rem; }
    .wp-text { color: var(--color-text-secondary); }
  `],
})
export class WorkspacePickerComponent {
  private readonly access = inject(AccessService);
  private readonly sdk = inject(SdkService);
  private readonly document = inject(DOCUMENT);
  private readonly destroyRef = inject(DestroyRef);
  readonly state = inject(WorkspaceState);

  readonly selectId = `xrm-workspace-pick-${nextId}`;
  readonly nameId = `xrm-workspace-name-${nextId++}`;

  private readonly rows = signal<WorkspaceRow[]>([]);
  private readonly loaded = signal(false);
  readonly failed = signal(false);
  readonly creating = signal(false);
  readonly createFailed = signal(false);
  readonly busy = signal(false);
  readonly draftName = signal('');

  readonly visible = computed(() => this.loaded() && this.builds());
  readonly open = computed(() => this.rows().filter(w => w.status === 'open'));

  constructor() {
    this.access.ready().pipe(
      switchMap(() => (this.builds()
        ? this.sdk.get<WorkspacePage>(WORKSPACE_ROUTES, { query: { page_size: 100 } })
        : EMPTY)),
      takeUntilDestroyed(this.destroyRef),
    ).subscribe({
      next: page => {
        this.rows.set(page.items);
        this.loaded.set(true);
        // A workspace published or discarded elsewhere: back to live.
        const chosen = this.state.active();
        if (chosen && !page.items.some(w => w.id === chosen.id && w.status === 'open')) this.state.leave();
      },
      error: () => {
        this.failed.set(true);
        this.loaded.set(true);
      },
    });
  }

  private builds(): boolean {
    return BUILDER_PRIVILEGES.some(p => this.access.hasPrivilege(p));
  }

  onPick(event: Event): void {
    const id = (event.target as HTMLSelectElement | null)?.value ?? '';
    const row = this.open().find(w => w.id === id);
    if (row) this.state.enter({ id: row.id, name: row.name });
    else this.state.leave();
    this.reload();
  }

  create(): void {
    const name = this.draftName().trim();
    if (!name) return;
    this.busy.set(true);
    this.createFailed.set(false);
    this.sdk.post<WorkspaceRow>(WORKSPACE_ROUTES, { body: { name } })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: made => {
          this.busy.set(false);
          this.state.enter({ id: made.id, name: made.name });
          this.reload();
        },
        error: () => {
          this.busy.set(false);
          this.createFailed.set(true);
        },
      });
  }

  /** Every screen re-reads from where the tab now works. */
  private reload(): void {
    try {
      this.document.defaultView?.location.reload();
    } catch {
      // No reload where there is no window (tests); the next navigation reads afresh.
    }
  }
}
