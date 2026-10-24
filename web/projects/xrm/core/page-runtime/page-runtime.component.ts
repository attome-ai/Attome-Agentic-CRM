import {
  ChangeDetectionStrategy, Component, DestroyRef, computed, effect, inject, input, signal, untracked,
} from '@angular/core';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { EntityService } from '@attome/xrm/core/entity';
import { catchError, of } from 'rxjs';

import { PageContext } from './page-context';
import { PageDataService } from './page-data.service';
import { Device, PageDoc, deviceOf } from './page-model';
import { PageNodeComponent } from './page-node.component';

/**
 * T2-T2 — renders a published page (the page kind, T2-T1): its component
 * tree from the palette (container, tabs, text, list, form, chart, kanban,
 * map, timeline, metric, button, custom), each component's data read under
 * the signed-in person's own rights, its events (start a flow, run an
 * action, navigate inside the app), and visibility by role, screen size
 * and a condition on the page's record. Routed at `pages/:id`, with
 * `?entity=&record=` for a record page; a host can pass `page` directly
 * (the designer's preview).
 */
@Component({
  selector: 'xrm-page-runtime',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [PageNodeComponent, TranslatePipe],
  providers: [PageContext],
  host: { '(window:resize)': 'onResize()' },
  template: `
    <main class="pr" [attr.dir]="arabic() ? 'rtl' : 'ltr'" data-testid="page-runtime">
      @if (error(); as e) {
        <p class="pr-error" role="alert">{{ e }}</p>
      } @else if (doc(); as d) {
        @if (title(); as t) { <h1 class="pr-title">{{ t }}</h1> }
        <xrm-page-node [node]="d.root" />
      } @else {
        <p class="pr-muted">{{ 'pageRuntime.loading' | translate }}</p>
      }
    </main>
  `,
  styles: [`
    .pr { display: grid; gap: var(--space-3, .75rem); padding: var(--space-4, 1rem); }
    .pr-title { margin: 0; font-size: 1.5rem; }
    .pr-error { color: var(--color-danger, #c53030); }
    .pr-muted { color: var(--color-text-secondary, #666); }
  `],
})
export class PageRuntimeComponent {
  private readonly data = inject(PageDataService);
  private readonly entities = inject(EntityService);
  private readonly lang = inject(LangService);
  private readonly ctx = inject(PageContext);
  private readonly destroyRef = inject(DestroyRef);

  /** The published page to load (route parameter). */
  readonly id = input<string | undefined>(undefined);
  /** A page document to render as is, instead of loading one. */
  readonly page = input<PageDoc | null>(null);
  /** On a record page: the record's entity (logical name) and id. */
  readonly entity = input<string | undefined>(undefined);
  readonly record = input<string | undefined>(undefined);
  /** T2-T3 preview: render as if the person held these roles, on this size, in this language. */
  readonly previewRoles = input<readonly string[] | null>(null);
  readonly previewDevice = input<Device | null>(null);
  readonly previewArabic = input<boolean | null>(null);

  protected readonly loaded = signal<PageDoc | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly doc = computed(() => this.page() ?? this.loaded());
  protected readonly arabic = computed(() => this.previewArabic() ?? this.lang.isRtl());
  protected readonly title = computed(() => {
    const d = this.doc();
    if (!d) return '';
    return (this.arabic() ? d.title_ar ?? d.title_en : d.title_en ?? d.title_ar) ?? '';
  });

  constructor() {
    this.onResize();
    effect(() => this.ctx.arabic.set(this.arabic()));
    const roles = this.data.myRoles().subscribe(r => {
      if (this.previewRoles() === null) this.ctx.roles.set(r);
    });
    this.destroyRef.onDestroy(() => roles.unsubscribe());
    effect(() => {
      const preview = this.previewRoles();
      if (preview !== null) this.ctx.roles.set(preview);
    });
    effect(() => {
      const device = this.previewDevice();
      if (device !== null) this.ctx.device.set(device);
      else untracked(() => this.onResize());
    });
    effect(() => {
      const id = this.id();
      untracked(() => {
        if (id && !this.page()) this.loadPage(id);
      });
    });
    effect(() => {
      const entity = this.entity() ?? null;
      const record = this.record() ?? null;
      untracked(() => this.loadRecord(entity, record));
    });
  }

  onResize(): void {
    if (this.previewDevice() !== null) return;
    if (typeof window !== 'undefined') this.ctx.device.set(deviceOf(window.innerWidth));
  }

  private loadPage(id: string): void {
    this.error.set(null);
    this.data.page(id).pipe(
      catchError((e: ApiError) => {
        this.error.set(e.status === 404 ? this.lang.translate('pageRuntime.notFound') : this.lang.errorText(e));
        return of(null);
      }),
    ).subscribe(doc => {
      if (doc) this.loaded.set(doc);
    });
  }

  private loadRecord(entity: string | null, record: string | null): void {
    this.ctx.entity.set(entity);
    this.ctx.recordId.set(record);
    this.ctx.record.set(null);
    this.ctx.schema.set(null);
    if (!entity) return;
    this.entities.getSchema(entity).pipe(catchError(() => of(null))).subscribe(s => this.ctx.schema.set(s));
    if (!record) return;
    this.data.record(entity, record).pipe(catchError(() => of(null))).subscribe(r => this.ctx.record.set(r));
  }
}
