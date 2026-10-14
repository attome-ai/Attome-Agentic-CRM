import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { ApiError, TranslatePipe } from '@attome/base';

import { KindView, ModelService, ObjectSummary, ObjectVersion, PatchOp, VersionSummary } from '../model.service';

/**
 * The metadata explorer (roadmap Y1-T15): pick a kind, then one of its
 * objects, then two of its versions to compare side by side with the
 * operations between them. Read-only. Layout uses logical CSS properties
 * only, so Arabic (right to left) needs nothing extra.
 */
@Component({
  selector:        'xrm-metadata-explorer',
  standalone:      true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:         [TranslatePipe],
  templateUrl:     './metadata-explorer.component.html',
  styleUrls:       ['./metadata-explorer.component.css'],
})
export class MetadataExplorerComponent implements OnInit {
  private readonly model = inject(ModelService);

  readonly kinds    = signal<KindView[]>([]);
  readonly kind     = signal<string | null>(null);
  readonly objects  = signal<ObjectSummary[]>([]);
  readonly page     = signal(1);
  readonly pages    = signal(1);
  readonly object   = signal<ObjectSummary | null>(null);
  readonly versions = signal<VersionSummary[]>([]);
  readonly from     = signal<number | null>(null);
  readonly to       = signal<number | null>(null);
  readonly ops      = signal<PatchOp[]>([]);
  readonly left     = signal<ObjectVersion | null>(null);
  readonly right    = signal<ObjectVersion | null>(null);
  readonly error    = signal<string | null>(null);

  /** Both sides chosen and different: the diff can be shown. */
  readonly comparing = computed(() => {
    const from = this.from();
    const to = this.to();
    return from !== null && to !== null && from !== to;
  });

  ngOnInit(): void {
    this.model.kinds().subscribe({
      next: page => this.kinds.set(page.items),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  selectKind(name: string): void {
    this.kind.set(name);
    this.object.set(null);
    this.versions.set([]);
    this.clearDiff();
    this.loadObjects(1);
  }

  loadObjects(page: number): void {
    const kind = this.kind();
    if (!kind) return;
    this.model.objects(kind, page).subscribe({
      next: result => {
        this.objects.set(result.items);
        this.page.set(result.page);
        this.pages.set(Math.max(1, Math.ceil(result.total / Math.max(1, result.page_size))));
      },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  selectObject(object: ObjectSummary): void {
    const kind = this.kind();
    if (!kind) return;
    this.object.set(object);
    this.clearDiff();
    this.model.history(kind, object.id).subscribe({
      next: page => {
        this.versions.set(page.items);
        // Newest first: compare the newest with the one before it.
        if (page.items.length >= 2) {
          this.compare(page.items[1].version_no, page.items[0].version_no);
        }
      },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  compare(from: number, to: number): void {
    const kind = this.kind();
    const object = this.object();
    if (!kind || !object) return;
    this.from.set(from);
    this.to.set(to);
    if (from === to) {
      this.ops.set([]);
      return;
    }
    this.model.diff(kind, object.id, from, to).subscribe({
      next: page => this.ops.set(page.items),
      error: (e: ApiError) => this.error.set(e.message),
    });
    this.model.version(kind, object.id, from).subscribe({
      next: v => this.left.set(v),
      error: (e: ApiError) => this.error.set(e.message),
    });
    this.model.version(kind, object.id, to).subscribe({
      next: v => this.right.set(v),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  setFrom(value: string): void {
    const to = this.to();
    if (to !== null) this.compare(Number(value), to);
    else this.from.set(Number(value));
  }

  setTo(value: string): void {
    const from = this.from();
    if (from !== null) this.compare(from, Number(value));
    else this.to.set(Number(value));
  }

  pretty(version: ObjectVersion | null): string {
    return version ? JSON.stringify(version.doc, null, 2) : '';
  }

  private clearDiff(): void {
    this.from.set(null);
    this.to.set(null);
    this.ops.set([]);
    this.left.set(null);
    this.right.set(null);
  }
}
