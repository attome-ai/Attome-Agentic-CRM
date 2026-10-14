import { DOCUMENT } from '@angular/common';
import {
  ChangeDetectionStrategy, Component, ElementRef, inject, signal,
} from '@angular/core';
import { Router } from '@angular/router';
import { TranslatePipe } from '@attome/base';
import {
  FavouriteItem, FavouriteList, FavouritesService, MAX_PINNED, RecentItem, recordFromUrl,
} from './favourites.service';

/**
 * The header's star button and its panel (B9-T3): pinned items with their
 * Ctrl+1..9 shortcuts, every list the person keeps or shares with a team
 * (drag to reorder, pin, remove), the current page added in one click, and
 * the records opened lately.
 */
@Component({
  selector: 'xrm-favourites',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  host: { '(document:click)': 'onDocumentClick($event)' },
  styleUrls: ['../header-dropdown.css', './favourites.component.css'],
  templateUrl: './favourites.component.html',
})
export class FavouritesComponent {
  protected readonly favourites = inject(FavouritesService);
  private readonly router = inject(Router);
  private readonly host = inject(ElementRef<HTMLElement>);
  private readonly document = inject(DOCUMENT);

  readonly isOpen = signal(false);
  /** The list and index being dragged. */
  readonly dragging = signal<{ listId: string; index: number } | null>(null);
  readonly maxPinned = MAX_PINNED;

  toggle(): void {
    const opening = !this.isOpen();
    this.isOpen.set(opening);
    if (opening) this.favourites.reload();
  }

  onDocumentClick(event: MouseEvent): void {
    if (this.isOpen() && !this.host.nativeElement.contains(event.target as Node)) {
      this.isOpen.set(false);
    }
  }

  open(item: Pick<FavouriteItem, 'kind' | 'entity' | 'ref'>): void {
    this.favourites.open(item);
    this.isOpen.set(false);
  }

  openRecent(item: RecentItem): void {
    this.open({ kind: 'record', entity: item.entity, ref: item.record_id });
  }

  /** Keeps the page now open: the record when it is a record's form. */
  addCurrent(): void {
    const url = this.router.url;
    const record = recordFromUrl(url);
    if (record) {
      if (!this.favourites.listWithRecord(record.entity, record.record_id)) {
        this.favourites.toggleRecord(record.entity, record.record_id, null);
      }
      return;
    }
    this.favourites.add({ kind: 'page', entity: null, ref: url, label: this.document.title || url, pinned: false });
  }

  itemLabel(item: FavouriteItem): string {
    return item.label || (item.kind === 'record' ? `${item.entity} ${item.ref.slice(0, 8)}` : item.ref);
  }

  recentLabel(item: RecentItem): string {
    return item.label || `${item.entity} ${item.record_id.slice(0, 8)}`;
  }

  icon(item: Pick<FavouriteItem, 'kind'>): string {
    return item.kind === 'record' ? 'las la-file-alt' : item.kind === 'view' ? 'las la-list' : 'las la-link';
  }

  pinIndex(item: FavouriteItem): number {
    return this.favourites.pinned().findIndex(p => p.id === item.id) + 1;
  }

  canPin(list: FavouriteList, item: FavouriteItem): boolean {
    return item.pinned || list.items.filter(i => i.pinned).length < MAX_PINNED;
  }

  // ── Drag to reorder, within one list ──────────────────────────────────────
  onDragStart(list: FavouriteList, index: number, event: DragEvent): void {
    this.dragging.set({ listId: list.id, index });
    event.dataTransfer?.setData('text/plain', String(index));
  }

  onDragOver(list: FavouriteList, event: DragEvent): void {
    if (this.dragging()?.listId === list.id) event.preventDefault();
  }

  onDrop(list: FavouriteList, index: number, event: DragEvent): void {
    event.preventDefault();
    const from = this.dragging();
    this.dragging.set(null);
    if (from && from.listId === list.id && from.index !== index) {
      this.favourites.move(list, from.index, index);
    }
  }

  /** Keyboard reordering for those who do not drag: Alt+Up / Alt+Down. */
  onItemKeydown(list: FavouriteList, index: number, event: KeyboardEvent): void {
    if (event.key === 'Enter') {
      this.open(list.items[index]);
      return;
    }
    if (!event.altKey) return;
    if (event.key === 'ArrowUp' && index > 0) {
      event.preventDefault();
      this.favourites.move(list, index, index - 1);
    } else if (event.key === 'ArrowDown' && index < list.items.length - 1) {
      event.preventDefault();
      this.favourites.move(list, index, index + 1);
    }
  }
}
