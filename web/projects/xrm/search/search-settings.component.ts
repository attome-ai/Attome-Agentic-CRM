import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { LangService, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import {
  SearchAttributeSetting,
  SearchEntitySettings,
  SearchIndexSize,
  SearchPageService,
  SearchPin,
  SearchQuality,
  SearchStatus,
  SearchStopword,
  SearchSynonym,
} from './services/search-page.service';

/** The modes an attribute takes in the index. */
export const ATTRIBUTE_MODES = ['key', 'text', 'off'] as const;

/** Bytes as a short size for the size panel. Pure. */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${Math.round(value * 10) / 10} ${units[unit]}`;
}

/**
 * Search administration (A25-T11): per entity, each attribute's mode
 * (key, text, off) and weight with the index size and the indexing backlog;
 * the synonym, stop-word and pin editors; and the quality panel. Saving an
 * entity sends its `row_version` as `If-Match`.
 */
@Component({
  selector: 'xrm-search-settings',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  templateUrl: './search-settings.component.html',
  styleUrls: ['./search-settings.component.css'],
})
export class SearchSettingsComponent implements OnInit {
  private readonly api = inject(SearchPageService);
  private readonly lang = inject(LangService);

  protected readonly modes = ATTRIBUTE_MODES;
  protected readonly size = signal<SearchIndexSize | null>(null);
  protected readonly status = signal<SearchStatus | null>(null);
  protected readonly quality = signal<SearchQuality | null>(null);
  protected readonly entity = signal<string | null>(null);
  protected readonly settings = signal<SearchEntitySettings | null>(null);
  protected readonly attributes = signal<SearchAttributeSetting[]>([]);
  protected readonly synonyms = signal<SearchSynonym[]>([]);
  protected readonly stopwords = signal<SearchStopword[]>([]);
  protected readonly pins = signal<SearchPin[]>([]);
  protected readonly error = signal<string | null>(null);
  protected readonly saving = signal(false);
  protected readonly savedNote = signal(false);

  protected readonly newSynonym = signal('');
  protected readonly newStopword = signal('');
  protected readonly listLang = signal<'en' | 'ar'>('en');
  protected readonly pinQuery = signal('');
  protected readonly pinEntity = signal('');
  protected readonly pinRecord = signal('');

  protected readonly entities = computed(() => (this.size()?.entities ?? []).map(e => e.entity));
  protected readonly entityRows = computed(() => {
    const name = this.entity();
    return this.size()?.entities.find(e => e.entity === name)?.rows ?? null;
  });
  protected readonly entityBytes = computed(() => {
    const name = this.entity();
    const measured = this.status()?.sizes.find(s => s.entity_logicalname === name);
    return measured ? formatBytes(measured.bytes) : null;
  });
  protected readonly backlog = computed(() => this.status()?.backlog ?? null);

  ngOnInit(): void {
    this.api.size().subscribe({ next: s => this.size.set(s), error: e => this.fail(e) });
    this.api.status().subscribe({ next: s => this.status.set(s), error: e => this.fail(e) });
    this.api.quality().subscribe({ next: q => this.quality.set(q), error: e => this.fail(e) });
    this.loadLists();
  }

  protected bytes(n: number): string {
    return formatBytes(n);
  }

  protected percent(value: number): string {
    return `${Math.round(value * 1000) / 10}`;
  }

  protected chooseEntity(event: Event): void {
    const name = (event.target as HTMLSelectElement).value;
    this.entity.set(name || null);
    this.settings.set(null);
    this.attributes.set([]);
    if (!name) return;
    this.api.entitySettings(name).subscribe({
      next: s => {
        this.settings.set(s);
        this.attributes.set(s.attributes.map(a => ({ ...a })));
      },
      error: e => this.fail(e),
    });
  }

  /** Sets one attribute's mode. */
  setMode(attribute: string, mode: string): void {
    this.attributes.update(all => all.map(a => (a.attribute === attribute ? { ...a, mode } : a)));
    this.savedNote.set(false);
  }

  protected onMode(attribute: string, event: Event): void {
    this.setMode(attribute, (event.target as HTMLSelectElement).value);
  }

  protected onWeight(attribute: string, event: Event): void {
    const weight = Number((event.target as HTMLInputElement).value);
    if (!Number.isFinite(weight)) return;
    this.attributes.update(all => all.map(a => (a.attribute === attribute ? { ...a, weight } : a)));
    this.savedNote.set(false);
  }

  /** Saves the attribute modes and weights at the loaded `row_version`. */
  save(): void {
    const current = this.settings();
    const entity = this.entity();
    if (!current || !entity) return;
    this.saving.set(true);
    this.api.saveEntitySettings(entity, { attributes: this.attributes() }, current.row_version).subscribe({
      next: s => {
        this.saving.set(false);
        this.settings.set(s);
        this.attributes.set(s.attributes.map(a => ({ ...a })));
        this.savedNote.set(true);
      },
      error: e => {
        this.saving.set(false);
        this.fail(e);
      },
    });
  }

  protected onText(target: 'synonym' | 'stopword' | 'pinQuery' | 'pinEntity' | 'pinRecord', event: Event): void {
    const value = (event.target as HTMLInputElement).value;
    const map = {
      synonym: this.newSynonym,
      stopword: this.newStopword,
      pinQuery: this.pinQuery,
      pinEntity: this.pinEntity,
      pinRecord: this.pinRecord,
    };
    map[target].set(value);
  }

  protected onLang(event: Event): void {
    this.listLang.set((event.target as HTMLSelectElement).value === 'ar' ? 'ar' : 'en');
  }

  protected addSynonym(): void {
    const terms = this.newSynonym().split(/[,،]/).map(t => t.trim()).filter(Boolean);
    if (terms.length < 2) {
      this.error.set(this.lang.translate('searchSettings.synonymNeedsTwo'));
      return;
    }
    this.api.addSynonym(terms, this.listLang()).subscribe({
      next: () => {
        this.newSynonym.set('');
        this.loadLists();
      },
      error: e => this.fail(e),
    });
  }

  protected deleteSynonym(id: string): void {
    this.api.deleteSynonym(id).subscribe({ next: () => this.loadLists(), error: e => this.fail(e) });
  }

  protected addStopword(): void {
    const word = this.newStopword().trim();
    if (!word) return;
    this.api.addStopword(word, this.listLang()).subscribe({
      next: () => {
        this.newStopword.set('');
        this.loadLists();
      },
      error: e => this.fail(e),
    });
  }

  protected deleteStopword(word: string): void {
    this.api.deleteStopword(word).subscribe({ next: () => this.loadLists(), error: e => this.fail(e) });
  }

  protected addPin(): void {
    const query = this.pinQuery().trim();
    const entity = this.pinEntity().trim();
    const recordId = this.pinRecord().trim();
    if (!query || !entity || !recordId) return;
    this.api.addPin({ query, entity, record_id: recordId }).subscribe({
      next: () => {
        this.pinQuery.set('');
        this.pinRecord.set('');
        this.loadLists();
      },
      error: e => this.fail(e),
    });
  }

  protected deletePin(id: string): void {
    this.api.deletePin(id).subscribe({ next: () => this.loadLists(), error: e => this.fail(e) });
  }

  private loadLists(): void {
    this.api.synonyms().subscribe({ next: p => this.synonyms.set(p.items), error: e => this.fail(e) });
    this.api.stopwords().subscribe({ next: p => this.stopwords.set(p.items), error: e => this.fail(e) });
    this.api.pins().subscribe({ next: p => this.pins.set(p.items), error: e => this.fail(e) });
  }

  private fail(e: ApiError): void {
    this.error.set(e.message ?? this.lang.translate('searchSettings.failed'));
  }
}
