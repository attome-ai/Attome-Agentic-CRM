import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { SearchSettingsComponent, formatBytes } from './search-settings.component';
import { SearchEntitySettings, SearchPageService } from './services/search-page.service';

const SETTINGS: SearchEntitySettings = {
  entity: 'account',
  enabled: true,
  boost: 1,
  document_embedding: false,
  image_embedding: false,
  max_age_days: null,
  row_version: 4,
  attributes: [
    { attribute: 'name', mode: 'text', weight: 1 },
    { attribute: 'cr_number', mode: 'off', weight: 1 },
  ],
};

describe('SearchSettingsComponent', () => {
  let api: Record<string, ReturnType<typeof vi.fn>>;

  beforeEach(() => {
    const empty = { items: [], total: 0, page: 1, page_size: 100 };
    api = {
      size: vi.fn(() => of({ rows: 120, bytes: 4096, entities: [{ entity: 'account', rows: 100 }, { entity: 'contact', rows: 20 }] })),
      status: vi.fn(() => of({ backlog: { action_type: 'reindex', pending: 0, oldest: null }, sizes: [] })),
      quality: vi.fn(() => of({ searches: 10, days: 30, zero_result_rate: 0.1, refinement_rate: 0.2, by_entity: [] })),
      synonyms: vi.fn(() => of(empty)),
      stopwords: vi.fn(() => of(empty)),
      pins: vi.fn(() => of(empty)),
      entitySettings: vi.fn(() => of(SETTINGS)),
      saveEntitySettings: vi.fn((_entity: string, body: { attributes: unknown[] }) =>
        of({ ...SETTINGS, row_version: 5, attributes: body.attributes })),
    };
    TestBed.configureTestingModule({
      imports: [SearchSettingsComponent],
      providers: [
        { provide: SearchPageService, useValue: api },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
  });

  it('saves attribute modes with If-Match', () => {
    const fixture = TestBed.createComponent(SearchSettingsComponent);
    fixture.detectChanges();
    const select = fixture.nativeElement.querySelector('select') as HTMLSelectElement;
    select.value = 'account';
    select.dispatchEvent(new Event('change'));
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelectorAll('[data-attribute-row]').length).toBe(2);

    fixture.componentInstance.setMode('cr_number', 'key');
    fixture.componentInstance.save();
    expect(api['saveEntitySettings']).toHaveBeenCalledWith(
      'account',
      { attributes: [{ attribute: 'name', mode: 'text', weight: 1 }, { attribute: 'cr_number', mode: 'key', weight: 1 }] },
      4,
    );

    // The next save sends the version the server answered with.
    fixture.componentInstance.save();
    expect(api['saveEntitySettings']).toHaveBeenLastCalledWith('account', expect.anything(), 5);
  });

  it('formats index sizes', () => {
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(2048)).toBe('2 KB');
    expect(formatBytes(5 * 1024 * 1024)).toBe('5 MB');
  });
});
