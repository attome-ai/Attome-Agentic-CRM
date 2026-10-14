import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { KnowledgeCoverageComponent } from './knowledge-coverage.component';
import { CollectionCoverage, IndexerStatus, KnowledgeService } from '../services/knowledge.service';

/**
 * The coverage screen shows what the backend counted and nothing else. The
 * one inference it must never make: an absent embedding backlog (knowledge is
 * lexical-only) is not a zero backlog, so it is said in words.
 */
describe('KnowledgeCoverageComponent', () => {
  let fixture: ComponentFixture<KnowledgeCoverageComponent>;
  let knowledge: { coverage: ReturnType<typeof vi.fn>; indexerStatus: ReturnType<typeof vi.fn> };

  const row = (over: Partial<CollectionCoverage> = {}): CollectionCoverage => ({
    collection_id: 'c-1',
    name: 'Policies',
    items_total: 4,
    items_published: 2,
    items_draft: 1,
    items_expired: 1,
    chunks: 7,
    last_indexed_at: '2026-09-20T10:00:00Z',
    chunks_embedded: 5,
    embedding_backlog: 2,
    ...over,
  });

  async function render(items: CollectionCoverage[], indexer: IndexerStatus) {
    knowledge = {
      coverage: vi.fn().mockReturnValue(of({ items, total: items.length, page: 1, page_size: 100 })),
      indexerStatus: vi.fn().mockReturnValue(of(indexer)),
    };
    await TestBed.configureTestingModule({
      imports: [KnowledgeCoverageComponent],
      providers: [
        provideRouter([]),
        { provide: KnowledgeService, useValue: knowledge },
        { provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' } },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(KnowledgeCoverageComponent);
    fixture.detectChanges();
  }

  const cells = () =>
    Array.from((fixture.nativeElement as HTMLElement).querySelectorAll('tbody tr td')).map((td) =>
      td.textContent?.trim(),
    );

  it('reads page 1 and renders the counted figures, with the backlog against the model', async () => {
    await render([row()], { drain_last_advanced_at: '2026-09-22T08:00:00Z', embedding_model: 'bge-m3' });
    expect(knowledge.coverage).toHaveBeenCalledWith(1, 100);
    const text = cells();
    expect(text).toEqual(expect.arrayContaining(['2', '1', '7', '5']));
    expect((fixture.nativeElement as HTMLElement).querySelector('.kc-backlog')?.textContent?.trim()).toBe('2');
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('bge-m3');
  });

  it('says lexical-only instead of showing a zero backlog when no model is configured', async () => {
    await render(
      [row({ chunks_embedded: null, embedding_backlog: null })],
      { drain_last_advanced_at: null, embedding_model: null },
    );
    const html = fixture.nativeElement as HTMLElement;
    expect(html.querySelector('.kc-backlog')).toBeNull();
    expect(cells()).toContain('knowledgeCoverage.lexicalCell');
    expect(html.textContent).toContain('knowledgeCoverage.lexicalOnly');
    expect(html.textContent).toContain('knowledgeCoverage.drainNeverRan');
  });

  it('links a collection with drafts to the draft review queue', async () => {
    await render([row()], { embedding_model: null });
    const link = (fixture.nativeElement as HTMLElement).querySelector('tbody a');
    expect(link?.getAttribute('href')).toBe('/xrm/admin/knowledge/drafts');
  });

  it('shows the administrator-only message on a 403, not an empty state', async () => {
    knowledge = {
      coverage: vi.fn().mockReturnValue(throwError(() => ({ status: 403, message: 'forbidden' }))),
      indexerStatus: vi.fn().mockReturnValue(throwError(() => ({ status: 403 }))),
    };
    await TestBed.configureTestingModule({
      imports: [KnowledgeCoverageComponent],
      providers: [
        provideRouter([]),
        { provide: KnowledgeService, useValue: knowledge },
        { provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' } },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(KnowledgeCoverageComponent);
    fixture.detectChanges();
    const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
    expect(text).toContain('knowledgeCoverage.forbidden');
    expect(text).not.toContain('knowledgeCoverage.empty');
  });
});
