import { TestBed } from '@angular/core/testing';
import { ActivatedRoute, Router } from '@angular/router';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { Block, ContentAdminService, PageDetail } from './services/content-admin.service';
import { ContentPageEditorComponent } from './content-page/form/content-page-editor/content-page-editor.component';
import { ContentPageListComponent } from './content-page/list/content-page-list/content-page-list.component';

const PAGE_ID = 'page-1';

function page(overrides: Partial<PageDetail> = {}): PageDetail {
  return {
    id: PAGE_ID,
    parent_page_id: null,
    title: 'Understanding templates',
    url_path: '/guide/templates',
    status: 'draft',
    content_space_id: 'space-1',
    template_id: null,
    blocks_draft: [],
    blocks_published: null,
    seo_title: null,
    seo_description: null,
    published_at: null,
    row_version: 3,
    created_at: '2026-08-17T00:00:00Z',
    updated_at: '2026-08-17T00:00:00Z',
    review_by: null,
    ...overrides,
  };
}

function block(kind: Block['kind'], props: Record<string, unknown> = {}): Block {
  return { id: crypto.randomUUID(), kind, props };
}

describe('ContentPageEditorComponent', () => {
  const svc = {
    listPages: vi.fn(),
    searchPages: vi.fn(),
    getPage: vi.fn(),
    createPage: vi.fn(),
    updatePage: vi.fn(),
    deletePage: vi.fn(),
    publishPage: vi.fn(),
    movePage: vi.fn(),
    ancestors: vi.fn(),
  };

  function mount(loaded: PageDetail) {
    svc.getPage.mockReturnValue(of(loaded));
    TestBed.configureTestingModule({
      providers: [
        { provide: ContentAdminService, useValue: svc },
        {
          provide: ActivatedRoute,
          useValue: { paramMap: of({ get: () => PAGE_ID }) },
        },
        { provide: Router, useValue: { navigate: vi.fn() } },
      ],
    });
    TestBed.overrideComponent(ContentPageEditorComponent, { set: { template: '' } });
    const fixture = TestBed.createComponent(ContentPageEditorComponent);
    fixture.detectChanges();
    return fixture;
  }

  beforeEach(() => {
    for (const fn of Object.values(svc)) fn.mockReset();
  });

  it('loads the page and seeds the block list from blocks_draft', () => {
    const heading = block('heading', { text: 'Hi', level: 2 });
    const fixture = mount(page({ blocks_draft: [heading] }));
    const c = fixture.componentInstance;

    expect(c.page()?.id).toBe(PAGE_ID);
    expect(c.blocks()).toEqual([heading]);
  });

  it('adds a block from the library to the end of the canvas and selects it', () => {
    const fixture = mount(page());
    const c = fixture.componentInstance;

    c.openLibrary('canvas');
    c.pickBlockType('heading');

    expect(c.blocks()).toHaveLength(1);
    expect(c.blocks()[0].kind).toBe('heading');
    expect(c.selectedBlockId()).toBe(c.blocks()[0].id);
    // The library modal closes after a pick.
    expect(c.library()).toBeNull();
  });

  it('inserts a block after the given index rather than always appending', () => {
    const a = block('heading');
    const b = block('alert');
    const fixture = mount(page({ blocks_draft: [a, b] }));
    const c = fixture.componentInstance;

    c.openLibrary('canvas', 0);
    c.pickBlockType('image');

    expect(c.blocks().map(x => x.kind)).toEqual(['heading', 'image', 'alert']);
  });

  it('duplicates a block as a new copy with a different id, placed right after it', () => {
    const original = block('heading', { text: 'Hi' });
    const fixture = mount(page({ blocks_draft: [original] }));
    const c = fixture.componentInstance;

    c.duplicateBlock(0);

    expect(c.blocks()).toHaveLength(2);
    expect(c.blocks()[1].props).toEqual(original.props);
    expect(c.blocks()[1].id).not.toBe(original.id);
  });

  it('removing the selected block clears the selection', () => {
    const a = block('heading');
    const fixture = mount(page({ blocks_draft: [a] }));
    const c = fixture.componentInstance;

    c.selectBlock(a.id);
    c.removeBlock(0);

    expect(c.blocks()).toHaveLength(0);
    expect(c.selectedBlockId()).toBeNull();
  });

  it('setProp updates only the targeted block, immutably', () => {
    const a = block('heading', { text: 'A' });
    const b = block('heading', { text: 'B' });
    const fixture = mount(page({ blocks_draft: [a, b] }));
    const c = fixture.componentInstance;

    c.setProp(a.id, 'text', 'Changed');

    expect(c.blocks()[0].props['text']).toBe('Changed');
    expect(c.blocks()[1].props['text']).toBe('B');
    // The original array/object are untouched (immutable update).
    expect(a.props['text']).toBe('A');
  });

  it('adding a block into a specific column only affects that column', () => {
    const columns = block('columns', { columns: [{ blocks: [] }, { blocks: [] }] });
    const fixture = mount(page({ blocks_draft: [columns] }));
    const c = fixture.componentInstance;

    c.openLibrary({ columnsBlockId: columns.id, columnIndex: 1 });
    c.pickBlockType('rich_text');

    expect(c.columnsOf(columns.id)[0].blocks).toHaveLength(0);
    expect(c.columnsOf(columns.id)[1].blocks).toHaveLength(1);
    expect(c.columnsOf(columns.id)[1].blocks[0].kind).toBe('rich_text');
  });

  it('the block library excludes "columns" when adding inside a column', () => {
    const columns = block('columns', { columns: [{ blocks: [] }] });
    const fixture = mount(page({ blocks_draft: [columns] }));
    const c = fixture.componentInstance;

    const target = { columnsBlockId: columns.id, columnIndex: 0 };
    const kinds = c.filteredBlockTypes(target).map(t => t.kind);

    expect(kinds).not.toContain('columns');
    expect(c.filteredBlockTypes('canvas').map(t => t.kind)).toContain('columns');
  });

  it('saveDraft sends the current row_version as If-Match and adopts the returned row', () => {
    const loaded = page({ blocks_draft: [] });
    const updated = page({ blocks_draft: [block('heading')], row_version: 4 });
    svc.updatePage.mockReturnValue(of(updated));
    const fixture = mount(loaded);
    const c = fixture.componentInstance;

    c.blocks.set([block('heading')]);
    c.saveDraft();

    expect(svc.updatePage).toHaveBeenCalledWith(
      PAGE_ID,
      { blocks: c.blocks() },
      3,
    );
    expect(c.page()?.row_version).toBe(4);
    expect(c.statusMessage()).toBe('Draft saved.');
  });

  it('publish saves the draft first, then publishes, then reloads the page', () => {
    const loaded = page();
    const savedDraft = page({ row_version: 4 });
    svc.updatePage.mockReturnValue(of(savedDraft));
    svc.publishPage.mockReturnValue(of({ id: PAGE_ID, status: 'published', published_at: '2026-08-17T01:00:00Z' }));
    svc.getPage.mockReturnValueOnce(of(loaded)).mockReturnValueOnce(of(page({ status: 'published' })));
    const fixture = mount(loaded);
    const c = fixture.componentInstance;

    c.publish();

    expect(svc.updatePage).toHaveBeenCalled();
    expect(svc.publishPage).toHaveBeenCalledWith(PAGE_ID);
    expect(c.statusMessage()).toBe('Published.');
  });

  it('surfaces a save error instead of silently discarding it', () => {
    const fixture = mount(page());
    const c = fixture.componentInstance;
    svc.updatePage.mockReturnValue(throwError(() => ({ message: 'row_version is stale' })));

    c.saveDraft();

    expect(c.saveError()).toBe('row_version is stale');
    expect(c.saving()).toBe(false);
  });
});

describe('ContentPageListComponent', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        {
          provide: ContentAdminService,
          useValue: {
            listSpaces: vi.fn(() => of([])),
            listTemplates: vi.fn(() => of([])),
            spaceTemplates: vi.fn(() => of([])),
            listPages: vi.fn(() => of([])),
            searchPages: vi.fn(() => of([])),
            createPage: vi.fn(),
          },
        },
        { provide: Router, useValue: { navigate: vi.fn() } },
      ],
    });
    TestBed.overrideComponent(ContentPageListComponent, { set: { template: '' } });
  });

  it('derives a url_path slug from the title until the path is edited by hand', () => {
    const fixture = TestBed.createComponent(ContentPageListComponent);
    fixture.detectChanges();
    const c = fixture.componentInstance;

    c.onTitleChange('Understanding Templates!');
    expect(c.newUrlPath).toBe('/understanding-templates');

    // Once the operator edits the path directly, further title changes must
    // not clobber their edit.
    c.onUrlPathChange('/custom/path');
    c.onTitleChange('A Totally Different Title');
    expect(c.newUrlPath).toBe('/custom/path');
  });
});
