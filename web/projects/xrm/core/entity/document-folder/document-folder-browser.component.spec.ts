import { ComponentFixture, TestBed } from '@angular/core/testing';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiService, LangService } from '@attome/base';
import { DialogService } from '@attome/base/dialog';
import { EntityService } from '../services/entity.service';
import { FileUploadService } from '../field/file-upload.service';
import { DocumentFolderBrowserComponent, DOCUMENT_ROW_HEIGHT_PX } from './document-folder-browser.component';

/**
 * FE-6 — the tree route has no LIMIT, so a folder with thousands of documents
 * arrives as one array. The list must window it: the DOM holds only the rows
 * that fit the viewport (plus the strategy's buffer), never one `<li>` per file.
 */
describe('DocumentFolderBrowserComponent virtual scrolling (FE-6)', () => {
  const FILE_COUNT = 5000;
  let fixture: ComponentFixture<DocumentFolderBrowserComponent>;
  let api: { get: ReturnType<typeof vi.fn>; post: ReturnType<typeof vi.fn>; patch: ReturnType<typeof vi.fn> };

  const files = Array.from({ length: FILE_COUNT }, (_, i) => ({
    id: `doc-${String(i).padStart(5, '0')}`,
    name: `report-${String(i).padStart(5, '0')}.pdf`,
    file: `uploads/doc-${i}.pdf`,
    source_field: null,
    created_at: '2026-08-01T00:00:00Z',
    modified_at: '2026-08-01T00:00:00Z',
    size_bytes: 1024 * (i + 1),
    row_version: 1,
  }));

  beforeEach(async () => {
    api = {
      get: vi.fn().mockReturnValue(of({ entities: [], records: [], folders: [], files })),
      post: vi.fn().mockReturnValue(of({})),
      patch: vi.fn().mockReturnValue(of({})),
    };

    await TestBed.configureTestingModule({
      imports: [DocumentFolderBrowserComponent],
      providers: [
        { provide: ApiService, useValue: api },
        { provide: EntityService, useValue: { get: vi.fn().mockReturnValue(of({ data: {} })), delete: vi.fn() } },
        { provide: FileUploadService, useValue: {} },
        { provide: DialogService, useValue: { confirm: vi.fn(), prompt: vi.fn(), error: vi.fn() } },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(DocumentFolderBrowserComponent);
    fixture.componentRef.setInput('entityName', 'user_account');
    fixture.componentRef.setInput('recordId', 'user-1');
    fixture.componentRef.setInput('folder', 'Documents');
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
  });

  it('flattens every file into the virtual list without dropping any', () => {
    const items = fixture.componentInstance.listItems();
    expect(items).toHaveLength(FILE_COUNT);
    expect(items.every(item => item.kind === 'file')).toBe(true);
  });

  it('renders only a window of rows, not one per file', () => {
    const viewport: HTMLElement | null = fixture.nativeElement.querySelector('cdk-virtual-scroll-viewport');
    expect(viewport).not.toBeNull();
    const rendered = fixture.nativeElement.querySelectorAll('.xdf-main li.xdf-row').length;
    // jsdom reports a 0px viewport, so the strategy renders at most its
    // buffer's worth of rows — the point is that it is bounded by the
    // viewport, not by the data. A per-file render would be 5000.
    expect(rendered).toBeLessThan(FILE_COUNT / 10);
  });

  it('pins the viewport item size to the row height the stylesheet uses', () => {
    expect(fixture.componentInstance.rowHeight).toBe(DOCUMENT_ROW_HEIGHT_PX);
    expect(DOCUMENT_ROW_HEIGHT_PX).toBe(40);
  });
});
