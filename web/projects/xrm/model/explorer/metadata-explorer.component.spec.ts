import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { xrmAr } from '@attome/xrm/core/i18n-ar';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { ModelService } from '../model.service';
import { MetadataExplorerComponent } from './metadata-explorer.component';

const page = <T>(items: T[]) => ({ items, total: items.length, page: 1, page_size: 50 });

/** Looks a dotted key up in a catalog, as LangService does. */
function lookup(catalog: unknown, key: string): string {
  const found = key.split('.').reduce<unknown>(
    (node, part) => (node && typeof node === 'object' ? (node as Record<string, unknown>)[part] : undefined),
    catalog,
  );
  return typeof found === 'string' ? found : key;
}

describe('MetadataExplorerComponent', () => {
  let svc: Record<string, ReturnType<typeof vi.fn>>;

  function setup(translate: (key: string) => string) {
    svc = {
      kinds: vi.fn().mockReturnValue(of(page([
        { name: 'entity', schema_version: 1, description: 'An entity' },
        { name: 'form', schema_version: 1, description: 'A form' },
      ]))),
      objects: vi.fn().mockReturnValue(of(page([
        { id: 'o1', name: 'Contact form', app: 'customer', owner_layer: 'customer', version_no: 2, state: 'draft', content_hash: 'h2' },
      ]))),
      history: vi.fn().mockReturnValue(of(page([
        { version_no: 2, state: 'draft', content_hash: 'h2', created_by: null, created_at: '2026-10-14T00:00:00Z' },
        { version_no: 1, state: 'published', content_hash: 'h1', created_by: null, created_at: '2026-10-13T00:00:00Z' },
      ]))),
      diff: vi.fn().mockReturnValue(of(page([{ op: 'replace', path: '/name', value: 'New' }]))),
      menuUsage: vi.fn().mockReturnValue(of(page([
        { item: 'Sales/Deals', opens: 40, last_opened: '2026-10-14', unused: false },
        { item: 'Sales/Old quotes', opens: 0, last_opened: null, unused: true },
      ]))),
      version: vi.fn().mockImplementation((_k: string, _id: string, v: number) =>
        of({ id: 'o1', kind: 'form', name: 'Contact form', version_no: v, kind_schema_version: 1,
             state: v === 2 ? 'draft' : 'published', doc: { name: v === 2 ? 'New' : 'Old' },
             content_hash: `h${v}`, created_at: '2026-10-14T00:00:00Z' })),
    };
    TestBed.configureTestingModule({
      imports: [MetadataExplorerComponent],
      providers: [
        { provide: ModelService, useValue: svc },
        { provide: LangService, useValue: { translate } },
      ],
    });
    const fixture = TestBed.createComponent(MetadataExplorerComponent);
    fixture.detectChanges();
    return fixture;
  }

  beforeEach(() => TestBed.resetTestingModule());

  it('suggests hiding the menu items nobody opened (AK6-T2)', () => {
    const fixture = setup(key => key);
    const explorer = fixture.componentInstance;
    explorer.selectKind('navigation');
    explorer.selectObject({ id: 'm1', name: 'Sales menu' } as never);
    fixture.detectChanges();
    expect(svc['menuUsage']).toHaveBeenCalledWith('m1');
    expect(explorer.unusedItems()).toEqual(['Sales/Old quotes']);
    const note = fixture.nativeElement.querySelector('[data-unused-items]') as HTMLElement;
    expect(note.textContent).toContain('Sales/Old quotes');
    expect(note.textContent).not.toContain('Sales/Deals');
  });

  it('asks for no usage for other kinds (AK6-T2)', () => {
    const fixture = setup(key => key);
    fixture.componentInstance.selectKind('form');
    fixture.componentInstance.selectObject({ id: 'o1', name: 'Contact form' } as never);
    expect(svc['menuUsage']).not.toHaveBeenCalled();
  });

  it('renders kind list', () => {
    const fixture = setup(key => key);
    const kinds = fixture.nativeElement.querySelectorAll('[data-kind]');
    expect(Array.from(kinds, (el: Element) => el.textContent?.trim())).toEqual(['entity', 'form']);
  });

  it('shows a version diff for a picked kind and object', () => {
    const fixture = setup(key => key);
    const cmp = fixture.componentInstance;
    cmp.selectKind('form');
    expect(svc['objects']).toHaveBeenCalledWith('form', 1);
    cmp.selectObject(cmp.objects()[0]);
    expect(svc['diff']).toHaveBeenCalledWith('form', 'o1', 1, 2);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('.mx-ops')?.textContent).toContain('replace /name');
    const sides = el.querySelectorAll('.mx-side pre');
    expect(sides[0].textContent).toContain('Old');
    expect(sides[1].textContent).toContain('New');
  });

  it('resolves Arabic labels', () => {
    const fixture = setup(key => lookup(xrmAr, key));
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('.mx-title')?.textContent?.trim()).toBe(xrmAr.metadataExplorer.title);
    fixture.componentInstance.selectKind('form');
    fixture.detectChanges();
    expect(el.textContent).toContain(xrmAr.metadataExplorer.state.draft);
  });
});
