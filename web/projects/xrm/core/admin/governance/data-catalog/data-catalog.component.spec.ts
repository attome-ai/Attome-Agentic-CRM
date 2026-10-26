import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { DataCatalogService, DataProfileService } from '@attome/xrm/core/admin/data';
import type { CatalogEntityDetail } from '@attome/xrm/core/admin/data';
import { DataCatalogComponent } from './data-catalog.component';

describe('DataCatalogComponent', () => {
  let fixture: ComponentFixture<DataCatalogComponent>;
  let svc: { searchEntities: ReturnType<typeof vi.fn>; getEntity: ReturnType<typeof vi.fn> };

  const detail: CatalogEntityDetail = {
    id: 'e1', logicalname: 'contact', name: 'Contact', category: null, domain_ref: null,
    fields: [
      { logicalname: 'email', display_name: 'Email', field_type: 'text', data_classification: 'personal', is_required: true, hidden: false },
    ],
    lineage: [
      { from_kind: 'query', from_ref: 'q1', from_label: 'Active contacts', to_attribute: null, created_at: '2026-09-01T00:00:00Z' },
    ],
    usage: { record_count: 42, last_write_at: null, search_impressions_30d: 7, computed_at: '2026-09-22T00:00:00Z' },
    glossary_terms: [{ id: 'g1', term: 'Customer contact', definition: 'A person we talk to.', status: 'approved' }],
  };

  async function render(entity?: string) {
    await TestBed.configureTestingModule({
      imports: [DataCatalogComponent],
      providers: [
        provideRouter([]),
        { provide: DataCatalogService, useValue: svc },
        { provide: DataProfileService, useValue: { latest: () => of(null) } },
        { provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' } },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(DataCatalogComponent);
    if (entity) fixture.componentRef.setInput('entity', entity);
    fixture.detectChanges();
  }

  const el = () => fixture.nativeElement as HTMLElement;

  beforeEach(() => {
    TestBed.resetTestingModule();
    svc = {
      searchEntities: vi.fn().mockReturnValue(of({
        items: [{ id: 'e1', logicalname: 'contact', name: 'Contact', category: 'CRM', domain_ref: null }],
        total: 1, page: 1, page_size: 50,
      })),
      getEntity: vi.fn().mockReturnValue(of(detail)),
    };
  });

  it('searches from page 1 on load and lists entities', async () => {
    await render();
    expect(svc.searchEntities).toHaveBeenCalledWith({ q: '', classification: undefined }, 1, 50);
    expect(el().querySelectorAll('.dc-entity').length).toBe(1);
    expect(el().textContent).toContain('governance.catalog.pickEntity');
  });

  it('opens the detail on click and records it in the URL', async () => {
    await render();
    const navigate = vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true);
    (el().querySelector('.dc-entity') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(svc.getEntity).toHaveBeenCalledWith('contact');
    expect(navigate).toHaveBeenCalledWith([], { queryParams: { entity: 'contact' }, queryParamsHandling: 'merge' });
    const text = el().textContent ?? '';
    expect(text).toContain('Active contacts');
    expect(text).toContain('Customer contact');
    expect(text).toContain('governance.catalog.classifications.personal');
    expect(text).toContain('governance.catalog.wholeEntity');
  });

  it('deep-links the detail from ?entity=', async () => {
    await render('contact');
    expect(svc.getEntity).toHaveBeenCalledWith('contact');
    expect(fixture.componentInstance.selected()).toBe('contact');
  });

  it('restarts from page 1 when the classification changes', async () => {
    await render();
    fixture.componentInstance.page.set(2);
    fixture.componentInstance.setClassification('personal');
    expect(svc.searchEntities).toHaveBeenLastCalledWith({ q: '', classification: 'personal' }, 1, 50);
  });
});
