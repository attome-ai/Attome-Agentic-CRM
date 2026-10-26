import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';
import { LangService, UserPreferencesService } from '@attome/base';
import { DataCatalogService } from '@attome/xrm/core/admin/data';
import { CatalogSearchComponent } from './catalog-search.component';
import { AssetPageComponent, assetName } from './asset-page.component';
import { RequestAccessButtonComponent } from './request-access-button.component';
import { PersonalDataMapComponent } from './personal-data-map.component';

function asset(id: string, over: Record<string, unknown> = {}) {
  return {
    id, kind: 'entity', ref: id, parent_ref: null, name_en: `Name ${id}`, name_ar: `اسم ${id}`,
    description_en: 'English words', description_ar: 'كلمات عربية', description_status: 'draft',
    domain_ref: null, label: null, row_version: 3, updated_at: '2026-10-26T10:00:00Z', ...over,
  };
}

function searchPage(items: unknown[]) {
  return {
    items, total: items.length, page: 1, page_size: 25,
    facets: {
      kind: [{ value: 'entity', count: 2 }, { value: 'view', count: 1 }],
      domain: [],
      label: [{ value: 'finance', count: 1 }],
    },
  };
}

function lang(rtl = false) {
  return {
    translate: (k: string) => k,
    isRtl: () => rtl,
    errorText: () => 'failed',
    intlLocale: () => (rtl ? 'ar-SA' : 'en-US'),
  };
}

describe('data catalogue assets (L4-T6)', () => {
  let svc: Record<string, ReturnType<typeof vi.fn>>;

  function setup(rtl = false) {
    svc = {
      searchAssets: vi.fn(() => of(searchPage([asset('account'), asset('contact')]))),
      getAsset: vi.fn(() => of({
        asset: asset('account'), domain: null, label: 'finance', terms: [], quality: null,
        profile: null, lineage: [{ from_kind: 'workflow', from_label: 'Welcome', to_attribute: null }],
        usage: { record_count: 12, search_impressions_30d: 0, unused: true }, certification: null, history: null,
      })),
      setDescription: vi.fn(() => of(asset('account', { row_version: 4 }))),
      approveDescription: vi.fn(() => of(asset('account', { description_status: 'reviewed', row_version: 5 }))),
      requestAccess: vi.fn(() => of({ id: 'r1', status: 'pending' })),
      personalDataMap: vi.fn(() => of({
        items: [{ entity: 'contact', attribute: 'phone', sensitivity: 'personal',
          readers: [{ kind: 'query', ref: 'q1', label: 'Monthly report', whole_entity: false }] }],
        total: 1, page: 1, page_size: 50,
      })),
    };
    TestBed.configureTestingModule({
      providers: [
        provideRouter([]),
        { provide: DataCatalogService, useValue: svc },
        { provide: LangService, useValue: lang(rtl) },
        { provide: UserPreferencesService, useValue: { timezone: () => 'UTC', calendar: () => null, digits: () => null } },
      ],
    });
  }

  it('searches again with the facet a person picks, and clears it on a second pick', () => {
    setup();
    const fixture = TestBed.createComponent(CatalogSearchComponent);
    fixture.detectChanges();
    expect(svc['searchAssets']).toHaveBeenCalledWith(
      { q: '', kind: undefined, domain: undefined, label: undefined }, 1, 25,
    );
    const el: HTMLElement = fixture.nativeElement;
    const facet = () => el.querySelector<HTMLButtonElement>('[data-facet="kind:view"]')!;
    facet().click();
    fixture.detectChanges();
    expect(svc['searchAssets']).toHaveBeenLastCalledWith(
      { q: '', kind: 'view', domain: undefined, label: undefined }, 1, 25,
    );
    expect(facet().getAttribute('aria-pressed')).toBe('true');
    facet().click();
    fixture.detectChanges();
    expect(svc['searchAssets']).toHaveBeenLastCalledWith(
      { q: '', kind: undefined, domain: undefined, label: undefined }, 1, 25,
    );
    expect(el.querySelectorAll('[data-asset]').length).toBe(2);
    expect(el.querySelector('[data-facet^="domain:"]')).toBeNull();
  });

  it('renders right to left with Arabic names in Arabic', () => {
    setup(true);
    const fixture = TestBed.createComponent(CatalogSearchComponent);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-testid="asset-layout"]')!.getAttribute('dir')).toBe('rtl');
    expect(el.querySelector('[data-asset="account"]')!.textContent).toContain('اسم account');
    expect(el.querySelector('[data-asset="account"]')!.textContent).toContain('كلمات عربية');
    expect(assetName({ name_en: null, name_ar: null, ref: 'x' }, true)).toBe('x');
    expect(assetName({ name_en: 'Account', name_ar: null, ref: 'x' }, true)).toBe('Account');
  });

  it('shows only the panels with data, and saves a description at the row version', () => {
    setup();
    const fixture = TestBed.createComponent(AssetPageComponent);
    fixture.componentRef.setInput('assetId', 'account');
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    const panels = [...el.querySelectorAll('[data-panel]')].map(p => p.getAttribute('data-panel'));
    expect(panels).toEqual(['description', 'label', 'lineage', 'usage']);
    expect(el.querySelector('[data-testid="asset-unused"]')).not.toBeNull();
    el.querySelector<HTMLButtonElement>('[data-testid="description-save"]')!.click();
    fixture.detectChanges();
    expect(svc['setDescription']).toHaveBeenCalledWith('account', 3, {
      description_en: 'English words', description_ar: 'كلمات عربية',
    });
    // The page now holds the saved copy, so approving uses its new version.
    el.querySelector<HTMLButtonElement>('[data-testid="description-approve"]')!.click();
    expect(svc['approveDescription']).toHaveBeenCalledWith('account', 4);
  });

  it('requests access to a hidden field through its entity, and treats a repeat as requested', () => {
    setup();
    const fixture = TestBed.createComponent(RequestAccessButtonComponent);
    fixture.componentRef.setInput('entity', 'account');
    fixture.componentRef.setInput('attribute', 'iban');
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    el.querySelector<HTMLButtonElement>('[data-testid="access-open"]')!.click();
    fixture.detectChanges();
    expect(el.querySelector('[data-testid="access-reason"]')).not.toBeNull();
    // ngModel binds its control asynchronously; set the reason directly.
    fixture.componentInstance.reason.set('Quarter close');
    fixture.detectChanges();
    el.querySelector<HTMLButtonElement>('[data-testid="access-send"]')!.click();
    fixture.detectChanges();
    expect(svc['searchAssets']).toHaveBeenLastCalledWith({ q: 'account', kind: 'entity' }, 1, 10);
    expect(svc['requestAccess']).toHaveBeenCalledWith('account', 'Quarter close (iban)');
    expect(el.querySelector('[data-testid="access-requested"]')).not.toBeNull();

    svc['requestAccess'].mockReturnValue(throwError(() => ({ kind: 'conflict', message: '', status: 409 })));
    const again = TestBed.createComponent(RequestAccessButtonComponent);
    again.componentRef.setInput('assetId', 'contact');
    again.detectChanges();
    again.componentInstance.reason.set('Again');
    again.componentInstance.send();
    again.detectChanges();
    expect(svc['requestAccess']).toHaveBeenLastCalledWith('contact', 'Again');
    expect(again.nativeElement.querySelector('[data-testid="access-requested"]')).not.toBeNull();
  });

  it('lists each labelled field with what reads it', () => {
    setup();
    const fixture = TestBed.createComponent(PersonalDataMapComponent);
    fixture.detectChanges();
    const row: HTMLElement = fixture.nativeElement.querySelector('[data-attribute="contact.phone"]');
    expect(row.textContent).toContain('Monthly report');
    expect(row.textContent).toContain('governance.catalog.assets.sensitivities.personal');
  });
});
