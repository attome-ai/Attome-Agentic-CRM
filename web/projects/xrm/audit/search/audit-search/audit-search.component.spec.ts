import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AuditSearchService } from '../data/audit-search.service';
import { AuditSearchComponent, SAVED_SEARCHES_KEY } from './audit-search.component';

const PAGE = { items: [], total: 120, page: 1, page_size: 50 };

describe('AuditSearchComponent', () => {
  let service: Record<string, ReturnType<typeof vi.fn>>;

  beforeEach(() => {
    localStorage.removeItem(SAVED_SEARCHES_KEY);
    service = {
      search: vi.fn().mockReturnValue(of(PAGE)),
      exportUrl: vi.fn().mockReturnValue('https://x/api/v1/admin/audit/export?format=csv'),
      evidencePack: vi.fn().mockReturnValue(of({ events: [], keys: [] })),
    };
    TestBed.configureTestingModule({
      imports: [AuditSearchComponent],
      providers: [
        { provide: AuditSearchService, useValue: service },
        { provide: LangService, useValue: { translate: (k: string) => k, intlLocale: () => 'en' } },
      ],
    });
    TestBed.overrideComponent(AuditSearchComponent, { set: { template: '' } });
  });

  afterEach(() => localStorage.removeItem(SAVED_SEARCHES_KEY));

  function create(): AuditSearchComponent {
    const fixture = TestBed.createComponent(AuditSearchComponent);
    fixture.detectChanges();
    return fixture.componentInstance;
  }

  it('searches on open and pages through the results', () => {
    const c = create();
    expect(service['search']).toHaveBeenCalledWith({}, 1, 50);
    expect(c.totalPages()).toBe(3);
    c.goToPage(2);
    expect(service['search']).toHaveBeenLastCalledWith({}, 2, 50);
    c.goToPage(9);
    expect(service['search']).toHaveBeenCalledTimes(2);
  });

  it('filters only by what was filled in', () => {
    const c = create();
    c.entityName.set(' account ');
    c.operation.set('3');
    c.search();
    expect(service['search']).toHaveBeenLastCalledWith(
      { entity_name: 'account', operation: 3 },
      1,
      50,
    );
    expect(c.operationKey(3)).toBe('auditSearch.op.hardDelete');
    expect(c.operationKey(99)).toBe('auditSearch.op.other');
  });

  it('saves a search, applies it again and removes it', () => {
    const c = create();
    c.entityName.set('invoice');
    c.userEmail.set('auditor@example.com');
    c.saveName.set('Invoice by auditor');
    c.saveSearch();
    expect(c.saved().map(s => s.name)).toEqual(['Invoice by auditor']);
    expect(JSON.parse(localStorage.getItem(SAVED_SEARCHES_KEY) ?? '[]')).toHaveLength(1);

    c.entityName.set('');
    c.userEmail.set('');
    c.applySaved(c.saved()[0]);
    expect(c.entityName()).toBe('invoice');
    expect(service['search']).toHaveBeenLastCalledWith(
      { entity_name: 'invoice', user_email: 'auditor@example.com' },
      1,
      50,
    );

    c.removeSaved('Invoice by auditor');
    expect(c.saved()).toEqual([]);
    expect(localStorage.getItem(SAVED_SEARCHES_KEY)).toBe('[]');
  });

  it('builds an evidence pack only for a range or one record', () => {
    const createUrl = vi.fn().mockReturnValue('blob:pack');
    const revoke = vi.fn();
    Object.assign(URL, { createObjectURL: createUrl, revokeObjectURL: revoke });
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);

    const c = create();
    expect(c.canBuildPack()).toBe(false);
    c.downloadEvidencePack();
    expect(service['evidencePack']).not.toHaveBeenCalled();

    c.entityName.set('account');
    c.recordId.set('0199a4f0-0000-7000-8000-000000000001');
    expect(c.canBuildPack()).toBe(true);
    c.downloadEvidencePack();
    expect(service['evidencePack']).toHaveBeenCalledWith({
      from: null,
      to: null,
      entity_name: 'account',
      record_id: '0199a4f0-0000-7000-8000-000000000001',
    });
    expect(click).toHaveBeenCalled();
    expect(revoke).toHaveBeenCalledWith('blob:pack');
    click.mockRestore();
  });
});
