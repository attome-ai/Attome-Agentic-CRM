import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService, LiveChannel, LiveRecords } from '@attome/base';
import { Subject, of, throwError } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { EntityService } from '../services/entity.service';
import { RecordChangedBannerComponent } from './record-changed-banner.component';

describe('RecordChangedBannerComponent (A16-T4)', () => {
  function setUp(get: (entity: string, id: string) => unknown) {
    const records = new Subject<LiveRecords>();
    const unwatch = vi.fn();
    const watch = vi.fn(() => unwatch);
    TestBed.configureTestingModule({
      imports: [RecordChangedBannerComponent],
      providers: [
        { provide: LiveChannel, useValue: { records, watch } },
        { provide: EntityService, useValue: { get: vi.fn(get) } },
        {
          provide: LangService,
          useValue: { intlLocale: signal('en-US'), translate: (key: string) => key, current: signal('en') },
        },
      ],
    });
    const fixture = TestBed.createComponent(RecordChangedBannerComponent);
    fixture.componentRef.setInput('entity', 'account');
    fixture.componentRef.setInput('recordId', 'r1');
    fixture.componentRef.setInput('rowVersion', 3);
    fixture.detectChanges();
    return { fixture, records, watch, unwatch, banner: fixture.componentInstance };
  }

  it('watches the record\'s entity while open and stops when it closes', () => {
    const { fixture, watch, unwatch } = setUp(() => of({ row_version: 3 }));
    expect(watch).toHaveBeenCalledWith('account');
    fixture.destroy();
    expect(unwatch).toHaveBeenCalled();
  });

  it('shows who changed the record when the server has a newer version', () => {
    const { records, banner } = setUp(() =>
      of({ row_version: 4, updated_at: '2026-10-15T09:30:00Z', lookups: { modified_by: { name: 'Mona', exists: true, is_active: true } } }));
    records.next({ changes: [{ entity: 'account', id: 'r1', op: 'update' }] });
    expect(banner.change()).toEqual({ deleted: false, by: 'Mona', at: '2026-10-15T09:30:00Z' });
  });

  it('says nothing about its own save, a version it already holds', () => {
    const { records, banner } = setUp(() => of({ row_version: 3 }));
    records.next({ changes: [{ entity: 'account', id: 'r1', op: 'update' }] });
    expect(banner.change()).toBeNull();
  });

  it('ignores changes to other records', () => {
    const get = vi.fn(() => of({ row_version: 9 }));
    const { records, banner } = setUp(get);
    records.next({ changes: [{ entity: 'account', id: 'other', op: 'update' }] });
    expect(get).not.toHaveBeenCalled();
    expect(banner.change()).toBeNull();
  });

  it('reports a deletion, and an unreadable record after an overflow, as deleted', () => {
    const deleted = setUp(() => of({ row_version: 3 }));
    deleted.records.next({ changes: [{ entity: 'account', id: 'r1', op: 'delete' }] });
    expect(deleted.banner.change()?.deleted).toBe(true);

    TestBed.resetTestingModule();
    const gone = setUp(() => throwError(() => new Error('not found')));
    gone.records.next({ overflow: true });
    expect(gone.banner.change()?.deleted).toBe(true);
  });

  it('clears once the form loads the newer version', () => {
    const { fixture, records, banner } = setUp(() => of({ row_version: 4 }));
    records.next({ changes: [{ entity: 'account', id: 'r1', op: 'update' }] });
    expect(banner.change()).not.toBeNull();
    fixture.componentRef.setInput('rowVersion', 4);
    fixture.detectChanges();
    expect(banner.change()).toBeNull();
  });
});
