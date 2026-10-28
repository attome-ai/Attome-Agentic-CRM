import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { ModelService } from '@attome/xrm/model';
import { of, throwError } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { AdminService } from '../data/services/admin.service';
import { EntitySettingsComponent, effective, labelCounts, presetValues, settingsCommands } from './entity-settings.component';

const ENTITIES = [
  { id: 'e-deal', name: 'Deal', logicalname: 'deal' },
  { id: 'e-account', name: 'Account', logicalname: 'account' },
];

describe('entity settings helpers (A31-T5)', () => {
  it('mirrors the server presets', () => {
    expect(presetValues('light')).toMatchObject({ notes: true, search: true, activities: false, audit_level: 'off' });
    expect(presetValues('full')).toMatchObject({ offline: true, ai: true, audit_level: 'full' });
    expect(presetValues('standard')).toMatchObject({ activities: true, attribute_history: false, audit_level: 'changes' });
  });

  it('marks a switch set here over its preset', () => {
    const values = effective({ preset: 'light', switches: { offline: true, unknown: true } });
    expect(values['offline']).toEqual({ value: true, source: 'set_here' });
    expect(values['notes']).toEqual({ value: true, source: 'preset' });
    expect(values['unknown']).toBeUndefined();
  });

  it('writes the entity once, then only what changed', () => {
    expect(settingsCommands('e1', null, { preset: 'full' })).toEqual([
      { op: 'set', path: '/entity', value: 'e1' },
      { op: 'set', path: '/preset', value: 'full' },
    ]);
    const before = { entity: 'e1', preset: 'full', switches: {} };
    expect(settingsCommands('e1', before, { ...before })).toEqual([]);
    expect(settingsCommands('e1', before, { ...before, switches: { ai: false } })).toEqual([
      { op: 'set', path: '/switches', value: { ai: false } },
    ]);
  });

  it('counts labels most sensitive first', () => {
    const attrs = [{ sensitivity: 'internal' }, { sensitivity: 'secret' }, { sensitivity: 'internal' }];
    expect(labelCounts(attrs as never)).toEqual([{ label: 'secret', count: 1 }, { label: 'internal', count: 2 }]);
  });
});

describe('EntitySettingsComponent (A31-T5)', () => {
  function setUp(opts: { retentionForbidden?: boolean } = {}) {
    const saveDraft = vi.fn(() => of({ id: 's2', version_no: 1, content_hash: 'h2', issues: [] }));
    const publish = vi.fn(() => of({ id: 's2', version_no: 1 }));
    const getAllPages = vi.fn((url: string) => {
      if (url.includes('entity_settings')) return of([{ id: 's1', name: 'deal' }]);
      if (url.includes('retention')) {
        return opts.retentionForbidden
          ? throwError(() => ({ status: 403 }))
          : of([{ name: 'Old deals', entity_logicalname: 'deal', period_days: 365, action: 'purge', is_active: true }]);
      }
      return of([{ id: 'h1', entity_logicalname: 'deal', matter_reference: 'M-1' }]);
    });
    TestBed.configureTestingModule({
      imports: [EntitySettingsComponent],
      providers: [
        { provide: AdminService, useValue: {
          listEntities: () => of(ENTITIES),
          getEntity: () => of({ attributes: [{ sensitivity: 'personal' }, { sensitivity: 'internal' }] }),
        } },
        { provide: ModelService, useValue: {
          object: () => of({ content_hash: 'h1', doc: { entity: 'e-deal', preset: 'full', switches: { ai: false } } }),
          saveDraft,
          publish,
        } },
        { provide: ApiService, useValue: { getAllPages } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: signal('en-US'), errorText: () => 'error' } },
      ],
    });
    const fixture = TestBed.createComponent(EntitySettingsComponent);
    fixture.detectChanges();
    return { fixture, root: fixture.nativeElement as HTMLElement, saveDraft, publish };
  }

  it('compares every entity with its effective switches', () => {
    const { root } = setUp();
    expect(root.querySelectorAll('[data-compare-row]').length).toBe(2);
    const deal = root.querySelector('[data-compare-row="deal"]') as HTMLElement;
    // full preset with AI turned off here
    expect(deal.querySelectorAll('[data-on="true"]').length).toBe(7);
    const account = root.querySelector('[data-compare-row="account"]') as HTMLElement;
    expect(account.textContent).toContain('entitySettings.presets.standard');
  });

  it('shows the protection card and saves a change as a draft, then publishes it', () => {
    const { fixture, root, saveDraft, publish } = setUp();
    fixture.componentInstance.select('e-deal');
    fixture.detectChanges();
    expect(root.querySelector('[data-label="personal"]')).not.toBeNull();
    expect(root.querySelectorAll('[data-retention-rule]').length).toBe(1);
    expect(root.querySelector('[data-holds]')).not.toBeNull();
    fixture.componentInstance.setSwitch('offline', false);
    fixture.componentInstance.save('e-deal');
    expect(saveDraft).toHaveBeenCalledWith('entity_settings', 's1', 'h1', null, [
      { op: 'set', path: '/switches', value: { ai: false, offline: false } },
    ]);
    expect(publish).toHaveBeenCalledWith('entity_settings', 's1');
  });

  it('says so when retention rules are not visible to the caller', () => {
    const { fixture, root } = setUp({ retentionForbidden: true });
    fixture.componentInstance.select('e-deal');
    fixture.detectChanges();
    expect(root.querySelector('[data-retention-hidden]')).not.toBeNull();
  });
});
