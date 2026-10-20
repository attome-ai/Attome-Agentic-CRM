import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, AuthService, LangService } from '@attome/base';
import { EntityService } from '@attome/xrm/core/entity';
import { of, throwError } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { ProjectService } from '../services/project.service';
import { TimesheetGridComponent, weekDays, weekStartOf } from './timesheet-grid.component';

const USER = 'u-1';

function record(id: string, data: Record<string, unknown>, rowVersion = 1) {
  return { id, entity_id: '', data: { id, ...data }, created_at: '', updated_at: '', row_version: rowVersion };
}

describe('TimesheetGridComponent (V3-T1)', () => {
  function setUp(opts: { status?: string; away?: string[]; awayFails?: boolean } = {}) {
    const days = weekDays(weekStartOf(new Date()));
    const timesheet = record('ts-1', { user_id: USER, week_start_date: days[0], status: opts.status ?? 'draft' });
    const entries = [
      record('e-1', { work_item_id: 'wi-1', entry_date: days[1], hours: 3,
        __lookups: { work_item_id: { exists: true, is_active: true, name: 'Design review' } } }, 4),
      record('e-2', { work_item_id: 'wi-1', entry_date: days[2], hours: 2.5,
        __lookups: { work_item_id: { exists: true, is_active: true, name: 'Design review' } } }),
    ];
    const entities = {
      list: vi.fn((entity: string) => of({
        data: entity === 'project_timesheet' ? [timesheet] : entries,
        meta: { total: 0, limit: 50, offset: 0 },
      })),
      create: vi.fn(() => of({ id: 'new', entity_id: '', data: {} })),
      update: vi.fn(() => of({ id: 'e-1', entity_id: '', data: {} })),
      delete: vi.fn(() => of(undefined)),
      lookupSearch: vi.fn(() => of({ data: [], meta: { total: 0, limit: 20, offset: 0 } })),
    };
    const api = {
      get: vi.fn(() => opts.awayFails
        ? throwError(() => ({ status: 403, kind: 'forbidden', message: '' }))
        : of({ user_id: USER, away: opts.away ?? [] })),
    };
    const project = { submitTimesheet: vi.fn(() => of({ timesheet_id: 'ts-1', status: 'submitted', approval_pending: false })) };
    TestBed.configureTestingModule({
      imports: [TimesheetGridComponent],
      providers: [
        { provide: EntityService, useValue: entities },
        { provide: ApiService, useValue: api },
        { provide: ProjectService, useValue: project },
        { provide: AuthService, useValue: { userId: signal(USER) } },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: signal('en-US'), errorText: () => 'error' },
        },
      ],
    });
    const fixture = TestBed.createComponent(TimesheetGridComponent);
    fixture.detectChanges();
    return { fixture, root: fixture.nativeElement as HTMLElement, entities, project, days };
  }

  it('shows a row per work item with its hours and totals', () => {
    const { root, days } = setUp();
    const row = root.querySelector('[data-row="wi-1"]') as HTMLElement;
    expect(row.textContent).toContain('Design review');
    expect((root.querySelector(`[data-cell="wi-1|${days[1]}"]`) as HTMLInputElement).value).toBe('3');
    expect(root.querySelector('[data-row-total="wi-1"]')?.textContent?.trim()).toBe('5.5');
    expect(root.querySelector('[data-week-total]')?.textContent?.trim()).toBe('5.5');
  });

  it('marks leave days and takes no hours on them', () => {
    const { fixture, root, days } = setUp();
    fixture.componentInstance.away.set(new Set([days[3]]));
    fixture.detectChanges();
    expect(root.querySelector(`[data-day="${days[3]}"] [data-away]`)).not.toBeNull();
    expect((root.querySelector(`[data-cell="wi-1|${days[3]}"]`) as HTMLInputElement).disabled).toBe(true);
  });

  it('opens without leave when the availability check is refused', () => {
    const { root } = setUp({ awayFails: true });
    expect(root.querySelector('[data-away]')).toBeNull();
    expect(root.querySelector('[data-row="wi-1"]')).not.toBeNull();
  });

  it('updates, creates and removes entries from cell changes', () => {
    const { fixture, entities, days } = setUp();
    const grid = fixture.componentInstance;
    grid.save('wi-1', days[1], '4');
    expect(entities.update).toHaveBeenCalledWith('project_time_entry', 'e-1', { hours: 4 }, 4);
    grid.save('wi-1', days[4], '1.5');
    expect(entities.create).toHaveBeenCalledWith('project_time_entry', expect.objectContaining({
      timesheet_id: 'ts-1', work_item_id: 'wi-1', entry_date: days[4], hours: 1.5,
    }));
    grid.save('wi-1', days[2], '');
    expect(entities.delete).toHaveBeenCalledWith('project_time_entry', 'e-2');
  });

  it('refuses hours outside a day', () => {
    const { fixture, entities, days } = setUp();
    fixture.componentInstance.save('wi-1', days[1], '25');
    expect(entities.update).not.toHaveBeenCalled();
    expect(fixture.componentInstance.error()).toBe('timesheetGrid.invalidHours');
  });

  it('submits the week, and a submitted week is read-only', () => {
    const { fixture, root, project, days } = setUp();
    (root.querySelector('[data-submit]') as HTMLButtonElement).click();
    expect(project.submitTimesheet).toHaveBeenCalledWith('ts-1');
    fixture.detectChanges();
    expect((root.querySelector(`[data-cell="wi-1|${days[1]}"]`) as HTMLInputElement).disabled).toBe(true);
    expect(root.querySelector('[data-submit]')).toBeNull();
  });
});
