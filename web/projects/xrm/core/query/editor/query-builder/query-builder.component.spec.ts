import { TestBed } from '@angular/core/testing';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiService, LangService } from '@attome/base';
import { QueryBuilderComponent } from './query-builder.component';
import { buildSpec, emptyState, stateFromFilter } from './query-builder.model';

describe('query builder (A14-T3)', () => {
  let get: ReturnType<typeof vi.fn>;
  let post: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    get = vi.fn(() => of({ fields: [
      { name: 'name', display_name: 'Name', field_type: 'text' },
      { name: 'amount', display_name: 'Amount', field_type: 'currency' },
      { name: 'closed_on', display_name: 'Closed on', field_type: 'date' },
    ] }));
    post = vi.fn((path: string) => {
      if (path.includes('search.parse_filter')) {
        return of({ status: 'completed', result: { status: 'parsed', filter: {
          entity: 'opportunity',
          where: { kind: 'and', all: [
            { kind: 'compare', field: 'stage', op: 'eq', value: 'won' },
            { kind: 'compare', field: 'amount', op: 'gt', value: 1000 },
          ] },
        } } });
      }
      if (path === '/api/v1/query/run') {
        return of({ groups: [{ keys: { closed_on: '2026-10-01' }, values: { total: 3200 } }] });
      }
      return of({});
    });
    TestBed.configureTestingModule({
      imports: [QueryBuilderComponent],
      providers: [
        { provide: ApiService, useValue: { get, post } },
        { provide: LangService, useValue: { translate: (k: string) => k, errorText: () => 'failed', isRtl: () => false } },
      ],
    });
  });

  it('builds a grouped spec with a date bucket and a summary', () => {
    const state = {
      ...emptyState('opportunity'),
      conditions: [
        { field: 'stage', op: 'in' as const, value: 'won, open' },
        { field: 'closed_on', op: 'is_null' as const, value: 'x' },
        { field: '', op: 'eq' as const, value: 'ignored' },
      ],
      groups: [{ field: 'closed_on', bucket: 'month' as const }],
      aggregates: [{ func: 'sum' as const, field: 'amount', alias: 'total' }],
      select: ['name'],
    };
    expect(buildSpec(state)).toEqual({
      entity: 'opportunity',
      where: { kind: 'and', all: [
        { kind: 'compare', field: 'stage', op: 'in', value: ['won', 'open'] },
        { kind: 'compare', field: 'closed_on', op: 'is_null' },
      ] },
      group_by: [{ field: 'closed_on', bucket: 'month' }],
      aggregates: [{ func: 'sum', field: 'amount', alias: 'total' }],
    });
    const plain = buildSpec({ ...emptyState('account'), select: ['name', 'owner.name'], sortField: 'name' });
    expect(plain).toEqual({
      entity: 'account', select: ['name', 'owner.name'], page_size: 50, sort: [{ field: 'name', desc: false }],
    });
  });

  it('turns a parsed sentence into rows, or keeps a tree it cannot show', () => {
    const rows = stateFromFilter({ entity: 'lead', where: { kind: 'compare', field: 'score', op: 'gte', value: 50 } });
    expect(rows.conditions).toEqual([{ field: 'score', op: 'gte', value: '50' }]);
    expect(buildSpec(rows)['where']).toEqual({ kind: 'compare', field: 'score', op: 'gte', value: 50 });
    const tree = { kind: 'or', any: [{ kind: 'compare', field: 'a', op: 'eq', value: 1 }] };
    const kept = stateFromFilter({ entity: 'lead', where: tree });
    expect(kept.conditions).toEqual([]);
    expect(buildSpec(kept)['where']).toEqual(tree);
  });

  it('proposes a query from a sentence and applies it only when asked', () => {
    const fixture = TestBed.createComponent(QueryBuilderComponent);
    fixture.detectChanges();
    const builder = fixture.componentInstance;
    builder.sentence.set('won deals over 1000');
    builder.ask();
    fixture.detectChanges();
    expect(post).toHaveBeenCalledWith('/api/v1/actions/search.parse_filter/invoke', { args: { query: 'won deals over 1000' } });
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-testid="qb-proposal"]')).not.toBeNull();
    // Nothing changes before the proposal is applied.
    expect(builder.state().entity).toBe('');
    el.querySelector<HTMLButtonElement>('[data-testid="qb-apply"]')!.click();
    fixture.detectChanges();
    expect(builder.state().entity).toBe('opportunity');
    expect(builder.state().conditions.length).toBe(2);
    expect(get).toHaveBeenCalledWith('/api/v1/schema/opportunity');
  });

  it('runs a grouped query and shows the groups', () => {
    const fixture = TestBed.createComponent(QueryBuilderComponent);
    fixture.detectChanges();
    const builder = fixture.componentInstance;
    builder.entityInput.set('opportunity');
    builder.loadEntity();
    builder.addGroup();
    builder.setGroup(0, { field: 'closed_on', bucket: 'month' });
    builder.addAggregate();
    builder.setAggregate(0, { func: 'sum', field: 'amount', alias: 'total' });
    builder.run();
    fixture.detectChanges();
    expect(post).toHaveBeenCalledWith('/api/v1/query/run', { spec: {
      entity: 'opportunity',
      group_by: [{ field: 'closed_on', bucket: 'month' }],
      aggregates: [{ func: 'sum', field: 'amount', alias: 'total' }],
    } });
    const table: HTMLElement = fixture.nativeElement.querySelector('[data-testid="qb-groups"]');
    expect(table.textContent).toContain('2026-10-01');
    expect(table.textContent).toContain('3200');
    builder.saveName.set('Won by month');
    builder.save();
    expect(post).toHaveBeenLastCalledWith('/api/v1/admin/queries', expect.objectContaining({ name: 'Won by month' }));
  });
});
