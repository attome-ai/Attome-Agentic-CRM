import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { describe, expect, it } from 'vitest';

import { AnswerViewComponent, MAX_TABLE_ROWS, answerView, cellText, flowDraft } from './copilot-components';

const column = (name: string, display_name = name) => ({ name, display_name, is_visible: true });

describe('copilot answer components (N1-T3)', () => {
  it('turns a query result into a table and, for label + number, a chart', () => {
    const view = answerView(JSON.stringify({
      data: {
        columns: [column('stage', 'Stage'), column('count', 'Deals')],
        records: [{ stage: 'won', count: 4 }, { stage: 'lost', count: 2 }],
      },
      metadata: { query_id: 'q' },
    }));
    expect(view?.kind).toBe('table');
    if (view?.kind !== 'table') return;
    expect(view.columns.map((c) => c.label)).toEqual(['Stage', 'Deals']);
    expect(view.rows).toEqual([['won', '4'], ['lost', '2']]);
    expect(view.bars).toEqual([
      { label: 'won', value: 4, share: 100 },
      { label: 'lost', value: 2, share: 50 },
    ]);
  });

  it('draws no chart for text columns and caps the table', () => {
    const records = Array.from({ length: MAX_TABLE_ROWS + 5 }, (_, i) => ({ name: `n${i}`, city: { id: 'c', name: 'Riyadh' } }));
    const view = answerView(JSON.stringify({ data: { columns: [column('name'), column('city')], records } }));
    if (view?.kind !== 'table') throw new Error('expected a table');
    expect(view.bars).toBeNull();
    expect(view.rows.length).toBe(MAX_TABLE_ROWS);
    expect(view.rows[0][1]).toBe('Riyadh');
  });

  it('turns a record into a card and leaves anything else raw', () => {
    const view = answerView(JSON.stringify({ id: 'r1', entity_id: 'e', row_version: 1, data: { name: 'Ada', email: null } }));
    expect(view).toEqual({ kind: 'record', id: 'r1', fields: [{ name: 'name', value: 'Ada' }] });
    expect(answerView('not json')).toBeNull();
    expect(answerView('[1,2]')).toBeNull();
    expect(answerView(JSON.stringify({ answer: 'text' }))).toBeNull();
    expect(cellText({ a: 1 })).toBe('{"a":1}');
  });

  it('renders cells as text, never as HTML', () => {
    TestBed.configureTestingModule({
      imports: [AnswerViewComponent],
      providers: [{ provide: LangService, useValue: { translate: (key: string) => key } }],
    });
    const fixture = TestBed.createComponent(AnswerViewComponent);
    fixture.componentRef.setInput('view', answerView(JSON.stringify({
      data: { columns: [column('name')], records: [{ name: '<img src=x onerror=alert(1)>' }] },
    })));
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('img')).toBeNull();
    expect(el.querySelector('td')?.textContent).toContain('<img');
  });

  it('drafts a workflow that repeats the request with the same agent', () => {
    const draft = flowDraft('agent-1', '  Email every overdue invoice owner  ', new Date('2026-10-14T09:30:00Z'));
    expect(draft.logicalname).toBe('assistant_task_20261014093000');
    expect(draft.name).toBe('Email every overdue invoice owner');
    expect(draft.graph).toEqual({
      nodes: [
        { id: 'start', type: 'trigger', config: { kind: 'manual', context: { task: 'Email every overdue invoice owner' } } },
        { id: 'agent', type: 'agent_step', config: { agent_definition_ref: 'agent-1', step_budget: 10 } },
      ],
      edges: [{ from_node: 'start', from_port: 'out', to_node: 'agent', to_port: 'task' }],
    });
  });
});
