import { describe, expect, it } from 'vitest';
import { layoutGantt } from './project-gantt.component';
import type { GanttView, WorkItemRollupRow } from '../../services/project.service';

function item(id: string, start: string | null, due: string | null, critical = false): WorkItemRollupRow {
  return {
    id, name: id, parent_work_item_id: null, item_type: 'task', status: 'not_started', owner_id: null,
    start_date: start, due_date: due, sequence: null, points_own: 0, points_completed: 0,
    points_total: 0, points_blocked: 0, progress_pct: 0, is_critical_path: critical, total_float_days: 0,
  };
}

describe('layoutGantt (V1-T1)', () => {
  const view: GanttView = {
    items: [
      item('a', '2027-03-01T00:00:00Z', '2027-03-04T00:00:00Z', true),
      item('b', '2027-03-04T00:00:00Z', '2027-03-06T00:00:00Z', true),
      item('c', null, null),
      item('m', '2027-03-08T00:00:00Z', '2027-03-08T00:00:00Z'),
    ],
    dependencies: [
      { predecessor_id: 'a', successor_id: 'b', dependency_type: 'finish_to_start', lag_days: 0 },
      { predecessor_id: 'a', successor_id: 'c', dependency_type: 'finish_to_start', lag_days: 0 },
    ],
    baseline: {
      baseline_id: 'x', label: 'v1', captured_at: null,
      items: [{ work_item_id: 'a', planned_start: '2027-02-28T00:00:00Z', planned_due: '2027-03-03T00:00:00Z' }],
    },
  };

  it('draws dated items in order and leaves undated ones out', () => {
    const l = layoutGantt(view);
    expect(l.bars.map(b => b.id)).toEqual(['a', 'b', 'm']);
    expect(l.bars.map(b => b.row)).toEqual([0, 1, 2]);
  });

  it('starts the scale at the earliest date, baseline included', () => {
    const l = layoutGantt(view);
    expect(l.origin).toBe(Date.parse('2027-02-28T00:00:00Z'));
    expect(l.bars[0].start).toBe(1);
    expect(l.bars[0].length).toBe(3);
    expect(l.bars[0].baselineStart).toBe(0);
    expect(l.bars[0].baselineLength).toBe(3);
    expect(l.days).toBe(9);
  });

  it('marks the critical path and milestones', () => {
    const l = layoutGantt(view);
    expect(l.bars[0].critical).toBe(true);
    expect(l.bars[2].milestone).toBe(true);
    expect(l.bars[2].length).toBe(0);
  });

  it('links finish to start and skips links to undrawn items', () => {
    const l = layoutGantt(view);
    expect(l.links).toEqual([{ fromRow: 0, fromDay: 4, toRow: 1, toDay: 4, critical: true }]);
  });

  it('answers an empty layout with nothing dated', () => {
    expect(layoutGantt({ items: [item('c', null, null)], dependencies: [], baseline: null }).bars).toEqual([]);
  });
});
