import { describe, expect, it } from 'vitest';
import {
  DashboardVariableBusService,
  MAX_PROPAGATION_HOPS,
  resolveReQueryChain,
  substituteVariableValues,
  widgetsListeningOn,
  type WidgetCrossFilterBinding,
} from './dashboard-variable-bus.service';

function binding(
  widgetId: string,
  emits: string[],
  listens: string[],
): WidgetCrossFilterBinding {
  return { widgetId, emits, listens };
}

describe('widgetsListeningOn', () => {
  it('returns every widget listening on the variable, excluding the source', () => {
    const bindings = [
      binding('a', ['region'], []),
      binding('b', [], ['region']),
      binding('c', [], ['region']),
      binding('d', [], ['other']),
    ];
    expect(widgetsListeningOn(bindings, 'region', 'a')).toEqual(['b', 'c']);
  });

  it('excludes the source widget even if it also listens on its own emitted variable', () => {
    const bindings = [binding('a', ['region'], ['region'])];
    expect(widgetsListeningOn(bindings, 'region', 'a')).toEqual([]);
  });
});

describe('resolveReQueryChain — direct (one-hop) cross-filtering', () => {
  it('re-queries every direct listener and nothing further when nothing chains', () => {
    const bindings = [
      binding('chart', ['region'], []),
      binding('table', [], ['region']),
      binding('kpi', [], ['region']),
    ];
    const result = resolveReQueryChain(bindings, {
      variable: 'region',
      value: 'GCC',
      sourceWidgetId: 'chart',
    });
    expect(new Set(result)).toEqual(new Set(['table', 'kpi']));
  });

  it('returns an empty chain when no widget listens on the changed variable', () => {
    const bindings = [binding('chart', ['region'], []), binding('table', [], ['segment'])];
    const result = resolveReQueryChain(bindings, {
      variable: 'region',
      value: 'GCC',
      sourceWidgetId: 'chart',
    });
    expect(result).toEqual([]);
  });

  it('never includes the source widget even if it also listens on the variable it emits', () => {
    const bindings = [binding('a', ['x'], ['x'])];
    const result = resolveReQueryChain(bindings, { variable: 'x', value: 1, sourceWidgetId: 'a' });
    expect(result).toEqual([]);
  });
});

describe('resolveReQueryChain — transitive propagation is bounded (no infinite re-query cycles)', () => {
  it('terminates immediately (does not hang the test runner) on a direct two-widget cycle', () => {
    // A emits X / listens Y; B emits Y / listens X — a click on A sets X,
    // which would loop A <-> B forever without a hop cap.
    const bindings = [binding('a', ['x'], ['y']), binding('b', ['y'], ['x'])];
    const result = resolveReQueryChain(bindings, { variable: 'x', value: 1, sourceWidgetId: 'a' });
    // Terminates (the test itself not hanging IS the primary assertion),
    // visits b exactly once, and never revisits the source.
    expect(result).toEqual(['b']);
  });

  it('never returns a widget id more than once, even across many hops of a cycle', () => {
    // A three-widget cycle: a -> b -> c -> a (each emits the variable the
    // next one listens on).
    const bindings = [
      binding('a', ['v1'], ['v3']),
      binding('b', ['v2'], ['v1']),
      binding('c', ['v3'], ['v2']),
    ];
    const result = resolveReQueryChain(bindings, {
      variable: 'v1',
      value: 1,
      sourceWidgetId: 'a',
    });
    const seen = new Set(result);
    expect(seen.size).toBe(result.length);
  });

  it('stops after MAX_PROPAGATION_HOPS even along a long non-cyclic chain', () => {
    // A straight-line chain of widgets longer than the hop cap:
    // w0 emits v0 -> w1 listens v0, emits v1 -> w2 listens v1, emits v2 -> ...
    const chainLength = MAX_PROPAGATION_HOPS + 6;
    const bindings: WidgetCrossFilterBinding[] = [];
    for (let i = 0; i < chainLength; i++) {
      bindings.push(binding(`w${i}`, [`v${i}`], i === 0 ? [] : [`v${i - 1}`]));
    }
    const result = resolveReQueryChain(bindings, {
      variable: 'v0',
      value: 1,
      sourceWidgetId: 'w0',
    });
    // Bounded: strictly fewer than the full remaining chain length, and at
    // most MAX_PROPAGATION_HOPS widgets reached.
    expect(result.length).toBeLessThanOrEqual(MAX_PROPAGATION_HOPS);
    expect(result.length).toBeLessThan(chainLength - 1);
    // The tail of the chain — reachable only past the hop cap — must NOT be
    // in the result, proving the cap actually stopped propagation short of
    // full closure rather than merely finishing naturally.
    expect(result).not.toContain(`w${chainLength - 1}`);
  });

  it('the two-widget cycle test above would loop forever without the hop cap (sanity check on the fixture)', () => {
    // Documents WHY the cap is needed: with no visited/hop guard at all, a
    // naive "keep expanding frontier variables" walk on a<->b never
    // terminates because each hop reintroduces the other widget's variable.
    // This test doesn't re-implement that broken walk (that would defeat
    // the point) — it just asserts the fixture really is cyclic in the
    // emits/listens graph, which is what makes the earlier termination
    // assertions meaningful rather than accidental.
    const bindings = [binding('a', ['x'], ['y']), binding('b', ['y'], ['x'])];
    const aEmitsWhatBListensOn = bindings[0].emits.some((v) => bindings[1].listens.includes(v));
    const bEmitsWhatAListensOn = bindings[1].emits.some((v) => bindings[0].listens.includes(v));
    expect(aEmitsWhatBListensOn && bEmitsWhatAListensOn).toBe(true);
  });
});

describe('DashboardVariableBusService', () => {
  it('publishes a re-query notification containing the resolved chain', async () => {
    const bus = new DashboardVariableBusService();
    bus.register(binding('chart', ['region'], []));
    bus.register(binding('table', [], ['region']));

    const received = new Promise<string[]>((resolve) => {
      bus.changes$().subscribe((notification) => resolve(notification.widgetIds));
    });
    bus.emit('region', 'GCC', 'chart');
    expect(await received).toEqual(['table']);
  });

  it('stops notifying a widget once it unregisters', async () => {
    const bus = new DashboardVariableBusService();
    bus.register(binding('chart', ['region'], []));
    bus.register(binding('table', [], ['region']));
    bus.unregister('table');

    const received = new Promise<string[]>((resolve) => {
      bus.changes$().subscribe((notification) => resolve(notification.widgetIds));
    });
    bus.emit('region', 'GCC', 'chart');
    expect(await received).toEqual([]);
  });
});

describe('variable values + filter substitution (M26 cross-filtering)', () => {
  it('records the last value emitted for each variable', () => {
    const bus = new DashboardVariableBusService();
    bus.emit('region', 'GCC', 'chart');
    bus.emit('region', 'EMEA', 'chart');

    expect(bus.values().get('region')).toBe('EMEA');
  });

  it("substitutes a @variable filter value with the variable's current value", () => {
    const bus = new DashboardVariableBusService();
    bus.emit('region', 'GCC', 'chart');

    const filters = [{ field: 'region', op: 'eq', value: '@region' }];
    expect(substituteVariableValues(filters, bus.values())).toEqual([
      { field: 'region', op: 'eq', value: 'GCC' },
    ]);
  });

  it('leaves a filter unchanged when its value is not a @ placeholder, or the variable is unset', () => {
    const values = new Map<string, unknown>([['region', 'GCC']]);
    const filters = [
      { field: 'region', op: 'eq', value: 'North' },
      { field: 'country', op: 'eq', value: '@country' },
      { field: 'region', op: 'eq', value: '@region' },
    ];

    expect(substituteVariableValues(filters, values)).toEqual([
      { field: 'region', op: 'eq', value: 'North' },
      { field: 'country', op: 'eq', value: '@country' },
      { field: 'region', op: 'eq', value: 'GCC' },
    ]);
  });
});
