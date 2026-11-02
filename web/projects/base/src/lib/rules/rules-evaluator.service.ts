import { Injectable, InjectionToken, inject } from '@angular/core';

/**
 * Z11-T13: where the rules evaluator's WebAssembly comes from — a URL the
 * browser fetches (the host app copies the module to `/rules/`), or bytes
 * (a test reads them from disk).
 */
export const RULES_WASM_SOURCE = new InjectionToken<string | (() => Promise<BufferSource>)>(
  'RULES_WASM_SOURCE',
  { providedIn: 'root', factory: () => '/rules/attome_rules_wasm_bg.wasm' },
);

/** One problem with an expression; `start`/`end` are byte offsets into it. */
export interface RulesDiagnostic {
  code: string;
  message: string;
  start: number | null;
  end: number | null;
}

/** The evaluator's answer, the shape `POST /api/v1/admin/expressions/validate` uses. */
export interface RulesAnswer {
  ok: boolean;
  result_type?: string;
  diagnostics: RulesDiagnostic[];
  value?: unknown;
  trace?: { expr: string; value: unknown }[];
}

/**
 * The declared types an expression is checked against: `fields`, `related`
 * (one hop through a lookup), `related_lists` and `paths`, each type one of
 * `null`, `bool`, `number`, `text`, `date`, `choice`, `lookup`, `list<T>`.
 */
export interface RulesSchema {
  fields?: Record<string, string>;
  related?: Record<string, Record<string, string>>;
  related_lists?: Record<string, Record<string, string>>;
  paths?: Record<string, string>;
}

/** The values an expression is evaluated on; `now` is the only clock it sees. */
export interface RulesContext {
  now: string;
  timezone?: string;
  fields?: Record<string, unknown>;
  related?: Record<string, Record<string, unknown>>;
  related_lists?: Record<string, Record<string, unknown>[]>;
  paths?: Record<string, unknown>;
  rates?: { base: string; rates: Record<string, number> };
  calendar?: Record<string, unknown>;
}

/** The generated glue's surface (`wasm/attome_rules_wasm.ts`, unchecked). */
interface RulesModule {
  default(init: { module_or_path: string | BufferSource }): Promise<unknown>;
  validate(src: string, schema: string, version: string): string;
  evaluate(src: string, schema: string, context: string, version: string): string;
  calendar_add(calendar: string, from: string, minutes: number): string;
  calendar_between(calendar: string, a: string, b: string): string;
  calendar_next(calendar: string, from: string): string;
  calendar_is_working(calendar: string, at: string): string;
}

/**
 * Z12-T11: a calendar as `GET /api/v1/admin/calendars/{id}/expanded` returns it.
 * `hours` and `exceptions` hold `{start_minute, end_minute}` ranges.
 */
export interface CalendarDefinition {
  timezone: string;
  working_days: string[];
  hours: Record<string, { start_minute: number; end_minute: number }[]>;
  holidays: string[];
  exceptions: Record<string, { start_minute: number; end_minute: number }[]>;
}

/** A calendar calculation's answer; a failure carries `diagnostics`. */
export interface CalendarAnswer<T> {
  ok: boolean;
  value?: T;
  diagnostics?: RulesDiagnostic[];
}

/**
 * Z11-T13: the server's own expression evaluator (attome-rules), built to
 * WebAssembly, so an editor or a preview answers exactly as the server will
 * without a round trip. The module loads on first use; the server still
 * decides every write.
 */
@Injectable({ providedIn: 'root' })
export class RulesEvaluatorService {
  private readonly source = inject(RULES_WASM_SOURCE);
  private module?: Promise<RulesModule>;

  private load(): Promise<RulesModule> {
    this.module ??= (import('./wasm/attome_rules_wasm') as Promise<RulesModule>).then(async m => {
      const source = this.source;
      await m.default({ module_or_path: typeof source === 'string' ? source : await source() });
      return m;
    });
    return this.module;
  }

  /** The expression's result type, or each error with the span it points at. */
  async validate(src: string, schema: RulesSchema, version = 'v2'): Promise<RulesAnswer> {
    const m = await this.load();
    return JSON.parse(m.validate(src, JSON.stringify(schema), version)) as RulesAnswer;
  }

  /** The expression's value on `context`, with its trace, or the errors. */
  async evaluate(
    src: string,
    schema: RulesSchema,
    context: RulesContext,
    version = 'v2',
  ): Promise<RulesAnswer> {
    const m = await this.load();
    return JSON.parse(
      m.evaluate(src, JSON.stringify(schema), JSON.stringify(context), version),
    ) as RulesAnswer;
  }

  /** The instant `minutes` of working time after `from` (RFC 3339, UTC). */
  async calendarAdd(
    calendar: CalendarDefinition,
    from: string,
    minutes: number,
  ): Promise<CalendarAnswer<string>> {
    const m = await this.load();
    return JSON.parse(m.calendar_add(JSON.stringify(calendar), from, minutes)) as CalendarAnswer<string>;
  }

  /** The working minutes between two instants. */
  async calendarBetween(
    calendar: CalendarDefinition,
    a: string,
    b: string,
  ): Promise<CalendarAnswer<number>> {
    const m = await this.load();
    return JSON.parse(m.calendar_between(JSON.stringify(calendar), a, b)) as CalendarAnswer<number>;
  }

  /** The next working moment at or after `from`. */
  async calendarNext(calendar: CalendarDefinition, from: string): Promise<CalendarAnswer<string>> {
    const m = await this.load();
    return JSON.parse(m.calendar_next(JSON.stringify(calendar), from)) as CalendarAnswer<string>;
  }

  /** Whether `at` is working time. */
  async calendarIsWorking(calendar: CalendarDefinition, at: string): Promise<CalendarAnswer<boolean>> {
    const m = await this.load();
    return JSON.parse(m.calendar_is_working(JSON.stringify(calendar), at)) as CalendarAnswer<boolean>;
  }
}
