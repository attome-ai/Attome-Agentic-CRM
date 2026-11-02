import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { TestBed } from '@angular/core/testing';
import { describe, expect, it } from 'vitest';
import { RULES_WASM_SOURCE, RulesEvaluatorService } from './rules-evaluator.service';

// The committed module (scripts/build-rules-wasm.ps1 writes it), read from disk.
const WASM = resolve(process.cwd(), 'projects/base/src/lib/rules/wasm/attome_rules_wasm_bg.wasm');

function service(): RulesEvaluatorService {
  TestBed.configureTestingModule({
    providers: [{ provide: RULES_WASM_SOURCE, useValue: async () => readFileSync(WASM) }],
  });
  return TestBed.inject(RulesEvaluatorService);
}

const schema = { fields: { amount: 'number', name: 'text' } };

describe('RulesEvaluatorService', () => {
  it('evaluates amount > 100 to true', async () => {
    const answer = await service().evaluate('amount > 100', schema, {
      now: '2026-10-28T09:00:00Z',
      fields: { amount: 150, name: 'Acme' },
    });
    expect(answer.ok).toBe(true);
    expect(answer.value).toBe(true);
  });

  it('points at an unknown field', async () => {
    const answer = await service().validate('amount + missing', schema);
    expect(answer.ok).toBe(false);
    expect(answer.diagnostics[0]).toMatchObject({ code: 'rules.field.unknown', start: 9, end: 16 });
  });

  it('calendarAdd matches server fixture', async () => {
    // Sunday to Thursday, 09:00 to 17:00 in Riyadh, with a holiday on Wednesday:
    // eight working hours from Tuesday 16:30 end on Thursday 16:30, the value
    // the server's add_business_duration gives (parity.rs compares the two).
    const hours = [{ start_minute: 540, end_minute: 1020 }];
    const calendar = {
      timezone: 'Asia/Riyadh',
      working_days: ['sun', 'mon', 'tue', 'wed', 'thu'],
      hours: { sun: hours, mon: hours, tue: hours, wed: hours, thu: hours },
      holidays: ['2026-11-04'],
      exceptions: {},
    };
    const answer = await service().calendarAdd(calendar, '2026-11-03T13:30:00Z', 480);
    expect(answer).toEqual({ ok: true, value: '2026-11-05T13:30:00Z' });
  });
});
