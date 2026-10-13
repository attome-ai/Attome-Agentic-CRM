import { describe, expect, it } from 'vitest';
import { describeItem, formatValue } from './report-text';

describe('report text', () => {
  const calls: { key: string; params?: Record<string, unknown> }[] = [];
  const lang = {
    translate: (key: string, params?: Record<string, unknown>) => {
      calls.push({ key, params });
      return params ? `${key}|${JSON.stringify(params)}` : key;
    },
  };

  const item = (kind: string, detail: Record<string, unknown>, field: string | null = 'rating') => ({
    kind, entity_logicalname: 'contact', field_logicalname: field, object_kind: null, detail,
  });

  it('says how many values a deleted field archived', () => {
    const text = describeItem(lang, item('field_deleted', { archived: 12, attribute_id: 'x' }));
    expect(text).toContain('releaseReport.text.field_deleted');
    expect(text).toContain('"count":"12"');
    expect(text).toContain('"field":"rating"');
  });

  it('names the from and to types of a type change', () => {
    const text = describeItem(lang, item('conversion_nulled', { nulled: 3, from: 'text', to: 'number' }));
    expect(text).toContain('"from":"text"');
    expect(text).toContain('"to":"number"');
    expect(text).toContain('"count":"3"');
  });

  it('picks the breaking-change sentence by the change', () => {
    expect(describeItem(lang, item('breaking_api_change', { change: 'renamed', to: 'renewal_on' })))
      .toContain('releaseReport.text.breaking_renamed');
    expect(describeItem(lang, item('breaking_api_change', { change: 'removed' })))
      .toContain('releaseReport.text.breaking_removed');
    expect(describeItem(lang, item('breaking_api_change', { change: 'type', from: 'text', to: 'date' })))
      .toContain('releaseReport.text.breaking_type');
    expect(describeItem(lang, item('breaking_api_change', {})))
      .toContain('releaseReport.text.breaking_other');
  });

  it('never shows a raw key for a missing count or field', () => {
    const text = describeItem(lang, item('required_empty', {}, null));
    expect(text).toContain('"count":"releaseReport.text.unknownCount"');
    expect(text).toContain('"field":"releaseReport.text.noField"');
  });

  it('describes a business-rule conflict by the rule name', () => {
    const text = describeItem(lang, item('conflict', { rule: 'Credit limit', change: 'updated' }, null));
    expect(text).toContain('releaseReport.text.conflict_rule');
    expect(text).toContain('"name":"Credit limit"');
  });

  it('falls back for an unknown kind', () => {
    expect(describeItem(lang, item('something_new', {}))).toContain('releaseReport.text.unknown');
  });

  it('formats conflict values', () => {
    expect(formatValue(lang, null)).toBe('releaseReport.item.empty');
    expect(formatValue(lang, '')).toBe('releaseReport.item.empty');
    expect(formatValue(lang, 'Gold')).toBe('Gold');
    expect(formatValue(lang, 4)).toBe('4');
    expect(formatValue(lang, false)).toBe('false');
    expect(formatValue(lang, { a: 1 })).toBe('{"a":1}');
  });
});
