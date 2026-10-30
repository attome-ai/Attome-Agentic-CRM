import { describe, expect, it } from 'vitest';

import { type PortalField, createOf, formFields, valueFor } from './portal-create-form.component';

const field = (name: string, field_type = 'text', writable = true): PortalField => ({
  name, label: null, field_type, required: false, writable, lookup_entity: null, options: null,
});

describe('portal create form (AC11-T2)', () => {
  it('reads a well-formed create target from the page root', () => {
    const doc = { root: { id: 'main', type: 'container', props: { create: { entity: 'deal_registration', fields: ['amount', 'Bad Name', 3] } } } };
    expect(createOf(doc as never)).toEqual({ entity: 'deal_registration', fields: ['amount'] });
    expect(createOf({ root: { id: 'main', type: 'container', props: { create: { entity: 'x; drop', fields: ['a'] } } } } as never)).toBeNull();
    expect(createOf({ root: { id: 'main', type: 'container', props: { create: { entity: 'deal', fields: [] } } } } as never)).toBeNull();
    expect(createOf(null)).toBeNull();
  });

  it('asks only for the writable fields, in the page order, and nothing without create', () => {
    const view = { entity: 'deal', can_create: true, fields: [field('amount', 'currency'), field('status', 'choice', false), field('customer_name')] };
    expect(formFields(view, ['customer_name', 'status', 'amount', 'missing']).map(f => f.name)).toEqual(['customer_name', 'amount']);
    expect(formFields({ ...view, can_create: false }, ['amount'])).toEqual([]);
  });

  it('sends numbers as numbers and leaves empty values out', () => {
    expect(valueFor(field('amount', 'currency'), ' 1500 ')).toBe(1500);
    expect(valueFor(field('name'), '  ')).toBeUndefined();
    expect(valueFor(field('name'), ' Acme ')).toBe('Acme');
    expect(valueFor(field('on', 'bool'), 'true')).toBe(true);
  });
});
