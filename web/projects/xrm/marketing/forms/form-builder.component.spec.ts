import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { EntityService } from '@attome/xrm/core/entity';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  FormBuilderComponent, embedSnippet, formProblems, parseFieldMap, serializeFieldMap,
} from './form-builder.component';

const texts = { submit: 'Send', thanks: 'Thanks', failed: 'Failed </script>' };

describe('form builder helpers (E10-T2)', () => {
  it('reads and writes the field map', () => {
    const rows = parseFieldMap('{"your_email":"email","name":"first_name"}');
    expect(rows).toEqual([
      { name: 'your_email', attribute: 'email' },
      { name: 'name', attribute: 'first_name' },
    ]);
    expect(serializeFieldMap([...rows, { name: ' ', attribute: '' }]))
      .toBe('{"your_email":"email","name":"first_name"}');
    expect(parseFieldMap('not json')).toEqual([]);
    expect(parseFieldMap(null)).toEqual([]);
  });

  it('names what stops a form from working', () => {
    expect(formProblems([{ name: 'your_email', attribute: 'email' }], ['newsletter'])).toEqual([]);
    expect(formProblems([{ name: 'name', attribute: 'first_name' }], [])).toContain('marketingForm.problem.noEmail');
    expect(formProblems([{ name: 'email', attribute: 'email' }, { name: 'Bad Name', attribute: 'x' }], []))
      .toContain('marketingForm.problem.badName');
    expect(formProblems([{ name: 'email', attribute: 'email' }, { name: 'email', attribute: 'email' }], []))
      .toContain('marketingForm.problem.duplicate');
    expect(formProblems([{ name: 'email', attribute: 'email' }, { name: 'utm_source', attribute: 'source' }], []))
      .toContain('marketingForm.problem.reservedName');
    expect(formProblems([{ name: 'email', attribute: 'email' }], ['News Letter']))
      .toContain('marketingForm.problem.badPurpose');
  });

  it('builds a snippet that posts to the deployment', () => {
    const html = embedSnippet('https://crm.example.com', 'f1',
      [{ name: 'your_email', attribute: 'email' }, { name: 'company', attribute: 'company' }],
      ['newsletter'], true, texts);
    expect(html).toContain('<input name="your_email" type="email" required>');
    expect(html).toContain('<input name="company" type="text">');
    expect(html).toContain('name="consent_newsletter"');
    expect(html).toContain('"https://crm.example.com/api/v1/marketing/forms/f1/submit"');
    expect(html).toContain('utm_campaign');
    expect(html).not.toContain('Failed </script>');
    expect(embedSnippet('', 'f1', [], [], false, texts)).not.toContain('utm_campaign');
  });
});

describe('FormBuilderComponent (E10-T2)', () => {
  const entities = { get: vi.fn(), update: vi.fn() };

  beforeEach(() => {
    vi.resetAllMocks();
    entities.get.mockReturnValue(of({
      id: 'f1', entity_id: 'f1', row_version: 3,
      data: {
        name: 'Webinar sign-up', target_entity: 'lead', field_map: '{"email":"email"}',
        consent_purposes: 'newsletter', capture_utm: true, is_published: false,
      },
    }));
    entities.update.mockReturnValue(of({ id: 'f1', entity_id: 'f1', row_version: 4, data: {} }));
    TestBed.configureTestingModule({
      imports: [FormBuilderComponent],
      providers: [
        { provide: EntityService, useValue: entities },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en') } },
      ],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(FormBuilderComponent);
    fixture.componentRef.setInput('id', 'f1');
    fixture.detectChanges();
    TestBed.flushEffects();
    fixture.detectChanges();
    return fixture;
  }

  it('loads the form and saves it at its row version', () => {
    const fixture = render();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelectorAll('[data-testid="fb-row"]').length).toBe(1);
    (el.querySelector('[data-testid="fb-add"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    const name = el.querySelectorAll<HTMLInputElement>('[data-testid="fb-name"]')[1];
    name.value = 'company';
    name.dispatchEvent(new Event('input'));
    const attribute = el.querySelectorAll<HTMLInputElement>('[data-testid="fb-attribute"]')[1];
    attribute.value = 'company_name';
    attribute.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    (el.querySelector('[data-testid="fb-save"]') as HTMLButtonElement).click();
    expect(entities.update).toHaveBeenCalledWith('marketing_form', 'f1', expect.objectContaining({
      field_map: '{"email":"email","company":"company_name"}',
      consent_purposes: 'newsletter',
      is_published: false,
    }), 3);
    expect(fixture.componentInstance.rowVersion()).toBe(4);
  });

  it('will not save a form without an email field', () => {
    const fixture = render();
    const el: HTMLElement = fixture.nativeElement;
    const attribute = el.querySelector<HTMLInputElement>('[data-testid="fb-attribute"]')!;
    const name = el.querySelector<HTMLInputElement>('[data-testid="fb-name"]')!;
    name.value = 'first';
    name.dispatchEvent(new Event('input'));
    attribute.value = 'first_name';
    attribute.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    expect((el.querySelector('[data-testid="fb-save"]') as HTMLButtonElement).disabled).toBe(true);
    expect(el.textContent).toContain('marketingForm.problem.noEmail');
  });

  it('shows the embed snippet for the form', () => {
    const fixture = render();
    const snippet = fixture.nativeElement.querySelector('[data-testid="fb-snippet"]') as HTMLTextAreaElement;
    expect(snippet.value).toContain('/api/v1/marketing/forms/f1/submit');
    expect(snippet.value).toContain('consent_newsletter');
  });
});
