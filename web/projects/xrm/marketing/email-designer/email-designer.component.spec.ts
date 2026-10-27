import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { EmailDesignerComponent } from './email-designer.component';
import { EmailDesign, fromCanvas, linkOk, problems, toCanvas } from './email-design.model';

describe('EmailDesignerComponent (E2-T1)', () => {
  const stored: EmailDesign = {
    blocks: [
      { type: 'heading', text: 'مرحبًا {{ first_name }}', level: 1 },
      { type: 'columns', columns: [[{ type: 'text', text: 'Left' }], [{ type: 'button', label: 'Book', href: 'https://acme.sa/book' }]] },
      { type: 'image', src: 'https://acme.sa/a.png', alt: '' },
    ],
    dir: 'rtl',
    width: 600,
  };

  function setUp(id: string | null) {
    const api = {
      get: vi.fn((path: string) => (path.endsWith('/d-1')
        ? of({ id: 'd-1', row_version: 3, data: { name: 'Welcome', subject: 'Hi', locale: 'ar', design: JSON.stringify(stored) } })
        : of({ items: [{ id: 'd-1', data: { name: 'Welcome' } }] }))),
      post: vi.fn((path: string) => (path.includes('preview')
        ? of({ html: '<p>rendered</p>', text: 'rendered', choices: {} })
        : of({ id: 'd-2', row_version: 0, data: {} }))),
      patch: vi.fn(() => of({ id: 'd-1', row_version: 4, data: {} })),
    };
    TestBed.configureTestingModule({
      imports: [EmailDesignerComponent],
      providers: [
        provideRouter([]),
        { provide: ApiService, useValue: api },
        {
          provide: LangService,
          useValue: {
            translate: (key: string, params?: Record<string, unknown>) => (params ? `${key} ${JSON.stringify(params)}` : key),
            errorText: () => 'error',
            current: signal('en'),
            intlLocale: signal('en-US'),
          },
        },
      ],
    });
    const fixture = TestBed.createComponent(EmailDesignerComponent);
    if (id) fixture.componentRef.setInput('id', id);
    fixture.detectChanges();
    return { fixture, cmp: fixture.componentInstance, el: fixture.nativeElement as HTMLElement, api };
  }

  it('lists saved designs when none is open', () => {
    const { el } = setUp(null);
    expect(el.querySelector('[data-design="d-1"]')?.textContent).toContain('Welcome');
    expect(el.querySelector('[data-new]')?.getAttribute('href')).toBe('/xrm/marketing/email-designer/new');
  });

  it('opens a saved design right to left and lists what the renderer would refuse', () => {
    const { el, cmp } = setUp('d-1');
    expect(cmp.locale()).toBe('ar');
    expect(el.querySelector('[data-email-designer]')?.getAttribute('dir')).toBe('rtl');
    expect(cmp.design()?.blocks).toEqual(stored.blocks);
    expect(el.querySelector('[data-issues]')?.textContent).toContain('emailDesigner.problems.missingAlt {"block":"3"}');
  });

  it('adds blocks from the palette into the selected column', () => {
    const { fixture, cmp, el } = setUp('new');
    (el.querySelector('[data-add="columns"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    cmp.onSelect(['/root/children/0/children/1']);
    (el.querySelector('[data-add="text"]') as HTMLButtonElement).click();
    const blocks = cmp.design()?.blocks ?? [];
    expect(blocks).toHaveLength(1);
    expect(blocks[0]).toEqual({ type: 'columns', columns: [[], [{ type: 'text', text: '' }]] });
  });

  it('saves the design as a record and opens it', () => {
    const { cmp, api } = setUp('new');
    const navigate = vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true);
    cmp.add('heading');
    cmp.name.set('Launch');
    cmp.save();
    const [path, body] = api.post.mock.calls.at(-1) as unknown as [string, Record<string, unknown>];
    expect(path).toBe('/api/v1/marketing_email_design');
    expect(body['name']).toBe('Launch');
    expect(JSON.parse(body['design'] as string)).toEqual({ blocks: [{ type: 'heading', text: '', level: 1 }], dir: 'ltr', width: 600 });
    expect(navigate).toHaveBeenCalledWith(['/xrm', 'marketing', 'email-designer', 'd-2']);
  });

  it('updates a saved design with its version, and previews it in a sandboxed frame', () => {
    const { fixture, cmp, el, api } = setUp('d-1');
    cmp.save();
    expect(api.patch).toHaveBeenCalledWith('/api/v1/marketing_email_design/d-1', expect.objectContaining({ name: 'Welcome' }), 3);
    cmp.previewPerson.set('c-9');
    cmp.preview();
    fixture.detectChanges();
    expect(api.post).toHaveBeenCalledWith('/api/v1/marketing/emails/preview', expect.objectContaining({ entity: 'contact', person_id: 'c-9' }));
    expect(el.querySelector('[data-frame]')?.getAttribute('sandbox')).toBe('');
  });

  it('turns designs into canvas documents and back purely', () => {
    const back = fromCanvas(toCanvas(stored), { dir: 'rtl', width: 600, colour: '' });
    expect(back.blocks).toEqual(stored.blocks);
    expect(fromCanvas(toCanvas({ blocks: [] }), { dir: 'ltr', width: 5000, colour: '#ABCDEF' })).toEqual({ blocks: [], dir: 'ltr', width: 800, primary_colour: '#abcdef' });
    expect(linkOk('{{ unsubscribe_url }}')).toBe(true);
    expect(linkOk('javascript:alert(1)')).toBe(false);
    expect(problems({ blocks: [{ type: 'button', label: 'Go', href: 'ftp://x' }] })).toEqual([{ index: '1', problem: 'badLink' }]);
  });
});
