import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ComposerComponent, ReplyTemplate, matchTemplates, slashQuery } from './composer.component';

const TEMPLATES: ReplyTemplate[] = [
  { id: 't1', name: 'Refund approved', folder: 'Billing', reply: 'Your refund for case 42 is approved.' },
  { id: 't2', name: 'Password reset', folder: 'Access', reply: 'Use the reset link we sent.' },
];

describe('ComposerComponent', () => {
  let api: { get: ReturnType<typeof vi.fn>; post: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    api = { get: vi.fn(() => of({ items: TEMPLATES })), post: vi.fn(() => of({})) };
    TestBed.configureTestingModule({
      imports: [ComposerComponent],
      providers: [
        { provide: ApiService, useValue: api },
        { provide: LangService, useValue: { translate: (k: string) => k } },
      ],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(ComposerComponent);
    fixture.componentRef.setInput('entity', 'service_ticket');
    fixture.componentRef.setInput('recordId', 'r1');
    fixture.componentRef.setInput('defaultTo', 'sara@example.com');
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    const q = <T extends HTMLElement = HTMLElement>(id: string) =>
      el.querySelector<T>(`[data-testid="${id}"]`);
    const type = (value: string) => {
      const box = q<HTMLTextAreaElement>('composer-body')!;
      box.value = value;
      box.setSelectionRange(value.length, value.length);
      box.dispatchEvent(new Event('input'));
      fixture.detectChanges();
      return box;
    };
    return { fixture, el, q, type };
  }

  it('finds a /name at the start of a line', () => {
    expect(slashQuery('/ref', 4)).toEqual({ start: 0, query: 'ref' });
    expect(slashQuery('Hi\n/pass', 8)).toEqual({ start: 3, query: 'pass' });
    expect(slashQuery('a /ref', 6)).toBeNull();
    expect(slashQuery('/ref now', 8)).toBeNull();
    expect(matchTemplates(TEMPLATES, 'bill').map(t => t.id)).toEqual(['t1']);
  });

  it('inserts a reply template with Enter and counts its use', () => {
    const { fixture, q, el, type } = render();
    expect(api.get).toHaveBeenCalledWith('/api/v1/model/reply-suggestions', {
      entity: 'service_ticket', record_id: 'r1', channel: 'email',
    });
    const box = type('Hello\n/refund');
    expect(el.querySelectorAll('[data-testid="composer-template"]').length).toBe(1);
    box.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', cancelable: true }));
    fixture.detectChanges();
    expect(box.value).toBe('Hello\nYour refund for case 42 is approved.');
    expect(q('composer-templates')).toBeNull();
    expect(api.post).toHaveBeenCalledWith('/api/v1/model/reply-templates/t1/used', {
      entity: 'service_ticket', record_id: 'r1',
    });
  });

  it('sends an email through the record and a note to the record', () => {
    const { fixture, q, type } = render();
    expect(q<HTMLInputElement>('composer-to')!.value).toBe('sara@example.com');
    type('We are on it.');
    q('composer-send')!.click();
    fixture.detectChanges();
    expect(api.post).toHaveBeenCalledWith('/api/v1/service_ticket/r1/communications', {
      channel: 'email', to: ['sara@example.com'], subject: '', body: 'We are on it.',
    });
    expect(q('composer-notice')?.textContent).toContain('composer.sent');

    q<HTMLInputElement>('composer-channel-note')!.click();
    fixture.detectChanges();
    expect(q('composer-to')).toBeNull();
    type('Customer called twice.');
    q('composer-send')!.click();
    fixture.detectChanges();
    expect(api.post).toHaveBeenLastCalledWith('/api/v1/note', {
      entity_name: 'service_ticket', record_id: 'r1',
      title: 'composer.noteDefaultTitle', note_text: 'Customer called twice.',
    });
  });

  it('says when sending failed', () => {
    api.post.mockReturnValue(throwError(() => ({ kind: 'internal_error' })));
    const { fixture, q, type } = render();
    type('Hi');
    q('composer-send')!.click();
    fixture.detectChanges();
    expect(q('composer-notice')?.textContent).toContain('composer.failed');
  });
});
