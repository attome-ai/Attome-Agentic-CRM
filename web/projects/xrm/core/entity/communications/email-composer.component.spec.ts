import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { ApiService, LangService } from '@attome/base';
import { EntityService } from '../services/entity.service';
import { EmailComposerComponent, composeBody, splitAddresses } from './email-composer.component';

describe('EmailComposerComponent (J1-T2)', () => {
  it('builds the compose request with a later time and the chosen files', () => {
    expect(splitAddresses('a@x.test; b@x.test , c@x.test')).toEqual(['a@x.test', 'b@x.test', 'c@x.test']);
    const body = composeBody('a@x.test', ' Quote ', 'Hello', '2030-01-02T09:30', ['k1']);
    expect(body.to).toEqual(['a@x.test']);
    expect(body.subject).toBe('Quote');
    expect(body.attachments).toEqual(['k1']);
    expect(body.send_at).toBe(new Date('2030-01-02T09:30').toISOString());
    const now = composeBody('a@x.test', 'S', 'B', '', []);
    expect(now.send_at).toBeUndefined();
    expect(now.attachments).toBeUndefined();
  });

  function create() {
    const get = vi.fn().mockReturnValue(of({
      items: [{ id: 't1', name: 'Thanks', folder: null, reply: 'Thank you for your order.' }],
    }));
    const post = vi.fn().mockReturnValue(of({}));
    const entities = {
      list: vi.fn().mockReturnValue(of({
        data: [{ id: 'd1', data: { name: 'quote.pdf', file: 'files/abc-quote.pdf' } }],
        meta: { total: 1, limit: 50, offset: 0 },
      })),
    };
    TestBed.configureTestingModule({
      imports: [EmailComposerComponent],
      providers: [
        { provide: ApiService, useValue: { get, post } },
        { provide: EntityService, useValue: entities },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: () => 'en-US' } },
      ],
    });
    const fixture = TestBed.createComponent(EmailComposerComponent);
    fixture.componentRef.setInput('entity', 'account');
    fixture.componentRef.setInput('recordId', 'r1');
    fixture.componentRef.setInput('defaultTo', 'buyer@x.test');
    fixture.detectChanges();
    return { fixture, get, post, entities };
  }

  it('fills the body from a template, attaches a record file and sends', () => {
    const { fixture, post, entities } = create();
    const composer = fixture.componentInstance;
    expect(entities.list).toHaveBeenCalledWith('attome_document', expect.objectContaining({
      filters: [
        { field: 'entity_name', op: 'eq', value: 'account' },
        { field: 'record_id', op: 'eq', value: 'r1' },
      ],
    }));
    expect(composer.to()).toBe('buyer@x.test');
    expect(composer.files()).toEqual([{ key: 'files/abc-quote.pdf', name: 'quote.pdf' }]);

    composer.useTemplate('t1');
    expect(composer.body()).toBe('Thank you for your order.');
    expect(post).toHaveBeenCalledWith('/api/v1/model/reply-templates/t1/used', { entity: 'account', record_id: 'r1' });

    composer.subject.set('Your quote');
    composer.toggleFile('files/abc-quote.pdf');
    let sent = 0;
    composer.sent.subscribe(() => sent++);
    composer.send(new Event('submit'));
    const [path, body] = post.mock.calls.at(-1) as [string, Record<string, unknown>];
    expect(path).toBe('/api/v1/account/r1/communications');
    expect(body['attachments']).toEqual(['files/abc-quote.pdf']);
    expect(body['to']).toEqual(['buyer@x.test']);
    expect(sent).toBe(1);
    expect(composer.notice()).toBe('emailComposer.sent');
    expect(composer.chosen()).toEqual([]);
  });

  it('will not send without a subject', () => {
    const { fixture } = create();
    const composer = fixture.componentInstance;
    composer.body.set('Hello');
    expect(composer.canSend()).toBe(false);
    composer.subject.set('Hi');
    expect(composer.canSend()).toBe(true);
  });
});
