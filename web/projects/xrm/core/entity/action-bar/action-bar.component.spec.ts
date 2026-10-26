import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ActionBarComponent, appliesTo } from './action-bar.component';
import type { CatalogAction } from './action-bar.component';

const RECORD = '01900000-0000-7000-8000-0000000000b1';
const OTHER = '01900000-0000-7000-8000-0000000000b2';

function action(id: string, required: string[], extra: Partial<CatalogAction> = {}): CatalogAction {
  return { id, description: id, risk: 'Reversible', input_schema: { required }, ...extra };
}

const CATALOG: CatalogAction[] = [
  action('custom.book_survey', ['entity', 'record_id'], { risk: 'Consequential' }),
  action('custom.tag_all', ['entity', 'record_ids']),
  action('custom.lead_only', ['entity', 'record_id'], {
    input_schema: { required: ['entity', 'record_id'], properties: { entity: { enum: ['lead'] } } },
  }),
  action('custom.needs_more', ['entity', 'record_id', 'reason']),
  action('record.update', ['entity', 'record_id']),
];

describe('action bar (AE1-T5)', () => {
  let api: { get: ReturnType<typeof vi.fn>; post: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    api = {
      get: vi.fn(() => of({ items: CATALOG })),
      post: vi.fn(() => of({ status: 'completed', result: {} })),
    };
    TestBed.configureTestingModule({
      imports: [ActionBarComponent],
      providers: [
        { provide: ApiService, useValue: api },
        { provide: LangService, useValue: { intlLocale: () => 'en-US', translate: (key: string) => key } },
      ],
    });
  });

  function render(inputs: { recordId?: string; recordIds?: string[] }) {
    const fixture = TestBed.createComponent(ActionBarComponent);
    fixture.componentRef.setInput('entity', 'account');
    if (inputs.recordId) fixture.componentRef.setInput('recordId', inputs.recordId);
    if (inputs.recordIds) fixture.componentRef.setInput('recordIds', inputs.recordIds);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    const open = () => {
      el.querySelector<HTMLButtonElement>('[data-testid="action-bar-open"]')!.click();
      fixture.detectChanges();
    };
    const items = () => [...el.querySelectorAll<HTMLButtonElement>('[data-action]')];
    return { fixture, el, open, items };
  }

  it('shows only custom actions that fit the record or the selection', () => {
    expect(appliesTo(CATALOG[0], 'account', false)).toBe(true);
    expect(appliesTo(CATALOG[0], 'account', true)).toBe(false);
    expect(appliesTo(CATALOG[1], 'account', true)).toBe(true);
    expect(appliesTo(CATALOG[2], 'account', false)).toBe(false);
    expect(appliesTo(CATALOG[2], 'lead', false)).toBe(true);
    expect(appliesTo(CATALOG[3], 'account', false)).toBe(false);
    expect(appliesTo(CATALOG[4], 'account', false)).toBe(false);
  });

  it('reads the catalogue only when opened', () => {
    const { open, items } = render({ recordId: RECORD });
    expect(api.get).not.toHaveBeenCalled();
    open();
    expect(api.get).toHaveBeenCalledWith('/api/v1/actions');
    expect(items().map(b => b.getAttribute('data-action'))).toEqual(['custom.book_survey']);
  });

  it('runs a record action on the record, and confirms a consequential one', () => {
    api.post.mockReturnValueOnce(of({ status: 'confirmation_required', reason: 'lasting effects' }));
    const { fixture, el, open, items } = render({ recordId: RECORD });
    const ran = vi.fn();
    fixture.componentInstance.ran.subscribe(ran);
    open();
    items()[0].click();
    fixture.detectChanges();
    expect(api.post).toHaveBeenLastCalledWith(
      `/api/v1/account/${RECORD}/actions/custom.book_survey`,
      { args: {}, confirm: false },
    );
    expect(el.querySelector('[data-testid="action-bar-notice"]')!.getAttribute('data-kind')).toBe('confirm');
    expect(ran).not.toHaveBeenCalled();

    el.querySelector<HTMLButtonElement>('[data-testid="action-bar-confirm"]')!.click();
    fixture.detectChanges();
    expect(api.post).toHaveBeenLastCalledWith(
      `/api/v1/account/${RECORD}/actions/custom.book_survey`,
      { args: {}, confirm: true },
    );
    expect(el.querySelector('[data-testid="action-bar-notice"]')!.getAttribute('data-kind')).toBe('done');
    expect(ran).toHaveBeenCalledWith('custom.book_survey');
  });

  it('sends the selection as one list for a bulk action, and reports an approval', () => {
    api.post.mockReturnValueOnce(of({ status: 'approval_required' }));
    const { fixture, el, open, items } = render({ recordIds: [RECORD, OTHER] });
    open();
    expect(items().map(b => b.getAttribute('data-action'))).toEqual(['custom.tag_all']);
    items()[0].click();
    fixture.detectChanges();
    expect(api.post).toHaveBeenCalledWith('/api/v1/actions/custom.tag_all/invoke', {
      args: { entity: 'account', record_ids: [RECORD, OTHER] },
      confirm: false,
    });
    expect(el.querySelector('[data-testid="action-bar-notice"]')!.getAttribute('data-kind')).toBe('approval');
  });

  it('says so when nothing applies', () => {
    api.get.mockReturnValue(of({ items: [] }));
    const { el, open } = render({ recordId: RECORD });
    open();
    expect(el.querySelector('[data-testid="action-bar-none"]')).not.toBeNull();
  });
});
