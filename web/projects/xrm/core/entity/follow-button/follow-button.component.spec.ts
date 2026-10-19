import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { AuthService, LangService } from '@attome/base';
import type { ApiError } from '@attome/base';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { EntityService } from '../services/entity.service';
import { FOLLOW_ENTITY, FollowButtonComponent } from './follow-button.component';

describe('FollowButtonComponent', () => {
  const USER = '01900000-0000-7000-8000-00000000000a';
  const RECORD = '01900000-0000-7000-8000-0000000000b1';
  let entities: {
    list: ReturnType<typeof vi.fn>;
    create: ReturnType<typeof vi.fn>;
    delete: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    entities = { list: vi.fn(), create: vi.fn(), delete: vi.fn() };
    TestBed.configureTestingModule({
      imports: [FollowButtonComponent],
      providers: [
        { provide: EntityService, useValue: entities },
        { provide: AuthService, useValue: { userId: signal<string | null>(USER) } },
        { provide: LangService, useValue: { intlLocale: () => 'en-US', translate: (key: string) => key } },
      ],
    });
  });

  function page(ids: string[]) {
    return of({ data: ids.map(id => ({ id, data: {} })), meta: { total: ids.length, limit: 1, offset: 0 } });
  }

  function render() {
    const fixture = TestBed.createComponent(FollowButtonComponent);
    fixture.componentRef.setInput('entity', 'account');
    fixture.componentRef.setInput('recordId', RECORD);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    const q = (testId: string) => el.querySelector<HTMLElement>(`[data-testid="${testId}"]`);
    return { fixture, q };
  }

  it('looks up the caller\'s own follow of this record', () => {
    entities.list.mockReturnValue(page([]));
    const { q } = render();
    expect(entities.list).toHaveBeenCalledTimes(1);
    const [entity, params] = entities.list.mock.calls[0];
    expect(entity).toBe(FOLLOW_ENTITY);
    expect(params.filters).toEqual([
      { field: 'user_id', op: 'eq', value: USER },
      { field: 'entity_name', op: 'eq', value: 'account' },
      { field: 'record_id', op: 'eq', value: RECORD },
    ]);
    expect(q('follow-toggle')?.textContent).toContain('follow.follow');
    expect(q('follow-toggle')?.getAttribute('aria-pressed')).toBe('false');
  });

  it('follows the record for the signed-in person', () => {
    entities.list.mockReturnValue(page([]));
    entities.create.mockReturnValue(of({ id: 'f1', entity_id: 'e', data: {}, row_version: 1 }));
    const { fixture, q } = render();
    q('follow-toggle')!.click();
    fixture.detectChanges();
    expect(entities.create).toHaveBeenCalledWith(FOLLOW_ENTITY, {
      user_id: USER, entity_name: 'account', record_id: RECORD,
    });
    expect(q('follow-toggle')?.textContent).toContain('follow.following');
    expect(q('follow-toggle')?.getAttribute('aria-pressed')).toBe('true');
  });

  it('stops following by deleting the follow', () => {
    entities.list.mockReturnValue(page(['f9']));
    entities.delete.mockReturnValue(of(undefined));
    const { fixture, q } = render();
    expect(q('follow-toggle')?.textContent).toContain('follow.following');
    q('follow-toggle')!.click();
    fixture.detectChanges();
    expect(entities.delete).toHaveBeenCalledWith(FOLLOW_ENTITY, 'f9');
    expect(q('follow-toggle')?.textContent).toContain('follow.follow');
  });

  it('says so when the record cannot be followed', () => {
    entities.list.mockReturnValue(page([]));
    entities.create.mockReturnValue(throwError(() => ({ kind: 'forbidden', message: 'no' } as ApiError)));
    const { fixture, q } = render();
    q('follow-toggle')!.click();
    fixture.detectChanges();
    expect(q('follow-error')?.textContent).toContain('follow.error.notAllowed');
    expect(q('follow-toggle')?.textContent).toContain('follow.follow');
  });

  it('stays hidden when follows cannot be read', () => {
    entities.list.mockReturnValue(throwError(() => ({ kind: 'forbidden' } as ApiError)));
    const { q } = render();
    expect(q('follow-toggle')).toBeNull();
  });
});
