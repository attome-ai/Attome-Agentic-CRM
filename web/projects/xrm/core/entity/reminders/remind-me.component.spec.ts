import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { AuthService, LangService } from '@attome/base';
import type { ApiError } from '@attome/base';
import { of, throwError } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EntityService } from '../services/entity.service';
import { REMINDER_ENTITY, RemindMeComponent } from './remind-me.component';

describe('RemindMeComponent', () => {
  const USER = '01900000-0000-7000-8000-00000000000a';
  const RECORD = '01900000-0000-7000-8000-0000000000b1';
  let entities: { create: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    entities = { create: vi.fn() };
    TestBed.configureTestingModule({
      imports: [RemindMeComponent],
      providers: [
        { provide: EntityService, useValue: entities },
        { provide: AuthService, useValue: { userId: signal<string | null>(USER) } },
        {
          provide: LangService,
          useValue: {
            intlLocale: () => 'en-US',
            translate: (key: string, params?: Record<string, unknown>) =>
              params ? `${key} ${JSON.stringify(params)}` : key,
          },
        },
      ],
    });
  });

  afterEach(() => vi.useRealTimers());

  function render() {
    const fixture = TestBed.createComponent(RemindMeComponent);
    fixture.componentRef.setInput('entity', 'service_ticket');
    fixture.componentRef.setInput('recordId', RECORD);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    const q = <T extends HTMLElement = HTMLElement>(testId: string) =>
      el.querySelector<T>(`[data-testid="${testId}"]`);
    return { fixture, el, q };
  }

  function type(el: HTMLInputElement | HTMLTextAreaElement, value: string) {
    el.value = value;
    el.dispatchEvent(new Event('input'));
  }

  it('opens with a default time an hour ahead and saves a reminder for the signed-in user', () => {
    entities.create.mockReturnValue(of({ data: { id: 'r1' } }));
    const { fixture, q } = render();
    expect(q('remind-me-panel')).toBeNull();
    q('remind-me-toggle')!.click();
    fixture.detectChanges();
    const when = q<HTMLInputElement>('remind-me-when')!;
    expect(when.value).not.toBe('');
    type(q<HTMLTextAreaElement>('remind-me-note')!, '  Call the customer back  ');
    q('remind-me-save')!.click();
    fixture.detectChanges();

    expect(entities.create).toHaveBeenCalledTimes(1);
    const [entity, body] = entities.create.mock.calls[0];
    expect(entity).toBe(REMINDER_ENTITY);
    expect(body).toMatchObject({
      user_ref: USER, entity_name: 'service_ticket', record_id: RECORD,
      note: 'Call the customer back', status: 'pending',
    });
    expect(new Date(body.remind_at as string).getTime()).toBeGreaterThan(Date.now());
    expect(q('remind-me-panel')).toBeNull();
    expect(q('remind-me-notice')?.textContent).toContain('reminders.saved');
  });

  it('refuses a time in the past without calling the server', () => {
    const { fixture, q } = render();
    q('remind-me-toggle')!.click();
    fixture.detectChanges();
    type(q<HTMLInputElement>('remind-me-when')!, '2001-01-01T09:00');
    q('remind-me-save')!.click();
    fixture.detectChanges();
    expect(entities.create).not.toHaveBeenCalled();
    expect(q('remind-me-error')?.textContent).toContain('reminders.error.past');
  });

  it('shows the server refusal on the panel', () => {
    const err: ApiError = { kind: 'forbidden', status: 403, message: 'Forbidden' };
    entities.create.mockReturnValue(throwError(() => err));
    const { fixture, q } = render();
    q('remind-me-toggle')!.click();
    fixture.detectChanges();
    q('remind-me-save')!.click();
    fixture.detectChanges();
    expect(q('remind-me-error')?.getAttribute('role')).toBe('alert');
    expect(q('remind-me-error')?.textContent).toContain('reminders.error.forbidden');
    expect(q('remind-me-panel')).not.toBeNull();
  });
});
