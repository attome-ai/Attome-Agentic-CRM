import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import type { ApiError } from '@attome/base';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { SlaService } from '../sla.service';
import { TicketSlaActionsComponent } from './ticket-sla-actions.component';

describe('TicketSlaActionsComponent', () => {
  const ID = 'ticket-1';
  let sla: {
    applyPolicy: ReturnType<typeof vi.fn>; pauseClock: ReturnType<typeof vi.fn>;
    resumeClock: ReturnType<typeof vi.fn>; recalculate: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    sla = { applyPolicy: vi.fn(), pauseClock: vi.fn(), resumeClock: vi.fn(), recalculate: vi.fn() };
    TestBed.configureTestingModule({
      imports: [TicketSlaActionsComponent],
      providers: [
        { provide: SlaService, useValue: sla },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
  });

  function render(locked = false) {
    const fixture = TestBed.createComponent(TicketSlaActionsComponent);
    fixture.componentRef.setInput('ticketId', ID);
    fixture.componentRef.setInput('locked', locked);
    const changed: string[] = [];
    fixture.componentInstance.changed.subscribe(a => changed.push(a));
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    const click = (testId: string) => {
      el.querySelector<HTMLButtonElement>(`[data-testid="${testId}"]`)!.click();
      fixture.detectChanges();
    };
    return { fixture, el, changed, click };
  }

  it('pauses with the chosen reason, announces it and asks the host to reload', () => {
    sla.pauseClock.mockReturnValue(of({ state: 'paused' }));
    const { el, changed, click, fixture } = render();
    const select = el.querySelector<HTMLSelectElement>('#sla-pause-reason')!;
    select.value = 'out_of_scope';
    select.dispatchEvent(new Event('change'));
    fixture.detectChanges();
    click('sla-pause');
    expect(sla.pauseClock).toHaveBeenCalledWith(ID, 'out_of_scope');
    expect(changed).toEqual(['pause']);
    expect(el.querySelector('[data-testid="sla-notice"]')?.textContent).toContain('serviceSla.notice.paused');
  });

  it('reports a 204 apply as "no matching policy"', () => {
    sla.applyPolicy.mockReturnValue(of(null));
    const { el, click, changed } = render();
    click('sla-apply');
    expect(sla.applyPolicy).toHaveBeenCalledWith(ID);
    expect(changed).toEqual(['apply']);
    expect(el.querySelector('[data-testid="sla-notice"]')?.textContent).toContain('serviceSla.notice.noPolicy');
  });

  it('distinguishes a recalculation that did nothing', () => {
    sla.recalculate.mockReturnValue(of({ ticket_id: ID, recalculated: false }));
    const { el, click } = render();
    click('sla-recalculate');
    expect(el.querySelector('[data-testid="sla-notice"]')?.textContent)
      .toContain('serviceSla.notice.nothingToRecalculate');
  });

  it('surfaces a 403 and a 409 as alerts and does not reload', () => {
    const forbidden: ApiError = { kind: 'forbidden', status: 403, message: 'Forbidden' };
    const conflict: ApiError = { kind: 'conflict', status: 409, message: 'busy' };
    sla.resumeClock.mockReturnValueOnce(throwError(() => forbidden)).mockReturnValueOnce(throwError(() => conflict));
    const { el, click, changed } = render();
    click('sla-resume');
    const alert = () => el.querySelector('[data-testid="sla-error"]');
    expect(alert()?.getAttribute('role')).toBe('alert');
    expect(alert()?.textContent).toContain('serviceSla.error.forbidden');
    click('sla-resume');
    expect(alert()?.textContent).toContain('serviceSla.error.conflict');
    expect(changed).toEqual([]);
  });

  it('disables every action and explains why while the form has unsaved edits', () => {
    const { el } = render(true);
    const buttons = Array.from(el.querySelectorAll<HTMLButtonElement>('button'));
    expect(buttons.length).toBe(4);
    expect(buttons.every(b => b.disabled)).toBe(true);
    expect(el.querySelector('[data-testid="sla-locked"]')?.textContent).toContain('serviceSla.saveFirst');
  });
});
