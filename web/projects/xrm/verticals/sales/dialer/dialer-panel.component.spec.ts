import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { EntityService } from '@attome/xrm/core/entity';
import { of } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { DialerPanelComponent, previewLines } from './dialer-panel.component';
import { DialerService } from './dialer.service';

describe('dialer helpers (D21-T11)', () => {
  it('previews a record by its name and role', () => {
    expect(previewLines({ full_name: 'Lina Haddad', job_title: 'CFO', company_name: 'Acme' }))
      .toEqual({ name: 'Lina Haddad', detail: 'CFO · Acme' });
    expect(previewLines({}).detail).toBeNull();
  });
});

describe('DialerPanelComponent (D21-T11)', () => {
  const dialer = { claim: vi.fn(), dial: vi.fn(), outcome: vi.fn(), skip: vi.fn(), voicemail: vi.fn() };
  const entities = { get: vi.fn(), list: vi.fn() };
  const current = signal<'en' | 'ar'>('en');

  beforeEach(() => {
    vi.useFakeTimers();
    vi.resetAllMocks();
    current.set('en');
    entities.get.mockImplementation((entity: string, id: string) => of(entity === 'call_list'
      ? { id, row_version: 1, data: { name: 'Renewals', countdown_seconds: 3, voicemail_enabled: false } }
      : { id, row_version: 1, data: { full_name: id === 'c1' ? 'Lina Haddad' : 'Omar Saleh' } }));
    dialer.claim
      .mockReturnValueOnce(of({ member: { member_id: 'm1', entity_name: 'contact', record_id: 'c1', phone: '+966500000001' }, skipped: [] }))
      .mockReturnValueOnce(of({ member: { member_id: 'm2', entity_name: 'contact', record_id: 'c2', phone: '+966500000002' }, skipped: [] }));
    dialer.dial.mockReturnValue(of({ call_id: 'call-1', activity_id: 'a1' }));
    dialer.outcome.mockReturnValue(of({ attempt_id: 't1', attempt_number: 1, member_status: 'done' }));
    TestBed.configureTestingModule({
      imports: [DialerPanelComponent],
      providers: [
        { provide: DialerService, useValue: dialer },
        { provide: EntityService, useValue: entities },
        {
          provide: LangService,
          useValue: {
            translate: (k: string) => k, current, errorText: () => 'failed',
            isRtl: () => current() === 'ar',
          },
        },
      ],
    });
  });

  afterEach(() => vi.useRealTimers());

  function render() {
    const fixture = TestBed.createComponent(DialerPanelComponent);
    fixture.componentRef.setInput('id', 'list-1');
    fixture.detectChanges();
    TestBed.flushEffects();
    fixture.detectChanges();
    return fixture;
  }

  it('shows next record after outcome', () => {
    const fixture = render();
    const el: HTMLElement = fixture.nativeElement;
    (el.querySelector('[data-testid="dp-start"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(el.querySelector('[data-testid="dp-member"]')?.textContent).toContain('Lina Haddad');
    expect(el.querySelector('[data-testid="dp-countdown"]')?.textContent).toContain('3');
    vi.advanceTimersByTime(3000);
    fixture.detectChanges();
    expect(dialer.dial).toHaveBeenCalledWith('list-1', { to: '+966500000001', entity_name: 'contact', record_id: 'c1' });
    (el.querySelector('[data-outcome="connected"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(dialer.outcome).toHaveBeenCalledWith('m1', expect.objectContaining({ outcome: 'connected', activity_id: 'a1' }));
    expect(el.querySelector('[data-testid="dp-member"]')?.textContent).toContain('Omar Saleh');
  });

  it('renders right to left in Arabic', () => {
    current.set('ar');
    const fixture = render();
    const panel = fixture.nativeElement.querySelector('[data-testid="dp"]') as HTMLElement;
    expect(panel.getAttribute('dir')).toBe('rtl');
    (fixture.nativeElement.querySelector('[data-testid="dp-start"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    const phone = fixture.nativeElement.querySelector('.dp-phone') as HTMLElement;
    expect(phone.getAttribute('dir')).toBe('ltr');
  });
});
