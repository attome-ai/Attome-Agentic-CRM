import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { PresenceComponent, toPresence } from './presence.component';

describe('toPresence', () => {
  it('reads busy and away, and treats anything else as available', () => {
    expect(toPresence('busy')).toBe('busy');
    expect(toPresence('away')).toBe('away');
    expect(toPresence('available')).toBe('available');
    expect(toPresence(null)).toBe('available');
    expect(toPresence('on the moon')).toBe('available');
  });
});

describe('PresenceComponent (G5-T3)', () => {
  const api = { get: vi.fn(), put: vi.fn(), post: vi.fn() };

  beforeEach(() => {
    vi.resetAllMocks();
    vi.useFakeTimers();
    api.get.mockReturnValue(of({ items: [{ key: 'service.presence', value: 'busy' }] }));
    api.put.mockReturnValue(of({}));
    api.post.mockReturnValue(of({ viewers: [{ user_id: 'u2', name: 'Sara' }], heartbeat_secs: 30 }));
    TestBed.configureTestingModule({
      imports: [PresenceComponent],
      providers: [
        { provide: ApiService, useValue: api },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
  });

  afterEach(() => vi.useRealTimers());

  function render(entity: string | null = null, recordId: string | null = null) {
    const fixture = TestBed.createComponent(PresenceComponent);
    fixture.componentRef.setInput('entity', entity);
    fixture.componentRef.setInput('recordId', recordId);
    fixture.detectChanges();
    return fixture;
  }

  it('shows my stored presence and saves a change as my own setting', () => {
    const fixture = render();
    const el: HTMLElement = fixture.nativeElement;
    const select = el.querySelector('[data-testid="presence-select"]') as HTMLSelectElement;
    expect(fixture.componentInstance.presence()).toBe('busy');
    select.value = 'away';
    select.dispatchEvent(new Event('change'));
    expect(api.put).toHaveBeenCalledWith('/api/v1/settings/me/service.presence', { value: 'away' });
    expect(fixture.componentInstance.presence()).toBe('away');
    // No record: no heartbeat, no viewers line.
    expect(api.post).not.toHaveBeenCalled();
    expect(el.querySelector('[data-testid="presence-viewers"]')).toBeNull();
  });

  it('puts the old presence back when saving fails', () => {
    api.put.mockReturnValue(throwError(() => new Error('down')));
    const fixture = render();
    fixture.componentInstance.setPresence('available');
    fixture.detectChanges();
    expect(fixture.componentInstance.presence()).toBe('busy');
    expect((fixture.nativeElement as HTMLElement).querySelector('[role="alert"]')).not.toBeNull();
  });

  it('shows the colleagues viewing the record and keeps saying it is open', () => {
    const fixture = render('service_ticket', 't1');
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    expect(api.post).toHaveBeenCalledWith('/api/v1/service/viewing', { entity: 'service_ticket', record_id: 't1' });
    const names = Array.from(el.querySelectorAll('[data-testid="presence-viewer"]')).map(n => n.textContent?.trim());
    expect(names).toEqual(['Sara']);
    vi.advanceTimersByTime(30_000);
    expect(api.post).toHaveBeenCalledTimes(2);
    fixture.destroy();
    vi.advanceTimersByTime(60_000);
    expect(api.post).toHaveBeenCalledTimes(2);
  });

  it('shows nobody when the viewers cannot be read', () => {
    api.post.mockReturnValue(throwError(() => new Error('down')));
    const fixture = render('service_ticket', 't1');
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelectorAll('[data-testid="presence-viewer"]').length).toBe(0);
    expect(el.querySelector('[data-testid="presence-viewers"]')?.textContent).toContain('servicePresence.nobodyElse');
  });
});
