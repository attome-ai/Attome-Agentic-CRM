import { TestBed } from '@angular/core/testing';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { ApiService } from '../api.service';
import { Tour, autoTour, localText, routeMatches, tourFor } from './tour';
import { TourService } from './tour.service';

const tour = (id: string, route: string, auto = true): Tour => ({
  id, name: id, route, auto_start: auto,
  title: { en: id, ar: 'جولة' },
  steps: [
    { selector: '#a', text: { en: 'First', ar: 'الأولى' } },
    { selector: '#b', text: { en: 'Second' } },
  ],
});

describe('tours (B14-T1)', () => {
  it('matches a route and prefers the most specific tour', () => {
    expect(routeMatches('/xrm/entity/opportunity', '/xrm/entity/opportunity/list?x=1')).toBe(true);
    expect(routeMatches('/xrm/entity/opportunity', '/xrm/entity/opportunity_line')).toBe(false);
    const tours = [tour('home', '/xrm'), tour('deals', '/xrm/entity/opportunity')];
    expect(tourFor(tours, '/xrm/entity/opportunity/list')?.id).toBe('deals');
    expect(tourFor(tours, '/xrm/admin')?.id).toBe('home');
    expect(autoTour(tours, '/xrm/entity/opportunity', ['deals'])?.id).toBe('home');
    expect(autoTour([tour('manual', '/xrm', false)], '/xrm', [])).toBeNull();
  });

  it('shows text in the page language, falling back to the other', () => {
    expect(localText({ en: 'Hi', ar: 'مرحبا' }, 'ar')).toBe('مرحبا');
    expect(localText({ en: 'Hi' }, 'ar')).toBe('Hi');
    expect(localText({ ar: 'مرحبا' }, 'en')).toBe('مرحبا');
    expect(localText(undefined, 'en')).toBe('');
  });

  function service(seen: string[] = []) {
    const put = vi.fn((_: string, _body: unknown) => of({}));
    const get = vi.fn((path: string) => of(path.endsWith('/tours')
      ? { items: [tour('deals', '/xrm/entity/opportunity')] }
      : { items: [{ key: 'core.tours_seen', value: seen }] }));
    TestBed.configureTestingModule({ providers: [{ provide: ApiService, useValue: { get, put } }] });
    return { svc: TestBed.inject(TourService), put };
  }

  it('starts a new tour once and remembers it when finished', async () => {
    const { svc, put } = service();
    await svc.onNavigate('/xrm/entity/opportunity/list');
    expect(svc.active()?.tour.id).toBe('deals');
    expect(svc.step()?.selector).toBe('#a');
    svc.next();
    expect(svc.step()?.selector).toBe('#b');
    svc.back();
    expect(svc.step()?.selector).toBe('#a');
    svc.next();
    svc.next();
    expect(svc.active()).toBeNull();
    expect(put).toHaveBeenCalledWith('/api/v1/settings/me/core.tours_seen', { value: ['deals'] });
  });

  it('does not start a seen tour, and a replay is not recorded', async () => {
    const { svc, put } = service(['deals']);
    await svc.onNavigate('/xrm/entity/opportunity');
    expect(svc.active()).toBeNull();
    expect(await svc.replayFor('/xrm/entity/opportunity')).toBe(true);
    svc.finish();
    expect(put).not.toHaveBeenCalled();
    expect(await svc.replayFor('/xrm/admin')).toBe(false);
  });
});
