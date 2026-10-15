import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { ChangeFeedService } from '@attome/xrm/core/admin/data';
import { ChangeFeedComponent, dateInputToIso } from './change-feed.component';

describe('ChangeFeedComponent', () => {
  let fixture: ComponentFixture<ChangeFeedComponent>;
  let svc: { listChanges: ReturnType<typeof vi.fn>; listConsumers: ReturnType<typeof vi.fn> };

  async function render() {
    await TestBed.configureTestingModule({
      imports: [ChangeFeedComponent],
      providers: [
        provideRouter([]),
        { provide: ChangeFeedService, useValue: svc },
        { provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' } },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(ChangeFeedComponent);
    fixture.detectChanges();
  }

  const el = () => fixture.nativeElement as HTMLElement;

  const page = (refs: string[], nextCursor: string | null, total: number | null) => of({
    items: refs.map((reference, i) => ({
      kind: i % 2 ? 'settings' : 'metadata',
      occurred_at: '2026-09-22T10:00:00Z',
      actor: i % 2 ? 'Admin' : null,
      description: 'change ' + reference,
      reference,
    })),
    total, next_cursor: nextCursor,
  });

  beforeEach(() => {
    TestBed.resetTestingModule();
    svc = {
      listChanges: vi.fn().mockReturnValue(page(['e1', 's1'], 'c2', 120)),
      listConsumers: vi.fn().mockReturnValue(of({ items: [] })),
    };
  });

  it('loads the first page (no cursor) of a window pinned at load time', async () => {
    const before = Date.now();
    await render();
    const [filter, cursor, size] = svc.listChanges.mock.calls[0];
    expect(filter.kind).toBeUndefined();
    expect(filter.from).toBeUndefined();
    expect(new Date(filter.to).getTime()).toBeGreaterThanOrEqual(before);
    expect(cursor).toBeUndefined();
    expect(size).toBe(50);
    expect(el().querySelectorAll('tbody tr').length).toBe(2);
    expect(el().textContent).toContain('governance.changes.noActor');
    expect(el().textContent).toContain('Admin');
  });

  it('follows next_cursor forward and pops back through the same window', async () => {
    await render();
    const cmp = fixture.componentInstance;
    const firstFilter = svc.listChanges.mock.calls[0][0];
    expect(el().querySelector('.gov-pager')).not.toBeNull();
    expect(cmp.page()).toBe(1);
    expect(cmp.pages()).toBe(3);

    svc.listChanges.mockReturnValue(page(['e2'], 'c3', null));
    cmp.next();
    expect(svc.listChanges).toHaveBeenLastCalledWith(firstFilter, 'c2', 50);
    expect(cmp.page()).toBe(2);
    expect(cmp.total()).toBe(120);

    svc.listChanges.mockReturnValue(page(['e3'], null, null));
    cmp.next();
    expect(svc.listChanges).toHaveBeenLastCalledWith(firstFilter, 'c3', 50);
    expect(cmp.hasNext()).toBe(false);
    cmp.next();
    expect(svc.listChanges).toHaveBeenCalledTimes(3);

    svc.listChanges.mockReturnValue(page(['e2'], 'c3', null));
    cmp.previous();
    expect(svc.listChanges).toHaveBeenLastCalledWith(firstFilter, 'c2', 50);
    cmp.previous();
    expect(svc.listChanges).toHaveBeenLastCalledWith(firstFilter, undefined, 50);
    expect(cmp.hasPrevious()).toBe(false);
    cmp.previous();
    expect(svc.listChanges).toHaveBeenCalledTimes(5);
  });

  it('hides the pager when everything fits on one page', async () => {
    svc.listChanges.mockReturnValue(page(['e1'], null, 1));
    await render();
    expect(el().querySelector('.gov-pager')).toBeNull();
  });

  it('applies kind and a whole-day window, back on the first page', async () => {
    await render();
    const cmp = fixture.componentInstance;
    cmp.next();
    cmp.kind.set('security');
    cmp.from.set('2026-09-01');
    cmp.to.set('2026-09-02');
    cmp.apply();
    const [filter, cursor] = svc.listChanges.mock.calls.at(-1)!;
    expect(cursor).toBeUndefined();
    expect(cmp.page()).toBe(1);
    expect(filter.kind).toBe('security');
    expect(new Date(filter.from).getTime()).toBeLessThan(new Date(filter.to).getTime());
  });

  it('converts a date input to an inclusive ISO range', () => {
    const from = new Date(dateInputToIso('2026-09-01', false)!);
    const to = new Date(dateInputToIso('2026-09-01', true)!);
    expect(to.getTime() - from.getTime()).toBe(24 * 60 * 60 * 1000 - 1);
    expect(dateInputToIso('', false)).toBeUndefined();
    expect(dateInputToIso('not a date', true)).toBeUndefined();
  });
});
