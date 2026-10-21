import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { AiWorkShareComponent, dayBar, sharePercent, workShareRange } from './ai-work-share.component';
import { AiWorkShareService } from './ai-work-share.service';
import type { ProcessShare } from './ai-work-share.service';

describe('AiWorkShareComponent (AK3-T7)', () => {
  let fixture: ComponentFixture<AiWorkShareComponent>;

  async function render(items: ProcessShare[]) {
    await TestBed.configureTestingModule({
      imports: [AiWorkShareComponent],
      providers: [
        provideRouter([]),
        {
          provide: AiWorkShareService,
          useValue: {
            summary: vi.fn().mockReturnValue(of({ items, total: items.length, page: 1, page_size: 200 })),
            events: vi.fn().mockReturnValue(of({
              items: [{ id: 'e1', entity: 'service_ticket', record_id: 't1', at: '2026-10-21T10:00:00Z', agent_session_id: 's1' }],
              next_cursor: null,
            })),
          },
        },
        {
          provide: LangService,
          useValue: {
            translate: (key: string) => key, intlLocale: () => 'en-US', current: () => 'en',
            errorText: (e: { message?: string }) => e.message ?? 'error',
          },
        },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(AiWorkShareComponent);
    fixture.detectChanges();
  }

  const el = () => fixture.nativeElement as HTMLElement;

  beforeEach(() => TestBed.resetTestingModule());

  it('rounds the share to a whole percentage and says when nothing was done', () => {
    expect(sharePercent(null)).toBeNull();
    expect(sharePercent(0)).toBe(0);
    expect(sharePercent(1 / 3)).toBe(33);
    expect(sharePercent(2 / 3)).toBe(67);
    expect(sharePercent(0.125)).toBe(13);
    expect(sharePercent(1)).toBe(100);
  });

  it('draws a day as the agents\' part of its completions', () => {
    expect(dayBar({ day: '2026-10-21', done_by_agent: 1, done_by_person: 3, handed_between: 0 })).toBe(25);
    expect(dayBar({ day: '2026-10-21', done_by_agent: 0, done_by_person: 0, handed_between: 2 })).toBe(0);
  });

  it('covers the 30 days ending today', () => {
    const range = workShareRange(new Date('2026-10-21T12:00:00Z'));
    expect(range).toEqual({ from: '2026-09-22', to: '2026-10-21' });
  });

  it('shows the empty state when no measure is active', async () => {
    await render([]);
    expect(el().querySelector('[data-empty]')).not.toBeNull();
  });

  it('shows each process with its share and opens the records behind a count', async () => {
    await render([{
      process_key: 'service.ticket_resolved', label: 'Ticket resolved', label_ar: null,
      done_by_agent: 1, done_by_person: 2, handed_between: 1, share: 1 / 3,
      days: [{ day: '2026-10-21', done_by_agent: 1, done_by_person: 2, handed_between: 1 }],
    }]);
    const process = el().querySelector('[data-process="service.ticket_resolved"]');
    expect(process?.textContent).toContain('Ticket resolved');
    expect(process?.querySelector('[data-share]')?.textContent).toContain('aiWorkShare.share');
    const cmp = fixture.componentInstance;
    cmp.open(cmp.processes()[0], '2026-10-21', 'agent');
    fixture.detectChanges();
    const service = TestBed.inject(AiWorkShareService) as unknown as { events: ReturnType<typeof vi.fn> };
    expect(service.events).toHaveBeenCalledWith('service.ticket_resolved', '2026-10-21', 'agent', null);
    expect(el().querySelector('.aws-events a')?.textContent).toContain('t1');
  });
});
