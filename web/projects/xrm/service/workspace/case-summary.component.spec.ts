import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { CaseSummaryComponent, summaryText } from './case-summary.component';

describe('summaryText', () => {
  it('reads a completed summary and nothing else', () => {
    expect(summaryText({ status: 'completed', result: { summary: 'Printer fixed.' } })).toBe('Printer fixed.');
    expect(summaryText({ status: 'completed', result: { summary: '  ' } })).toBeNull();
    expect(summaryText({ status: 'approval_required' })).toBeNull();
    expect(summaryText(null)).toBeNull();
  });
});

describe('CaseSummaryComponent (G1-T3)', () => {
  const api = { post: vi.fn() };

  beforeEach(() => {
    vi.resetAllMocks();
    TestBed.configureTestingModule({
      imports: [CaseSummaryComponent],
      providers: [
        { provide: ApiService, useValue: api },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(CaseSummaryComponent);
    fixture.componentRef.setInput('entity', 'service_ticket');
    fixture.componentRef.setInput('recordId', 't1');
    fixture.detectChanges();
    fixture.detectChanges();
    return fixture;
  }

  it('shows the case summary and asks again on refresh', () => {
    api.post.mockReturnValue(of({ status: 'completed', result: { summary: 'Waiting on the customer.', cached: true } }));
    const fixture = render();
    const el: HTMLElement = fixture.nativeElement;
    expect(api.post).toHaveBeenCalledWith('/api/v1/actions/record.summarize/invoke', {
      args: { entity: 'service_ticket', record_id: 't1' },
    });
    expect(el.querySelector('[data-testid="case-summary-text"]')?.textContent).toContain('Waiting on the customer.');
    (el.querySelector('[data-testid="case-summary-refresh"]') as HTMLButtonElement).click();
    expect(api.post).toHaveBeenCalledTimes(2);
  });

  it('shows nothing when AI is not available', () => {
    api.post.mockReturnValue(throwError(() => new Error('404')));
    const fixture = render();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('.case-summary')).toBeNull();
  });
});
