import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { MemberExplainDialogComponent } from './member-explain-dialog.component';
import { SegmentInsightService } from './segment-insight.service';

const LIST = '019a0000-0000-7000-8000-000000000001';
const OTHER = '019a0000-0000-7000-8000-000000000003';
const PERSON = '019a0000-0000-7000-8000-000000000002';

describe('MemberExplainDialogComponent (E7-T12)', () => {
  const current = signal<'en' | 'ar'>('en');
  const insight = { explain: vi.fn() };

  beforeEach(() => {
    current.set('en');
    vi.clearAllMocks();
    TestBed.configureTestingModule({
      imports: [MemberExplainDialogComponent],
      providers: [
        { provide: SegmentInsightService, useValue: insight },
        {
          provide: LangService,
          useValue: {
            current,
            translate: (k: string) => k,
            isRtl: () => current() === 'ar',
            intlLocale: () => 'en',
          },
        },
      ],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(MemberExplainDialogComponent);
    fixture.componentRef.setInput('listId', LIST);
    fixture.componentRef.setInput('personId', PERSON);
    fixture.detectChanges();
    return fixture;
  }

  it('lists each step and the verdict', () => {
    insight.explain.mockReturnValue(of({
      list_id: LIST,
      person_id: PERSON,
      member: false,
      steps: [
        { step: 'base', list_id: LIST, holds: true, member_after: true },
        { step: 'exclude', list_id: OTHER, holds: true, member_after: false },
      ],
    }));
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    expect(insight.explain).toHaveBeenCalledWith(LIST, PERSON);
    expect(root.querySelector('[data-testid="me-verdict"]')?.textContent).toContain('segmentInsight.notMember');
    const steps = root.querySelectorAll('[data-testid="me-step"]');
    expect(steps.length).toBe(2);
    expect(steps[0].textContent).toContain('segmentInsight.stepBase');
    expect(steps[1].textContent).toContain('exclude');
    expect(steps[1].textContent).toContain('segmentInsight.outAfter');
  });

  it('says so when the explanation cannot be read, and closes', () => {
    insight.explain.mockReturnValue(throwError(() => new Error('404')));
    current.set('ar');
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    expect(root.querySelector('[data-testid="me"]')?.getAttribute('dir')).toBe('rtl');
    expect(root.querySelector('[role="alert"]')?.textContent).toContain('segmentInsight.explainFailed');
    let closed = false;
    fixture.componentInstance.closed.subscribe(() => (closed = true));
    (root.querySelector('[data-testid="me-close"]') as HTMLButtonElement).click();
    expect(closed).toBe(true);
  });
});
