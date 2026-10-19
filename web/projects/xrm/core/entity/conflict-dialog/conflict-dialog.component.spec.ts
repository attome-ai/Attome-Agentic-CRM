import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService, VersionConflictState } from '@attome/base';
import { describe, expect, it } from 'vitest';

import { ConflictChoices, ConflictDialogComponent } from './conflict-dialog.component';

const details: VersionConflictState = {
  currentVersion: 6,
  lastChangedBy: 'Sara',
  lastChangedAt: '2026-10-19T09:12:44Z',
  changedAttributes: [
    { name: 'amount', their_value: '120000', changed_by: 'Sara', changed_at: '2026-10-19T09:12:44Z' },
    { name: 'stage', their_value: 'Negotiation', changed_by: null, changed_at: null },
  ],
  hiddenChanges: 1,
};

describe('ConflictDialogComponent (A16-T3)', () => {
  function setUp(lang = 'en') {
    TestBed.configureTestingModule({
      imports: [ConflictDialogComponent],
      providers: [
        {
          provide: LangService,
          useValue: {
            intlLocale: signal('en-US'),
            translate: (key: string) => key,
            current: signal(lang),
            isRtl: signal(lang === 'ar'),
          },
        },
      ],
    });
    const fixture = TestBed.createComponent(ConflictDialogComponent);
    fixture.componentRef.setInput('details', details);
    fixture.componentRef.setInput('mine', { amount: 125000, stage: 'Proposal', title: 'typed, not in conflict' });
    fixture.componentRef.setInput('labelOf', (name: string) => `Label ${name}`);
    fixture.detectChanges();
    const root = fixture.nativeElement as HTMLElement;
    return { fixture, root, dialog: fixture.componentInstance };
  }

  it('lists each changed attribute with your value and theirs', () => {
    const { root } = setUp();
    const rows = root.querySelectorAll('[data-conflict-row]');
    expect(rows.length).toBe(2);
    const amount = root.querySelector('[data-conflict-row="amount"]') as HTMLElement;
    expect(amount.textContent).toContain('Label amount');
    expect(amount.textContent).toContain('125000');
    expect(amount.textContent).toContain('120000');
    expect(root.querySelector('[data-conflict-hidden]')).not.toBeNull();
  });

  it('keeps mine by default and answers the choices made', () => {
    const { root, dialog } = setUp();
    let answered: ConflictChoices | null = null;
    dialog.resolve.subscribe(choices => (answered = choices));
    (root.querySelector('[data-conflict-pick="stage:theirs"]') as HTMLInputElement).click();
    (root.querySelector('[data-conflict-confirm]') as HTMLButtonElement).click();
    expect(answered).toEqual({ amount: 'mine', stage: 'theirs' });
  });

  it('cancels without choosing', () => {
    const { root, dialog } = setUp();
    let cancelled = false;
    let answered = false;
    dialog.cancelled.subscribe(() => (cancelled = true));
    dialog.resolve.subscribe(() => (answered = true));
    (root.querySelector('[data-conflict-cancel]') as HTMLButtonElement).click();
    expect(cancelled).toBe(true);
    expect(answered).toBe(false);
  });

  it('renders the same rows right to left', () => {
    const { root } = setUp('ar');
    document.documentElement.setAttribute('dir', 'rtl');
    try {
      expect(root.querySelectorAll('[data-conflict-row]').length).toBe(2);
      expect(root.querySelector('[data-conflict-pick="amount:mine"]')).not.toBeNull();
    } finally {
      document.documentElement.removeAttribute('dir');
    }
  });
});
