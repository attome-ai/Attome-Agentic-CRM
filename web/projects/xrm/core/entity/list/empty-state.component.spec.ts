import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { beforeEach, describe, expect, it } from 'vitest';
import { xrmAr } from '@attome/xrm/core/i18n-ar';
import { xrmEn } from '@attome/xrm/core/i18n-en';
import { EmptyStateComponent, type EmptyReason } from './empty-state.component';

describe('EmptyStateComponent (AK4-T1)', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [EmptyStateComponent],
      providers: [{ provide: LangService, useValue: { translate: (key: string) => key, isRtl: () => false } }],
    });
  });

  function render(reason: EmptyReason, canCreate: boolean) {
    const fixture = TestBed.createComponent(EmptyStateComponent);
    fixture.componentRef.setInput('reason', reason);
    fixture.componentRef.setInput('canCreate', canCreate);
    fixture.detectChanges();
    return fixture;
  }

  it('offers to create the first record when the list has none and the caller may create', () => {
    const fixture = render('none', true);
    let created = 0;
    fixture.componentInstance.create.subscribe(() => created++);
    const el: HTMLElement = fixture.nativeElement;
    expect(el.textContent).toContain('emptyState.noneTitle');
    expect(el.textContent).toContain('emptyState.noneHintCreate');
    const button = el.querySelector<HTMLButtonElement>('[data-empty-action="create"]');
    expect(button).not.toBeNull();
    button!.click();
    expect(created).toBe(1);
    expect(el.querySelector('[data-empty-action="clear"]')).toBeNull();
  });

  it('offers no action to a caller who may not create', () => {
    const el: HTMLElement = render('none', false).nativeElement;
    expect(el.textContent).toContain('emptyState.noneHint');
    expect(el.querySelector('button')).toBeNull();
  });

  it('offers to clear the filters when filters matched nothing', () => {
    const fixture = render('filtered', true);
    let cleared = 0;
    fixture.componentInstance.clearFilters.subscribe(() => cleared++);
    const el: HTMLElement = fixture.nativeElement;
    expect(el.textContent).toContain('emptyState.filteredTitle');
    el.querySelector<HTMLButtonElement>('[data-empty-action="clear"]')!.click();
    expect(cleared).toBe(1);
    expect(el.querySelector('[data-empty-action="create"]')).toBeNull();
  });

  it('has every key in both catalogs', () => {
    const keys = ['filteredTitle', 'filteredHint', 'noneTitle', 'noneHint', 'noneHintCreate', 'clearFilters', 'createFirst'];
    for (const key of keys) {
      expect((xrmEn.emptyState as Record<string, string>)[key], `en ${key}`).toBeTruthy();
      expect((xrmAr.emptyState as Record<string, string>)[key], `ar ${key}`).toBeTruthy();
    }
    expect(xrmEn.dashboard.viewer.openDesigner).toBeTruthy();
    expect(xrmAr.dashboard.viewer.openDesigner).toBeTruthy();
  });
});
