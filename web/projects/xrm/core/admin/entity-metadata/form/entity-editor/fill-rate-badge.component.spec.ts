import { TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { LangService } from '@attome/base';
import { FillRateBadgeComponent } from './fill-rate-badge.component';

describe('FillRateBadgeComponent (L6-T7)', () => {
  beforeEach(() => {
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      imports: [FillRateBadgeComponent],
      providers: [{ provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' } }],
    });
  });

  function render(rate: number | null | undefined) {
    const fixture = TestBed.createComponent(FillRateBadgeComponent);
    fixture.componentRef.setInput('rate', rate);
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  it('shows nothing for an unprofiled field', () => {
    expect(render(undefined).querySelector('[data-fill-rate]')).toBeNull();
  });

  it('bands the rate', () => {
    expect(render(95).querySelector('[data-fill-rate]')?.classList).toContain('fr-good');
    expect(render(60).querySelector('[data-fill-rate]')?.classList).toContain('fr-fair');
    expect(render(10).querySelector('[data-fill-rate]')?.classList).toContain('fr-poor');
    expect(render(0).querySelector('[data-fill-rate]')?.classList).toContain('fr-poor');
  });
});
