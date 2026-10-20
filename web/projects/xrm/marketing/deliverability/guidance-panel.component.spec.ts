import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { beforeEach, describe, expect, it } from 'vitest';

import type { DeliverabilityAlert } from './deliverability.service';
import { GuidancePanelComponent } from './guidance-panel.component';

const AR: Record<string, string> = {
  'deliverabilityAlert.bounce_rate': 'معدل الارتداد مرتفع: احذف العناوين غير الصالحة.',
  'marketingDeliverability.kind.bounce_rate': 'معدل الارتداد',
};

const alert: DeliverabilityAlert = {
  day: '2026-10-19',
  subject: 'mail.example.com (gmail)',
  kind: 'bounce_rate',
  value: 4.5,
  threshold: 2,
  guidance_key: 'deliverabilityAlert.bounce_rate',
};

describe('GuidancePanelComponent (E6-T13)', () => {
  const current = signal<'en' | 'ar'>('ar');

  beforeEach(() => {
    current.set('ar');
    TestBed.configureTestingModule({
      imports: [GuidancePanelComponent],
      providers: [{
        provide: LangService,
        useValue: {
          current,
          translate: (k: string) => (current() === 'ar' ? AR[k] ?? k : k),
          isRtl: () => current() === 'ar',
          intlLocale: () => (current() === 'ar' ? 'ar' : 'en'),
        },
      }],
    });
  });

  it('renders an alert in Arabic, right to left, with figures left to right', () => {
    const fixture = TestBed.createComponent(GuidancePanelComponent);
    fixture.componentRef.setInput('alerts', [alert]);
    fixture.detectChanges();
    const root: HTMLElement = fixture.nativeElement;
    const section = root.querySelector('[data-testid="dg"]') as HTMLElement;
    expect(section.getAttribute('dir')).toBe('rtl');
    const items = root.querySelectorAll('[data-testid="dg-item"]');
    expect(items.length).toBe(1);
    expect(items[0].textContent).toContain('معدل الارتداد');
    expect(root.querySelector('[data-testid="dg-guidance"]')?.textContent?.trim())
      .toBe(AR['deliverabilityAlert.bounce_rate']);
    const figures = [...items[0].querySelectorAll('[dir="ltr"]')].map(e => e.textContent?.trim());
    expect(figures).toContain('mail.example.com (gmail)');
    expect(figures).toContain('4.5%');
    expect(figures).toContain('2%');
  });

  it('says so when there are no alerts, left to right in English', () => {
    current.set('en');
    const fixture = TestBed.createComponent(GuidancePanelComponent);
    fixture.detectChanges();
    const root: HTMLElement = fixture.nativeElement;
    expect(root.querySelector('[data-testid="dg"]')?.getAttribute('dir')).toBe('ltr');
    expect(root.querySelector('[data-testid="dg-empty"]')?.textContent?.trim())
      .toBe('marketingDeliverability.noAlerts');
  });
});
