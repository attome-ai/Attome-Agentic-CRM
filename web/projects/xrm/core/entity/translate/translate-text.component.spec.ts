import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { TranslateTextComponent } from './translate-text.component';

function render(post: ReturnType<typeof vi.fn>) {
  TestBed.resetTestingModule();
  TestBed.configureTestingModule({
    imports: [TranslateTextComponent],
    providers: [
      { provide: ApiService, useValue: { post } },
      { provide: LangService, useValue: {
        translate: (key: string) => key, current: signal('ar'), isRtl: signal(true), intlLocale: () => 'ar',
      } },
    ],
  });
  const fixture = TestBed.createComponent(TranslateTextComponent);
  fixture.componentRef.setInput('text', 'Please call the customer.');
  fixture.detectChanges();
  return fixture;
}

describe('TranslateTextComponent (N20-T2)', () => {
  it('translates into the viewer\'s language and can hide it again', () => {
    const post = vi.fn().mockReturnValue(of({ status: 'completed', result: { translation: 'يرجى الاتصال بالعميل.' } }));
    const fixture = render(post);
    fixture.componentInstance.translate();
    fixture.detectChanges();
    expect(post).toHaveBeenCalledWith('/api/v1/actions/text.translate/invoke', {
      args: { text: 'Please call the customer.', to: 'ar' },
    });
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-test="translation"]')?.textContent).toContain('يرجى الاتصال بالعميل.');
    fixture.componentInstance.translation.set(null);
    fixture.detectChanges();
    expect(el.querySelector('[data-test="translation"]')).toBeNull();
  });

  it('says so when translation is unavailable', () => {
    const fixture = render(vi.fn().mockReturnValue(throwError(() => ({ message: 'not found' }))));
    fixture.componentInstance.translate();
    fixture.detectChanges();
    expect(fixture.componentInstance.error()).toBe(true);
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('translateText.failed');
  });
});
