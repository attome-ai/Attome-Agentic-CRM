import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { ModelService } from '../model.service';
import { ModelTestsPreviewComponent } from './model-tests-preview.component';

describe('ModelTestsPreviewComponent (T7-T2)', () => {
  it('runs the affected tests and lists their results', () => {
    const previewTests = vi.fn(() => of([
      { id: 't1', name: 'Discount needs approval', blocking: true, passed: false, failures: ['deal d.status is open'] },
      { id: 't2', name: 'Lead gets an owner', blocking: false, passed: true, failures: [] },
    ]));
    TestBed.configureTestingModule({
      imports: [ModelTestsPreviewComponent],
      providers: [
        { provide: ModelService, useValue: { previewTests } },
        { provide: LangService, useValue: { translate: (k: string) => k, intlLocale: () => 'en-US' } },
      ],
    });
    const fixture = TestBed.createComponent(ModelTestsPreviewComponent);
    fixture.componentRef.setInput('kind', 'page');
    fixture.componentRef.setInput('objectId', 'p1');
    fixture.componentRef.setInput('doc', { name: 'Home' });
    fixture.detectChanges();
    (fixture.nativeElement.querySelector('[data-testid="mtp-run"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(previewTests).toHaveBeenCalledWith('page', 'p1', { name: 'Home' });
    const items = fixture.nativeElement.querySelectorAll('[data-testid="mtp-results"] li');
    expect(items.length).toBe(2);
    expect(items[0].textContent).toContain('modelTests.failed');
    expect(items[0].textContent).toContain('deal d.status is open');
    expect(items[1].textContent).toContain('modelTests.passed');
  });
});
