import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { StatusBannerComponent, SystemStatus } from './status-banner.component';

describe('StatusBannerComponent (AB5-T9)', () => {
  function create(status: SystemStatus) {
    TestBed.configureTestingModule({
      imports: [StatusBannerComponent],
      providers: [
        { provide: ApiService, useValue: { get: vi.fn().mockReturnValue(of(status)) } },
        { provide: LangService, useValue: { translate: (k: string) => k } },
      ],
    });
    const fixture = TestBed.createComponent(StatusBannerComponent);
    fixture.detectChanges();
    return fixture;
  }

  it('shows read-only banner', () => {
    const fixture = create({ read_only: true, degraded: [{ feature: 'files', message_key: 'systemStatus.files' }] });
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-read-only]')?.textContent).toContain('systemStatus.readOnly');
    expect(el.querySelector('[data-feature="files"]')?.textContent).toContain('systemStatus.files');
    fixture.destroy();
  });

  it('hides when nothing degraded', () => {
    const fixture = create({ read_only: false, degraded: [] });
    expect(fixture.nativeElement.querySelector('[data-status-banner]')).toBeNull();
    fixture.destroy();
  });
});
