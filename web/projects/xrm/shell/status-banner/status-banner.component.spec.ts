import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { OpsNotice, StatusBannerComponent, SystemStatus } from './status-banner.component';

describe('StatusBannerComponent (AB5-T9)', () => {
  function create(status: SystemStatus, notice: OpsNotice | null = null) {
    TestBed.configureTestingModule({
      imports: [StatusBannerComponent],
      providers: [
        { provide: ApiService, useValue: {
          get: vi.fn((url: string) => of(url.includes('/ops/status/banner') ? notice : status)),
        } },
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

  // AB11-T9
  it('banner hidden on 204', () => {
    const fixture = create({ read_only: false, degraded: [] }, null);
    expect(fixture.nativeElement.querySelector('[data-ops-notice]')).toBeNull();
    fixture.destroy();
  });

  it('shows the status page notice until it is dismissed', () => {
    const notice: OpsNotice = { kind: 'incident', id: 'i1', title: 'Search is slow', impact: 'partial', starts_at: '2026-10-28T08:00:00Z' };
    const fixture = create({ read_only: false, degraded: [] }, notice);
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-ops-notice="incident"]')?.textContent).toContain('systemStatus.incident');
    (el.querySelector('[data-dismiss]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(el.querySelector('[data-ops-notice]')).toBeNull();
    fixture.destroy();
  });
});
