import { TestBed } from '@angular/core/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { LangService, WorkspaceState } from '@attome/base';
import { WorkspaceBannerComponent } from './workspace-banner.component';

describe('WorkspaceBannerComponent (T5-T7)', () => {
  beforeEach(() => {
    sessionStorage.clear();
    TestBed.configureTestingModule({
      imports: [WorkspaceBannerComponent],
      providers: [
        {
          provide: LangService,
          useValue: {
            translate: (k: string, p?: Record<string, unknown>) => (p ? `${k} ${Object.values(p).join(' ')}` : k),
            current: () => 'en',
          },
        },
      ],
    });
  });

  afterEach(() => sessionStorage.clear());

  function render(): HTMLElement {
    const fixture = TestBed.createComponent(WorkspaceBannerComponent);
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  it('shows nothing on live', () => {
    expect(render().querySelector('[data-workspace-banner]')).toBeNull();
  });

  it('shows the workspace by name while inside one', () => {
    TestBed.inject(WorkspaceState).enter({ id: 'ws-1', name: 'Sales rework' });
    const banner = render().querySelector('[data-workspace-banner]');
    expect(banner).not.toBeNull();
    expect(banner?.textContent).toContain('Sales rework');
  });

  it('goes back to live from its button', () => {
    const state = TestBed.inject(WorkspaceState);
    state.enter({ id: 'ws-1', name: 'Sales rework' });
    const fixture = TestBed.createComponent(WorkspaceBannerComponent);
    fixture.detectChanges();
    fixture.componentInstance.state.leave();
    fixture.detectChanges();
    expect(state.active()).toBeNull();
    expect((fixture.nativeElement as HTMLElement).querySelector('[data-workspace-banner]')).toBeNull();
  });
});
