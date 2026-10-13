import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AdminAiService } from '../../services/admin-ai.service';
import { AiRuntimeSwitchComponent } from './ai-runtime-switch.component';

const VIEW = {
  surfaces: [
    { surface: 'all', configured: true, runtime_enabled: true, effective: true },
    { surface: 'chat', configured: true, runtime_enabled: false, effective: false, reason: 'incident' },
    { surface: 'webchat', configured: false, runtime_enabled: true, effective: false },
  ],
};

describe('AiRuntimeSwitchComponent', () => {
  let adminAi: Record<string, ReturnType<typeof vi.fn>>;

  beforeEach(() => {
    adminAi = {
      runtimeSwitch: vi.fn().mockReturnValue(of(VIEW)),
      setRuntimeSwitch: vi.fn().mockReturnValue(of(VIEW)),
    };
    TestBed.configureTestingModule({
      imports: [AiRuntimeSwitchComponent],
      providers: [
        { provide: AdminAiService, useValue: adminAi },
        { provide: LangService, useValue: { translate: (k: string) => k, intlLocale: () => 'en' } },
      ],
    });
    TestBed.overrideComponent(AiRuntimeSwitchComponent, { set: { template: '' } });
  });

  function create() {
    const fixture = TestBed.createComponent(AiRuntimeSwitchComponent);
    fixture.detectChanges();
    return fixture.componentInstance;
  }

  /** Row A-85 at the screen: switching off asks for a reason, switching on does not. */
  it('asks for a reason before switching off, and not before switching on', () => {
    const c = create();
    expect(c.visible()).toBe(true);
    c.toggle(VIEW.surfaces[0] as never);
    expect(adminAi['setRuntimeSwitch']).not.toHaveBeenCalled();
    expect(c.confirming()).toBe('all');
    c.reason.set('  model misbehaving  ');
    c.confirmOff();
    expect(adminAi['setRuntimeSwitch']).toHaveBeenCalledWith('all', false, 'model misbehaving');

    c.toggle(VIEW.surfaces[1] as never);
    expect(adminAi['setRuntimeSwitch']).toHaveBeenLastCalledWith('chat', true, null);
  });

  it('stays hidden for a caller who is not an administrator', () => {
    adminAi['runtimeSwitch'].mockReturnValue(throwError(() => ({ status: 403, message: 'no' })));
    const c = create();
    expect(c.visible()).toBe(false);
    expect(c.error()).toBeNull();
  });
});
