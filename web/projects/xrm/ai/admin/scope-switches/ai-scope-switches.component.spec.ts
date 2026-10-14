import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { AiScopeSwitchesComponent } from './ai-scope-switches.component';

describe('AiScopeSwitchesComponent (N31-T2)', () => {
  it('lists switched scopes and turns one off and back on', () => {
    const api = {
      get: vi.fn().mockReturnValue(of({ items: [
        { scope_kind: 'tool', scope_key: 'record.delete', enabled: false, cause: 'manual',
          reason: 'incident', changed_by: 'u1', changed_at: '2026-10-14T00:00:00Z' },
      ], total: 1, page: 1, page_size: 1000 })),
      put: vi.fn().mockReturnValue(of(undefined)),
    };
    TestBed.configureTestingModule({
      imports: [AiScopeSwitchesComponent],
      providers: [
        { provide: ApiService, useValue: api },
        { provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' } },
      ],
    });
    const fixture = TestBed.createComponent(AiScopeSwitchesComponent);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-scope="tool/record.delete"]')?.textContent).toContain('aiSwitches.off');

    const cmp = fixture.componentInstance;
    cmp.set('tool', 'record.delete', true, null);
    expect(api.put).toHaveBeenCalledWith('/api/v1/admin/ai/switches/tool/record.delete', { enabled: true, reason: null });

    cmp.newKind.set('agent');
    cmp.newKey.set('a1');
    cmp.newReason.set('over budget');
    cmp.switchOff();
    expect(api.put).toHaveBeenLastCalledWith('/api/v1/admin/ai/switches/agent/a1', { enabled: false, reason: 'over budget' });
  });
});
