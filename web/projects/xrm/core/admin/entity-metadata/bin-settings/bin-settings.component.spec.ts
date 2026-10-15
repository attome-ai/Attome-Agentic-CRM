import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { BinSettingsComponent } from './bin-settings.component';

describe('BinSettingsComponent (A18-T9)', () => {
  function create(items: unknown[]) {
    const get = vi.fn().mockReturnValue(of({ items }));
    const put = vi.fn().mockImplementation((_path: string, body: object) => of({ entity: 'account', ...body }));
    TestBed.configureTestingModule({
      imports: [BinSettingsComponent],
      providers: [
        { provide: ApiService, useValue: { get, put } },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
    const fixture = TestBed.createComponent(BinSettingsComponent);
    fixture.componentRef.setInput('entity', 'account');
    fixture.detectChanges();
    TestBed.flushEffects();
    fixture.detectChanges();
    return { fixture, get, put };
  }

  it('shows the entity\'s own rules', () => {
    const { fixture, get } = create([
      { entity: 'contact', require_reason: false, retention_days: 7, alert_threshold: 5, hard_delete_needs_approval: false },
      { entity: 'account', require_reason: true, retention_days: 90, alert_threshold: 20, hard_delete_needs_approval: true },
    ]);
    expect(get).toHaveBeenCalledWith('/api/v1/admin/bin-settings');
    const c = fixture.componentInstance;
    expect(c.requireReason()).toBe(true);
    expect(c.approval()).toBe(true);
    expect(c.threshold()).toBe(20);
    expect(c.retention()).toBe(90);
    // A value set elsewhere stays selectable.
    expect(c.choices).toContain(90);
  });

  it('saves the rules for its entity', () => {
    const { fixture, put } = create([]);
    const c = fixture.componentInstance;
    expect(c.retention()).toBeNull();
    c.retention.set(30);
    c.requireReason.set(true);
    c.save();
    expect(put).toHaveBeenCalledWith('/api/v1/admin/bin-settings/account', {
      require_reason: true, retention_days: 30, alert_threshold: 100, hard_delete_needs_approval: false,
    });
    expect(c.saved()).toBe(true);
  });
});
