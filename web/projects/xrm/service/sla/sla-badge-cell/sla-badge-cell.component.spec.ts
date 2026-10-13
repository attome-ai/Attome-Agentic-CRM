import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService, UserPreferencesService } from '@attome/base';
import { EntityRouteRegistry } from '@attome/xrm/core/entity';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { registerServiceEntityForms } from '../../provide-service-entity-forms';
import { SlaBadgeCellComponent } from './sla-badge-cell.component';

describe('SlaBadgeCellComponent', () => {
  const NOW = Date.parse('2026-09-23T12:00:00Z');

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
    TestBed.configureTestingModule({
      imports: [SlaBadgeCellComponent],
      providers: [
        {
          provide: LangService,
          useValue: {
            intlLocale: () => 'en-US',
            translate: (key: string) => key,
          },
        },
        { provide: UserPreferencesService, useValue: { timezone: signal<string | null>('UTC') } },
      ],
    });
  });

  afterEach(() => vi.useRealTimers());

  function render(row: Record<string, unknown> | null) {
    const fixture = TestBed.createComponent(SlaBadgeCellComponent);
    fixture.componentRef.setInput('row', row);
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  it('renders the badge from the list row', () => {
    const el = render({
      sla_policy_id: 'p1', resolution_due_at: '2026-09-23T15:00:00Z', status: 'open',
      sla_breached: false, sla_warned: false,
    });

    expect(el.querySelector('[data-testid="sla-badge"]')?.getAttribute('data-kind')).toBe('due');
  });

  it('renders nothing for a ticket with no SLA', () => {
    const el = render({ status: 'open' });

    expect(el.querySelector('[data-testid="sla-badge"]')).toBeNull();
  });

  it('is registered as the ticket list\'s resolution_due_at cell', () => {
    const registry = new EntityRouteRegistry();
    registerServiceEntityForms(registry);

    expect(registry.get('service_ticket')?.cellRenderers?.['resolution_due_at']).toBe(SlaBadgeCellComponent);
  });
});
