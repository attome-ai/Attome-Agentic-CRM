import { TestBed } from '@angular/core/testing';
import { Component, input, signal } from '@angular/core';
import { Router } from '@angular/router';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';
import { ATTOME_CONFIG, ApiService, LangService } from '@attome/base';
import { AccessService } from '@attome/xrm/core/access/data';
import { EntityService, RecordTabPanelsComponent, XrmBaseFormComponent } from '@attome/xrm/core/entity';
import type { XrmFormTabDef } from '@attome/xrm/core/entity';
import type { EntitySchema } from '@attome/xrm';
import { CERTIFY_PRIVILEGE, DashboardMetricDefinitionFormComponent } from './dashboard-metric-definition-form.component';

@Component({ selector: 'xrm-record-tab-panels', standalone: true, template: '' })
class RecordTabPanelsStubComponent {
  readonly entityName = input.required<string>();
  readonly recordId   = input<string | null>(null);
  readonly tabs       = input.required<XrmFormTabDef[]>();
  readonly activeTab  = input.required<string>();
  readonly idPrefix   = input('entity');
}

const SCHEMA = {
  id: 'e1', name: 'Metric', logical_name: 'dashboard_metric_definition',
  fields: [
    { id: 'f1', entity_id: 'e1', name: 'name', display_name: 'Name', field_type: 'text', options: null, sort_order: 0, is_required: false },
    { id: 'f2', entity_id: 'e1', name: 'aggregate', display_name: 'Aggregate', field_type: 'text', options: null, sort_order: 1, is_required: false },
    { id: 'f3', entity_id: 'e1', name: 'review_due', display_name: 'Review due', field_type: 'text', options: null, sort_order: 2, is_required: false },
  ],
} as unknown as EntitySchema;

const ARABIC: Record<string, string> = {
  'metricForm.sections.details': 'التفاصيل',
  'metricForm.sections.builder': 'مصدر الحساب',
  'metricForm.sections.governance': 'الحوكمة',
  'metricForm.certified': 'معتمد',
  'metricForm.notCertified': 'غير معتمد',
  'metricForm.certify': 'اعتماد',
};

/** Configures the form with the real services (other parts of the form use
 * them); only the privilege answer is chosen, and in Arabic or English. */
function setUp(privileged: boolean, arabic: boolean): void {
  TestBed.configureTestingModule({
    imports: [DashboardMetricDefinitionFormComponent],
    providers: [
      provideHttpClient(),
      provideHttpClientTesting(),
      { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
      {
        provide: EntityService,
        useValue: {
          getSchema: () => of(SCHEMA),
          get: () => of({ id: 'm1', row_version: 1, data: { name: 'Win rate', certified: false } }),
        },
      },
      {
        provide: Router,
        useValue: { navigate: vi.fn(), url: '/', parseUrl: () => ({ queryParamMap: { get: () => null } }) },
      },
      {
        provide: LangService,
        useValue: {
          translate: (key: string) => (arabic ? ARABIC[key] ?? key : key),
          current: signal(arabic ? 'ar' : 'en'),
          isRtl: () => arabic,
        },
      },
    ],
  });
  TestBed.overrideComponent(XrmBaseFormComponent, {
    remove: { imports: [RecordTabPanelsComponent] },
    add: { imports: [RecordTabPanelsStubComponent] },
  });
  vi.spyOn(TestBed.inject(AccessService), 'hasPrivilege')
    .mockImplementation((key: string) => privileged && key === CERTIFY_PRIVILEGE);
}

function create() {
  const fixture = TestBed.createComponent(DashboardMetricDefinitionFormComponent);
  fixture.componentRef.setInput('name', 'dashboard_metric_definition');
  fixture.componentRef.setInput('id', 'm1');
  fixture.detectChanges();
  return { fixture, el: fixture.nativeElement as HTMLElement };
}

describe('DashboardMetricDefinitionFormComponent (P9-T14)', () => {
  it('shows its sections with Arabic titles', () => {
    setUp(false, true);
    const { el } = create();
    const titles = Array.from(el.querySelectorAll('.xf-section-title')).map(h => h.textContent?.trim());
    expect(titles).toEqual(['التفاصيل', 'مصدر الحساب', 'الحوكمة']);
    expect(el.querySelector('[data-testid="certification"]')?.textContent).toContain('غير معتمد');
  });

  it('hides certification from a caller without the certify privilege', () => {
    setUp(false, false);
    const { el } = create();
    expect(el.querySelector('[data-testid="certify-button"]')).toBeNull();
  });

  it('offers certification to a holder of the certify privilege', () => {
    setUp(true, false);
    const post = vi.spyOn(TestBed.inject(ApiService), 'post').mockReturnValue(
      of({ metric_id: 'm1', certified: true, certified_at: '2026-10-29T00:00:00Z' }) as never,
    );
    const { el } = create();
    const button = el.querySelector<HTMLButtonElement>('[data-testid="certify-button"]');
    expect(button).not.toBeNull();
    button?.click();
    expect(post).toHaveBeenCalledWith('/api/v1/metrics/m1/certify', { certified: true });
  });
});
