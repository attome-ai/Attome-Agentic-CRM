import { TestBed } from '@angular/core/testing';
import { Component, Type, input, signal } from '@angular/core';
import { Router } from '@angular/router';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';
import { ATTOME_CONFIG, LangService } from '@attome/base';
import { EntityService, RecordTabPanelsComponent, XrmBaseFormComponent } from '@attome/xrm/core/entity';
import type { XrmFormTabDef } from '@attome/xrm/core/entity';
import type { EntitySchema } from '@attome/xrm';
import { MetricCommentFormComponent } from './metric-comment-form/metric-comment-form.component';
import { MetricScorecardFormComponent } from './metric-scorecard-form/metric-scorecard-form.component';
import { MetricScorecardItemFormComponent } from './metric-scorecard-item-form/metric-scorecard-item-form.component';

@Component({ selector: 'xrm-record-tab-panels', standalone: true, template: '' })
class RecordTabPanelsStubComponent {
  readonly entityName = input.required<string>();
  readonly recordId   = input<string | null>(null);
  readonly tabs       = input.required<XrmFormTabDef[]>();
  readonly activeTab  = input.required<string>();
  readonly idPrefix   = input('entity');
}

function schema(entity: string, field: string): EntitySchema {
  return {
    id: 'e1', name: entity, logical_name: entity,
    fields: [
      { id: 'f1', entity_id: 'e1', name: field, display_name: field, field_type: 'text', options: null, sort_order: 0, is_required: false },
    ],
  } as unknown as EntitySchema;
}

const CASES: [string, Type<unknown>, string, string][] = [
  ['metric_scorecard', MetricScorecardFormComponent, 'name', 'Board'],
  ['metric_scorecard_item', MetricScorecardItemFormComponent, 'sort_order', '1'],
  ['metric_comment', MetricCommentFormComponent, 'body', 'Ahead of plan.'],
];

/** P9-T14: the metric governance forms (P9-T1) on the shared base form, in Arabic. */
describe('metric governance forms (P9-T14)', () => {
  for (const [entity, form, field, value] of CASES) {
    it(`${entity}: shows its details section with the Arabic title`, () => {
      TestBed.configureTestingModule({
        imports: [form],
        providers: [
          provideHttpClient(),
          provideHttpClientTesting(),
          { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
          {
            provide: EntityService,
            useValue: {
              getSchema: () => of(schema(entity, field)),
              get: () => of({ id: 'r1', row_version: 1, data: { [field]: value } }),
            },
          },
          {
            provide: Router,
            useValue: { navigate: vi.fn(), url: '/', parseUrl: () => ({ queryParamMap: { get: () => null } }) },
          },
          {
            provide: LangService,
            useValue: {
              translate: (key: string) => (key === 'xrmForm.tabs.details' ? 'التفاصيل' : key),
              current: signal('ar'),
              isRtl: () => true,
            },
          },
        ],
      });
      TestBed.overrideComponent(XrmBaseFormComponent, {
        remove: { imports: [RecordTabPanelsComponent] },
        add: { imports: [RecordTabPanelsStubComponent] },
      });
      const fixture = TestBed.createComponent(form);
      fixture.componentRef.setInput('name', entity);
      fixture.componentRef.setInput('id', 'r1');
      fixture.detectChanges();
      const el = fixture.nativeElement as HTMLElement;
      expect(el.querySelector('.xf-section-title')?.textContent?.trim()).toBe('التفاصيل');
    });
  }
});
