import { ChangeDetectionStrategy, Component, input, signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { DefaultUrlSerializer, Router } from '@angular/router';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ATTOME_CONFIG, CurrencyService, LangService } from '@attome/base';
import { DialogService } from '@attome/base/dialog';
import { AvailableView, QueryService, ViewAdminService } from '@attome/xrm/core/query/data';
import { EntityRouteRegistry } from '../entity-route-registry.service';
import { EntityService } from '../services/entity.service';
import { BulkJobRunner } from './bulk-job-runner.service';
import { EntityListComponent, richTextToPlainText } from './entity-list.component';

/** A registered cell renderer: echoes a hidden helper column of its row. */
@Component({
  selector: 'xrm-test-due-cell',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: '<span class="due-cell">{{ row()?.["due_at"] }}|{{ row()?.["helper"] }}</span>',
})
class DueCellComponent {
  readonly row = input<Record<string, unknown> | null>(null);
}

const VIEW: AvailableView = {
  id: 'v1', name: 'All', icon: '', is_default: true, kind: 'list', view_metadata: {},
  scope: 'system', is_mine: false,
};

function column(name: string, visible = true) {
  return {
    name, display_name: name, data_type: 'text', is_visible: visible, is_sortable: true,
    is_searchable: false, is_clickable: false, route_template: '',
  };
}

describe('EntityListComponent — registered cell renderers', () => {
  const serializer = new DefaultUrlSerializer();
  let registry: EntityRouteRegistry;

  beforeEach(() => {
    const execute = vi.fn(() => of({
      metadata: {
        query_id: 'q1', view_id: 'v1', record_no: null, entity_logical_name: null, can_edit_query: false,
        view_kind: 'list', view_metadata: null,
      },
      data: {
        columns: [column('title'), column('due_at'), column('helper', false)],
        records: [{ id: 'r1', title: 'First', due_at: '2026-09-24', helper: 'hidden-value' }],
        total: 1, page: 1, page_size: 50,
      },
    }));
    TestBed.configureTestingModule({
      imports: [EntityListComponent],
      providers: [
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
        { provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US', isRtl: () => false } },
        { provide: QueryService, useValue: { execute } },
        { provide: ViewAdminService, useValue: { listAvailable: vi.fn(() => of([VIEW])) } },
        { provide: EntityService, useValue: {} },
        { provide: DialogService, useValue: {} },
        { provide: BulkJobRunner, useValue: {} },
        { provide: CurrencyService, useValue: { preferredCurrency: signal('USD'), getPreferredCurrency: () => 'USD' } },
        {
          provide: Router,
          useValue: {
            navigate: vi.fn(), navigateByUrl: vi.fn(), url: '/xrm/ticket/list',
            parseUrl: (value: string) => serializer.parse(value),
          },
        },
      ],
    });
    registry = TestBed.inject(EntityRouteRegistry);
  });

  function render() {
    const fixture = TestBed.createComponent(EntityListComponent);
    fixture.componentRef.setInput('entityName', 'ticket');
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  it('draws the registered column through its renderer, with the whole row', () => {
    registry.register('ticket', { cellRenderers: { due_at: DueCellComponent } });

    const el = render();

    const cell = el.querySelector('.due-cell');
    expect(cell?.textContent).toBe('2026-09-24|hidden-value');
    // Other columns keep the stock cell, and the hidden column stays hidden.
    expect(el.textContent).toContain('First');
    expect(el.querySelectorAll('thead th.column-header').length).toBe(2);
  });

  it('keeps the stock cell when no renderer is registered', () => {
    const el = render();

    expect(el.querySelector('.due-cell')).toBeNull();
    expect(el.textContent).toContain('24-09-2026');
  });
});

// U9 (D-605) — a rich-text cell shows visible text only.
describe('richTextToPlainText', () => {
  it('drops markup, keeps text, never runs script', () => {
    (globalThis as { pwned?: boolean }).pwned = false;
    expect(richTextToPlainText('<p>Fish &amp; <b>chips</b></p><p>two</p><img src=x onerror="globalThis.pwned=true">'))
      .toBe('Fish & chips two');
    expect((globalThis as { pwned?: boolean }).pwned).toBe(false);
    expect(richTextToPlainText('')).toBe('');
  });
});
