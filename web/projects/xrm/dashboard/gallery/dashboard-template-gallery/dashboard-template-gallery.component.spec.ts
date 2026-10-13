import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { EntityRecord } from '@attome/xrm';
import { EntityService } from '@attome/xrm/core/entity';
import { DashboardService } from '@attome/xrm/dashboard/data';
import { DashboardTemplateGalleryComponent } from './dashboard-template-gallery.component';

function mockTemplate(id: string, name: string): EntityRecord {
  return {
    id,
    entity_id:  'attome_dashboard',
    data:       { name, is_template: true },
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    row_version: 0,
  };
}

function setup(templates: EntityRecord[] = []): {
  fixture: ComponentFixture<DashboardTemplateGalleryComponent>;
  listSpy: ReturnType<typeof vi.fn>;
  cloneSpy: ReturnType<typeof vi.fn>;
  navigateSpy: ReturnType<typeof vi.fn>;
} {
  const listSpy = vi.fn(() =>
    of({ data: templates, meta: { total: templates.length, limit: 50, offset: 0 } }));
  const cloneSpy = vi.fn(() => of({ id: 'clone-1' }));
  // A mocked `Router`, not `provideRouter([])` — `useAsTemplate` navigates on
  // success, and an empty real route config throws `NG04002` (no route
  // matches `/xrm/dashboard/form`) rather than something this spec cares
  // about proving.
  const navigateSpy = vi.fn();

  TestBed.configureTestingModule({
    imports: [DashboardTemplateGalleryComponent],
    providers: [
      { provide: Router, useValue: { navigate: navigateSpy } },
      { provide: EntityService, useValue: { list: listSpy } },
      { provide: DashboardService, useValue: { clone: cloneSpy } },
      { provide: LangService, useValue: { translate: (key: string) => key } },
    ],
  });

  const fixture = TestBed.createComponent(DashboardTemplateGalleryComponent);
  fixture.detectChanges();
  return { fixture, listSpy, cloneSpy, navigateSpy };
}

// R-10 (M26-dashboard-remediation) — this component moved from
// `@attome/xrm/report` to `@attome/xrm/dashboard`; this is its first spec.
describe('DashboardTemplateGalleryComponent', () => {
  it('lists attome_dashboard rows filtered to is_template = true only', () => {
    const { listSpy } = setup();

    expect(listSpy).toHaveBeenCalledWith('attome_dashboard', {
      filters: [{ field: 'is_template', op: 'eq', value: 'true' }],
    });
  });

  it('exposes the fetched templates and clears loading', () => {
    const templates = [mockTemplate('t1', 'Sales Overview'), mockTemplate('t2', 'Support Health')];
    const { fixture } = setup(templates);

    expect(fixture.componentInstance.templates()).toEqual(templates);
    expect(fixture.componentInstance.loading()).toBe(false);
  });

  it('useAsTemplate clones through DashboardService, not a raw API call', () => {
    const { fixture, cloneSpy } = setup([mockTemplate('t1', 'Sales Overview')]);

    fixture.componentInstance.useAsTemplate('t1');

    expect(cloneSpy).toHaveBeenCalledWith('t1');
    expect(fixture.componentInstance.cloning()).toBeNull();
  });
});
