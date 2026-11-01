import { ComponentFixture, TestBed } from '@angular/core/testing';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { ConfirmService } from '@attome/base/dialog';
import { MetadataVersionsComponent, MetadataVersionsService } from './metadata-versions.component';

const VERSIONS = {
  items: [
    { version: 3, published_at: '2026-10-21T08:00:00Z', published_by: null, current: true, nodes: 2 },
    { version: 2, published_at: '2026-10-20T08:00:00Z', published_by: null, current: false, nodes: 2 },
  ],
  total: 2, page: 1, page_size: 20,
};

describe('MetadataVersionsComponent', () => {
  let fixture: ComponentFixture<MetadataVersionsComponent>;
  let svc: {
    list: ReturnType<typeof vi.fn>;
    nodes: ReturnType<typeof vi.fn>;
    rollback: ReturnType<typeof vi.fn>;
    preview: ReturnType<typeof vi.fn>;
    switchTo: ReturnType<typeof vi.fn>;
  };
  let confirm: { confirm: ReturnType<typeof vi.fn> };

  async function render() {
    await TestBed.configureTestingModule({
      imports: [MetadataVersionsComponent],
      providers: [
        { provide: MetadataVersionsService, useValue: svc },
        { provide: ConfirmService, useValue: confirm },
        {
          provide: LangService,
          useValue: {
            translate: (key: string) => key,
            errorText: () => 'errors.unknown',
            intlLocale: () => 'en-US',
          },
        },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(MetadataVersionsComponent);
    fixture.detectChanges();
  }

  const el = () => fixture.nativeElement as HTMLElement;

  beforeEach(() => {
    TestBed.resetTestingModule();
    svc = {
      list: vi.fn().mockReturnValue(of(VERSIONS)),
      nodes: vi.fn().mockReturnValue(of({
        items: [{ node_id: 'node-a:7865', switched_at: '2026-10-21T08:00:02Z' }],
        total: 1, page: 1, page_size: 100,
      })),
      rollback: vi.fn().mockReturnValue(of({ from: 3, to: 2 })),
      preview: vi.fn().mockReturnValue(of({
        from: 3, to: 2, added: ['page:old'], removed: [], changed: ['form:deal'],
      })),
      switchTo: vi.fn().mockReturnValue(of({ from: 3, to: 2 })),
    };
    confirm = { confirm: vi.fn().mockResolvedValue(true) };
  });

  it('lists the versions with the current one marked', async () => {
    await render();
    expect(el().querySelectorAll('tbody tr').length).toBe(2);
    expect(el().querySelectorAll('[data-testid="current"]').length).toBe(1);
  });

  it('shows the nodes of a version', async () => {
    await render();
    fixture.componentInstance.toggle(3);
    fixture.detectChanges();
    expect(svc.nodes).toHaveBeenCalledWith(3);
    expect(el().textContent).toContain('node-a:7865');
  });

  it('previews what a switch to an earlier version would change', async () => {
    await render();
    fixture.componentInstance.toggle(2);
    fixture.detectChanges();
    expect(svc.preview).toHaveBeenCalledWith(2);
    expect(el().querySelector('[data-testid="preview"]')?.textContent).toContain('form:deal');
  });

  it('offers no switch on the current version', async () => {
    await render();
    fixture.componentInstance.toggle(3);
    fixture.detectChanges();
    expect(el().querySelector('[data-testid="switch"]')).toBeNull();
  });

  it('switches only once confirmed', async () => {
    await render();
    confirm.confirm.mockResolvedValue(false);
    await fixture.componentInstance.switchTo(2);
    expect(svc.switchTo).not.toHaveBeenCalled();
    confirm.confirm.mockResolvedValue(true);
    await fixture.componentInstance.switchTo(2);
    expect(svc.switchTo).toHaveBeenCalledWith(2);
  });

  it('rollback asks for confirmation', async () => {
    await render();
    await fixture.componentInstance.rollback();
    expect(confirm.confirm).toHaveBeenCalledTimes(1);
    expect(svc.rollback).toHaveBeenCalledTimes(1);
    fixture.detectChanges();
    expect(el().querySelector('[data-testid="rolled-back"]')).not.toBeNull();
  });

  it('does not roll back when the confirmation is cancelled', async () => {
    confirm.confirm.mockResolvedValue(false);
    await render();
    await fixture.componentInstance.rollback();
    expect(svc.rollback).not.toHaveBeenCalled();
  });

  it('cannot roll back with a single version', async () => {
    svc.list.mockReturnValue(of({ ...VERSIONS, items: [VERSIONS.items[0]], total: 1 }));
    await render();
    expect(fixture.componentInstance.canRollBack()).toBe(false);
    await fixture.componentInstance.rollback();
    expect(confirm.confirm).not.toHaveBeenCalled();
  });
});
