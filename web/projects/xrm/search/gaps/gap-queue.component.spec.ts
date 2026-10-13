import { ComponentFixture, TestBed } from '@angular/core/testing';
import { EntityService } from '@attome/xrm/core/entity';
import { of } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { GapQueueComponent } from './gap-queue.component';
import { GapTopic, KnowledgeService } from '../services/knowledge.service';

/**
 * Regression coverage for the "Addressed" bug found in review: the button
 * used to triage a gap `addressed` with no `addressed_item_ref` at all,
 * because nothing in the UI ever offered an article to link. These specs pin
 * the picker flow that replaced it — opening it must not triage anything,
 * and confirming it must pass the selected item's id through. Driven through
 * the template rather than the (deliberately `protected`) component methods,
 * same as the rest of this button-driven admin screen.
 */
describe('GapQueueComponent — the Addressed picker', () => {
  let fixture: ComponentFixture<GapQueueComponent>;
  let compiled: HTMLElement;
  let knowledge: { listGaps: ReturnType<typeof vi.fn>; triageGap: ReturnType<typeof vi.fn> };
  let entities: { list: ReturnType<typeof vi.fn> };

  const topic: GapTopic = {
    id: 'gap-1',
    normalized_phrase: 'refund policy',
    first_seen_at: '2026-09-01T00:00:00Z',
    last_seen_at: '2026-09-10T00:00:00Z',
    hit_count: 3,
    status: 'open',
    addressed_page_ref: null,
    addressed_item_ref: null,
  };

  const kbItem = {
    id: 'kb-item-1',
    entity_id: '',
    data: { title: 'Refunds and returns' },
    created_at: '2026-08-01T00:00:00Z',
    updated_at: '2026-08-01T00:00:00Z',
    row_version: 0,
  };

  const addressedButton = () =>
    Array.from(compiled.querySelectorAll<HTMLButtonElement>('.gap-actions button'))
      .find((b) => b.textContent?.includes('Addressed'));

  const pickerItemButton = () => compiled.querySelector<HTMLButtonElement>('.gap-picker-item');

  const confirmButton = () =>
    Array.from(compiled.querySelectorAll<HTMLButtonElement>('.gap-picker-actions button'))
      .find((b) => b.textContent?.includes('Mark addressed'));

  const cancelButton = () =>
    Array.from(compiled.querySelectorAll<HTMLButtonElement>('.gap-picker-actions button'))
      .find((b) => b.textContent?.includes('Cancel'));

  beforeEach(async () => {
    vi.useFakeTimers();

    knowledge = {
      listGaps: vi.fn().mockReturnValue(of({ items: [topic], total: 1, page: 1, page_size: 100 })),
      triageGap: vi.fn().mockReturnValue(of({ ...topic, status: 'addressed' })),
    };
    entities = {
      list: vi.fn().mockReturnValue(of({ data: [kbItem], meta: { total: 1, limit: 20, offset: 0 } })),
    };

    await TestBed.configureTestingModule({
      imports: [GapQueueComponent],
      providers: [
        { provide: KnowledgeService, useValue: knowledge },
        { provide: EntityService, useValue: entities },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(GapQueueComponent);
    compiled = fixture.nativeElement as HTMLElement;
    fixture.detectChanges();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('opens the picker without triaging anything', () => {
    addressedButton()?.click();
    fixture.detectChanges();

    expect(knowledge.triageGap).not.toHaveBeenCalled();
    expect(compiled.querySelector('.gap-picker')).toBeTruthy();
  });

  it('searches the published Knowledge Base entity, not an arbitrary one', () => {
    addressedButton()?.click();
    fixture.detectChanges();
    vi.advanceTimersByTime(200);
    fixture.detectChanges();

    expect(entities.list).toHaveBeenCalledWith(
      'knowledge_data_item',
      expect.objectContaining({
        filters: expect.arrayContaining([{ field: 'lifecycle', op: 'eq', value: 'published' }]),
      }),
    );
    expect(pickerItemButton()?.textContent).toContain('Refunds and returns');
  });

  it('passes the selected item id through to triageGap on confirm', () => {
    addressedButton()?.click();
    fixture.detectChanges();
    vi.advanceTimersByTime(200);
    fixture.detectChanges();

    pickerItemButton()?.click();
    fixture.detectChanges();
    confirmButton()?.click();
    fixture.detectChanges();

    expect(knowledge.triageGap).toHaveBeenCalledWith('gap-1', 'addressed', 'kb-item-1');
    expect(compiled.querySelector('.gap-picker')).toBeFalsy();
  });

  it('disables confirm until an item is selected', () => {
    addressedButton()?.click();
    fixture.detectChanges();
    vi.advanceTimersByTime(200);
    fixture.detectChanges();

    expect(confirmButton()?.disabled).toBe(true);

    pickerItemButton()?.click();
    fixture.detectChanges();

    expect(confirmButton()?.disabled).toBe(false);
  });

  it('cancelling never calls triageGap', () => {
    addressedButton()?.click();
    fixture.detectChanges();
    vi.advanceTimersByTime(200);
    fixture.detectChanges();

    cancelButton()?.click();
    fixture.detectChanges();

    expect(knowledge.triageGap).not.toHaveBeenCalled();
    expect(compiled.querySelector('.gap-picker')).toBeFalsy();
  });

  it('dismiss/reopen still triage directly with no item reference', () => {
    const dismissButton = Array.from(compiled.querySelectorAll<HTMLButtonElement>('.gap-actions button'))
      .find((b) => b.textContent?.includes('Dismiss'));
    dismissButton?.click();

    expect(knowledge.triageGap).toHaveBeenCalledWith('gap-1', 'dismissed', null);
  });
});
