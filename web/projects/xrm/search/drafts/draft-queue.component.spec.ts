import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { EntityService } from '@attome/xrm/core/entity';
import { DraftQueueComponent } from './draft-queue.component';

/**
 * The draft queue adds no write path of its own: it lists drafts through the
 * generic entity list, publishes with an ordinary PATCH under the record's
 * current row_version, and rejects with the entity soft delete, only after a
 * second confirmation.
 */
describe('DraftQueueComponent', () => {
  let fixture: ComponentFixture<DraftQueueComponent>;
  let entities: {
    list: ReturnType<typeof vi.fn>;
    get: ReturnType<typeof vi.fn>;
    update: ReturnType<typeof vi.fn>;
    delete: ReturnType<typeof vi.fn>;
  };

  const draft = {
    id: 'item-1',
    entity_id: '',
    data: { title: 'Refund policy', lifecycle: 'draft' },
    lookups: { data_source_ref: { exists: true, is_active: true, name: 'Policies' } },
    created_at: '2026-09-20T00:00:00Z',
    updated_at: '2026-09-21T00:00:00Z',
    row_version: 0,
  };

  const button = (cls: string) =>
    (fixture.nativeElement as HTMLElement).querySelector<HTMLButtonElement>(`.gap-actions ${cls}`);
  const buttons = () =>
    Array.from((fixture.nativeElement as HTMLElement).querySelectorAll<HTMLButtonElement>('.gap-actions button'));

  beforeEach(async () => {
    entities = {
      list: vi.fn().mockReturnValue(of({ data: [draft], meta: { total: 1, limit: 100, offset: 0 } })),
      get: vi.fn().mockReturnValue(of({ ...draft, row_version: 7 })),
      update: vi.fn().mockReturnValue(of({ ...draft, row_version: 8 })),
      delete: vi.fn().mockReturnValue(of(undefined)),
    };
    await TestBed.configureTestingModule({
      imports: [DraftQueueComponent],
      providers: [
        provideRouter([]),
        { provide: EntityService, useValue: entities },
        { provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' } },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(DraftQueueComponent);
    fixture.detectChanges();
  });

  it('lists only draft knowledge items, with their collection', () => {
    expect(entities.list).toHaveBeenCalledWith(
      'knowledge_data_item',
      expect.objectContaining({ filters: [{ field: 'lifecycle', op: 'eq', value: 'draft' }] }),
    );
    const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
    expect(text).toContain('Refund policy');
    expect(text).toContain('Policies');
  });

  it('publishes through the entity PATCH under the current row_version', () => {
    button('.kd-publish')!.click();
    fixture.detectChanges();
    expect(entities.get).toHaveBeenCalledWith('knowledge_data_item', 'item-1');
    expect(entities.update).toHaveBeenCalledWith(
      'knowledge_data_item',
      'item-1',
      { lifecycle: 'published' },
      7,
    );
    expect(entities.delete).not.toHaveBeenCalled();
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('knowledgeDrafts.published');
  });

  it('rejects only after a second confirmation, through the entity soft delete', () => {
    button('.kd-reject')!.click();
    fixture.detectChanges();
    expect(entities.delete).not.toHaveBeenCalled();

    const confirm = buttons().find((b) => b.textContent?.includes('knowledgeDrafts.confirmReject'));
    confirm!.click();
    fixture.detectChanges();
    expect(entities.delete).toHaveBeenCalledWith('knowledge_data_item', 'item-1');
    expect(entities.update).not.toHaveBeenCalled();
  });

  it('cancelling a reject deletes nothing', () => {
    button('.kd-reject')!.click();
    fixture.detectChanges();
    buttons().find((b) => b.textContent?.includes('knowledgeDrafts.cancel'))!.click();
    fixture.detectChanges();
    expect(entities.delete).not.toHaveBeenCalled();
    expect(button('.kd-publish')).not.toBeNull();
  });
});
