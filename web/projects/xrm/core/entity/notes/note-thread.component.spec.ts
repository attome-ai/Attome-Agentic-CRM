import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { AuthService, LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { EntityService } from '../services/entity.service';
import { NoteThreadComponent, ThreadItem, parseReactions, toggleReaction } from './note-thread.component';

describe('note thread helpers (C1-T2)', () => {
  it('reads stored reactions and ignores anything else', () => {
    expect(parseReactions('{"👍":["u1","u2"],"x":"bad"}')).toEqual({ '👍': ['u1', 'u2'] });
    expect(parseReactions('not json')).toEqual({});
    expect(parseReactions(null)).toEqual({});
  });

  it('toggles one user\'s reaction', () => {
    const once = toggleReaction({}, '👍', 'u1');
    expect(once).toEqual({ '👍': ['u1'] });
    expect(toggleReaction(once, '👍', 'u2')).toEqual({ '👍': ['u1', 'u2'] });
    expect(toggleReaction(once, '👍', 'u1')).toEqual({});
  });
});

describe('NoteThreadComponent (C1-T2)', () => {
  const entities = { update: vi.fn(), get: vi.fn(), fieldHistory: vi.fn() };
  const note: ThreadItem = { entity: 'note', id: 'n1', reactions: '{"👍":["u2"]}', rowVersion: 4, isResolved: false };

  beforeEach(() => {
    vi.resetAllMocks();
    TestBed.configureTestingModule({
      imports: [NoteThreadComponent],
      providers: [
        { provide: EntityService, useValue: entities },
        { provide: AuthService, useValue: { userId: signal('u1') } },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: () => 'en-GB', errorText: () => 'failed' },
        },
      ],
    });
  });

  function render(item: ThreadItem = note, resolvable = true) {
    const fixture = TestBed.createComponent(NoteThreadComponent);
    fixture.componentRef.setInput('item', item);
    fixture.componentRef.setInput('resolvable', resolvable);
    fixture.detectChanges();
    return fixture;
  }

  it('adds the user\'s reaction at the item\'s row version', () => {
    entities.update.mockReturnValue(of({ id: 'n1', row_version: 5, data: { reactions: '{"👍":["u2","u1"]}' } }));
    const fixture = render();
    const thumbs = fixture.nativeElement.querySelector('[data-testid="nt-reaction"]') as HTMLButtonElement;
    expect(thumbs.textContent).toContain('1');
    thumbs.click();
    fixture.detectChanges();
    expect(entities.update).toHaveBeenCalledWith('note', 'n1', { reactions: '{"👍":["u2","u1"]}' }, 4);
    expect(thumbs.textContent).toContain('2');
    expect(fixture.componentInstance.rowVersion()).toBe(5);
  });

  it('reloads and tries once more when someone else changed the note', () => {
    entities.update
      .mockReturnValueOnce(throwError(() => ({ kind: 'conflict', status: 409, message: '' })))
      .mockReturnValueOnce(of({ id: 'n1', row_version: 7, data: { reactions: '{"👍":["u2","u3","u1"]}' } }));
    entities.get.mockReturnValue(of({ id: 'n1', row_version: 6, data: { reactions: '{"👍":["u2","u3"]}' } }));
    const fixture = render();
    (fixture.nativeElement.querySelector('[data-testid="nt-reaction"]') as HTMLButtonElement).click();
    expect(entities.update).toHaveBeenLastCalledWith('note', 'n1', { reactions: '{"👍":["u2","u3","u1"]}' }, 6);
    expect(fixture.componentInstance.reactions()).toEqual({ '👍': ['u2', 'u3', 'u1'] });
  });

  it('resolves the thread', () => {
    entities.update.mockReturnValue(of({ id: 'n1', row_version: 5, data: { is_resolved: true } }));
    const fixture = render();
    (fixture.nativeElement.querySelector('[data-testid="nt-resolve"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(entities.update).toHaveBeenCalledWith('note', 'n1', expect.objectContaining({ is_resolved: true, resolved_by: 'u1' }), 4);
    expect(fixture.nativeElement.querySelector('[data-testid="nt-resolved"]')).not.toBeNull();
  });

  it('shows earlier texts from the field history; a reply cannot be resolved', () => {
    entities.fieldHistory.mockReturnValue(of({
      items: [{ changed_on: '2026-10-20T10:00:00Z', actor: 'u2', fields: [{ field_name: 'note_text', masked: false, old_value: 'first draft' }] }],
    }));
    const fixture = render({ entity: 'note_reply', id: 'r1', rowVersion: 1 }, false);
    expect(fixture.nativeElement.querySelector('[data-testid="nt-resolve"]')).toBeNull();
    (fixture.nativeElement.querySelector('[data-testid="nt-history"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(entities.fieldHistory).toHaveBeenCalledWith('note_reply', 'r1', 'note_text');
    expect(fixture.nativeElement.querySelector('[data-testid="nt-history-list"]').textContent).toContain('first draft');
  });
});
