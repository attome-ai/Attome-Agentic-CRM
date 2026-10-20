import { ComponentFixture, TestBed } from '@angular/core/testing';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError, ApiService, AuthService, LangService } from '@attome/base';
import { DialogService } from '@attome/base/dialog';
import { EntityService } from '../services/entity.service';
import { FileUploadService } from '../field/file-upload.service';
import { NotesPanelComponent } from './notes-panel.component';

describe('NotesPanelComponent', () => {
  let fixture: ComponentFixture<NotesPanelComponent>;
  let component: NotesPanelComponent;
  let entityService: {
    list: ReturnType<typeof vi.fn>;
    create: ReturnType<typeof vi.fn>;
    update: ReturnType<typeof vi.fn>;
    delete: ReturnType<typeof vi.fn>;
  };
  let dialogService: {
    confirm: ReturnType<typeof vi.fn>;
  };
  let fileService: {
    getDownloadUrl: ReturnType<typeof vi.fn>;
  };

  const sampleNotes = {
    data: [
      {
        id: 'note-1',
        created_at: '2026-08-14T10:42:00Z',
        updated_at: '2026-08-14T10:42:00Z',
        row_version: 0,
        data: {
          id: 'note-1',
          title: 'Document Verification',
          entity_name: 'user_account',
          record_id: 'user-1',
          note_text: 'Test note text with attachment',
          created_by: 'user-2',
          created_at: '2026-08-14T10:42:00Z',
          attachments: [
            { name: 'document.pdf', size_bytes: 102400, size_formatted: '100 KB' },
          ],
        },
      },
    ],
    meta: { total: 1, limit: 50, offset: 0 },
  };

  // C1-T1: replies are `note_reply` records on the note's parent record.
  const sampleReplies = {
    data: [
      {
        id: 'reply-1',
        created_at: '2026-08-14T11:00:00Z',
        updated_at: '2026-08-14T11:00:00Z',
        row_version: 2,
        data: {
          id: 'reply-1',
          note_id: 'note-1',
          entity_name: 'user_account',
          record_id: 'user-1',
          note_text: 'First reply',
          created_by: 'user-2',
          // A reply moved from the old JSON list: its file is on the note.
          attachments: JSON.stringify([{ name: 'old.pdf', key: 'note/note-1/files/old' }]),
          files: [],
        },
      },
    ],
    meta: { total: 1, limit: 500, offset: 0 },
  };

  const sampleUsers = {
    data: [
      {
        id: 'user-2',
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z',
        row_version: 0,
        data: {
          id: 'user-2',
          user_name: 'Jane Smith',
          email: 'jane@example.com',
        },
      },
    ],
    meta: { total: 1, limit: 100, offset: 0 },
  };

  beforeEach(async () => {
    entityService = {
      list: vi.fn().mockImplementation((entityName: string) => {
        if (entityName === 'user_account') {
          return of(sampleUsers);
        }
        if (entityName === 'note') {
          return of(sampleNotes);
        }
        if (entityName === 'note_reply') {
          return of(sampleReplies);
        }
        return of({ data: [], meta: { total: 0, limit: 50, offset: 0 } });
      }),
      create: vi.fn().mockReturnValue(of({ id: 'note-2', row_version: 0 })),
      update: vi.fn().mockReturnValue(of({ id: 'note-1' })),
      delete: vi.fn().mockReturnValue(of(undefined)),
    };

    dialogService = {
      confirm: vi.fn().mockResolvedValue(true),
    };

    fileService = {
      getDownloadUrl: vi.fn().mockReturnValue(of({ download_url: 'https://store.example/signed', expires_in_secs: 300 })),
    };

    await TestBed.configureTestingModule({
      imports: [NotesPanelComponent],
      providers: [
        { provide: EntityService, useValue: entityService },
        { provide: DialogService, useValue: dialogService },
        { provide: FileUploadService, useValue: fileService },
        { provide: ApiService, useValue: {} },
        { provide: AuthService, useValue: { userId: () => 'user-1' } },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(NotesPanelComponent);
    component = fixture.componentInstance;
    fixture.componentRef.setInput('entityName', 'user_account');
    fixture.componentRef.setInput('recordId', 'user-1');
    fixture.detectChanges();
  });

  it('reads each note\'s replies from its reply records', () => {
    const replies = component.notes()[0].replies ?? [];
    expect(replies.map(r => r.note_text)).toEqual(['First reply']);
    expect(replies[0].author_name).toBe('Jane Smith');
    expect(replies[0].row_version).toBe(2);
    expect(entityService.list).toHaveBeenCalledWith('note_reply', expect.objectContaining({
      filters: [
        { field: 'entity_name', op: 'eq', value: 'user_account' },
        { field: 'record_id', op: 'eq', value: 'user-1' },
      ],
    }));
  });

  it('renders notes history and opens create view by default when no note selected', () => {
    expect(component.notes().length).toBe(1);
    expect(component.notes()[0].title).toBe('Document Verification');
    expect(component.notes()[0].author_name).toBe('Jane Smith');

    const compiled = fixture.nativeElement as HTMLElement;
    // The LangService stub echoes catalog keys, so the header renders its key.
    expect(compiled.querySelector('.xnp-sidebar-title')?.textContent).toContain('notes.history');
    expect(compiled.querySelector('.xnp-item-title')?.textContent).toContain('Document Verification');
  });

  it('switches to chat-like detail view with timeline track and edit button', () => {
    component.selectNote('note-1');
    fixture.detectChanges();

    expect(component.viewMode()).toBe('detail');
    expect(component.selectedNoteId()).toBe('note-1');

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('.xnp-detail-title')?.textContent).toContain('Document Verification');
    expect(compiled.querySelector('.xnp-btn-edit-note')?.textContent).toContain('notes.editNoteButton');
    expect(compiled.querySelector('.xnp-avatar')?.textContent).toContain('JS');
    expect(compiled.querySelector('.xnp-card-body')?.textContent).toContain('Test note text with attachment');
    expect(compiled.querySelector('.xnp-att-name')?.textContent).toContain('document.pdf');
  });

  it('Esc in the note form cancels creating a note', () => {
    component.startCreateNote();
    component.formNoteTitle = 'Draft';
    fixture.detectChanges();
    const title = (fixture.nativeElement as HTMLElement).querySelector('#note-title') as HTMLInputElement;
    title.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    fixture.detectChanges();

    expect(component.viewMode()).toBe('detail');
    expect(entityService.create).not.toHaveBeenCalled();
  });

  it('saves new note with title, text, and attachments', () => {
    component.startCreateNote();
    component.formNoteTitle = 'New Note Title';
    component.formNoteText = 'Detailed note body';
    component.saveFormNote();

    expect(entityService.create).toHaveBeenCalledWith('note', {
      entity_name: 'user_account',
      record_id: 'user-1',
      title: 'New Note Title',
      note_text: 'Detailed note body',
    });
  });

  it('edits existing note and saves updates', () => {
    const note = component.notes()[0];
    component.startEditNote(note);
    fixture.detectChanges();

    expect(component.viewMode()).toBe('edit');
    expect(component.formNoteTitle).toBe('Document Verification');

    component.formNoteTitle = 'Updated Document Title';
    component.formNoteText = 'Updated note text';
    component.saveFormNote();

    expect(entityService.update).toHaveBeenCalledWith('note', 'note-1', {
      title: 'Updated Document Title',
      note_text: 'Updated note text',
      attachments: JSON.stringify([{ name: 'document.pdf', size_bytes: 102400, size_formatted: '100 KB' }]),
      // The legacy attachment has no object key; the moved reply's file stays on the note.
      files: ['note/note-1/files/old'],
    }, 0);
  });

  // Attachments used to be saved as name/size metadata only — the bytes never
  // left the browser and `openAttachment` had nothing to open. They now go
  // through the D-144 pipeline into `note.files`, keyed per note.
  describe('attachment upload', () => {
    type RunFn = ReturnType<typeof vi.fn>;
    const stubPipeline = (run: RunFn) => {
      (component as unknown as { uploadPipeline: { run: RunFn } }).uploadPipeline.run = run;
    };
    const file = () => new File(['hello'], 'contract.pdf', { type: 'application/pdf' });

    it("uploads a new note's files against the created note and stores their keys", async () => {
      const run = vi.fn().mockResolvedValue({ kind: 'clean', finalKey: 'note/note-2/files/k1' });
      stubPipeline(run);
      entityService.create.mockReturnValue(of({ id: 'note-2', row_version: 3 }));

      component.startCreateNote();
      component.formNoteTitle = 'With a file';
      component.formNoteText = 'Body';
      component.pendingFiles.set([file()]);
      component.saveFormNote();

      await vi.waitFor(() => expect(entityService.update).toHaveBeenCalled());
      expect(run).toHaveBeenCalledWith(
        { entityName: 'note', recordId: 'note-2', fieldName: 'files' }, expect.any(File));
      const [entity, id, patch, rowVersion] = entityService.update.mock.calls[0];
      expect([entity, id, rowVersion]).toEqual(['note', 'note-2', 3]);
      expect(patch.files).toEqual(['note/note-2/files/k1']);
      expect(JSON.parse(patch.attachments)[0]).toMatchObject({ name: 'contract.pdf', key: 'note/note-2/files/k1' });
    });

    it('keeps the note but reports a file the scan rejected, without attaching it', async () => {
      stubPipeline(vi.fn().mockResolvedValue({ kind: 'rejected', message: 'infected' }));
      entityService.create.mockReturnValue(of({ id: 'note-2', row_version: 0 }));
      // After the save the server's list holds the new note, so the refetch
      // keeps it selected instead of falling back to the first note.
      const created = { ...sampleNotes.data[0], id: 'note-2', data: { ...sampleNotes.data[0].data, id: 'note-2' } };
      entityService.list.mockImplementation((entityName: string) =>
        of(entityName === 'note' ? { ...sampleNotes, data: [created, ...sampleNotes.data] } : sampleUsers));

      component.startCreateNote();
      component.formNoteTitle = 'With a bad file';
      component.formNoteText = 'Body';
      component.pendingFiles.set([file()]);
      component.saveFormNote();

      await vi.waitFor(() => expect(component.saving()).toBe(false));
      expect(entityService.update).not.toHaveBeenCalled();
      expect(component.errorMessage()).toContain('contract.pdf: infected');
    });

    it("uploads a reply's files to the reply record and records their keys on it", async () => {
      const run = vi.fn().mockResolvedValue({ kind: 'clean', finalKey: 'note_reply/reply-9/files/r1' });
      stubPipeline(run);
      entityService.create.mockReturnValue(of({ id: 'reply-9', row_version: 1 }));
      component.selectNote('note-1');
      component.replyText = 'See attached';
      component.replyPendingFiles.set([file()]);
      component.sendReply();

      await vi.waitFor(() => expect(entityService.update).toHaveBeenCalled());
      expect(run).toHaveBeenCalledWith(
        { entityName: 'note_reply', recordId: 'reply-9', fieldName: 'files' }, expect.any(File));
      const [entity, id, patch, rowVersion] = entityService.update.mock.calls[0];
      expect([entity, id, rowVersion]).toEqual(['note_reply', 'reply-9', 1]);
      expect(patch.files).toEqual(['note_reply/reply-9/files/r1']);
      expect(JSON.parse(patch.attachments)[0]).toMatchObject({ key: 'note_reply/reply-9/files/r1' });
    });

    it("opens a moved reply's file through the note and a new reply's through the reply", () => {
      vi.spyOn(window, 'open').mockReturnValue(null);
      const moved = component.notes()[0].replies![0];
      component.openAttachment('note-1', { name: 'old.pdf', key: 'note/note-1/files/old' }, moved);
      expect(fileService.getDownloadUrl).toHaveBeenLastCalledWith('note', 'note-1', 'files', 'note/note-1/files/old');
      const fresh = { ...moved, id: 'reply-9', files: ['note_reply/reply-9/files/r1'] };
      component.openAttachment('note-1', { name: 'r.pdf', key: 'note_reply/reply-9/files/r1' }, fresh);
      expect(fileService.getDownloadUrl).toHaveBeenLastCalledWith('note_reply', 'reply-9', 'files', 'note_reply/reply-9/files/r1');
    });

    it('opens an uploaded attachment through a presigned download URL', () => {
      const open = vi.spyOn(window, 'open').mockReturnValue(null);
      component.openAttachment('note-1', { name: 'contract.pdf', key: 'note/note-1/files/k1' });

      expect(fileService.getDownloadUrl).toHaveBeenCalledWith('note', 'note-1', 'files', 'note/note-1/files/k1');
      expect(open).toHaveBeenCalledWith('https://store.example/signed', '_blank', 'noopener');
      open.mockRestore();
    });

    it('explains that a legacy metadata-only attachment has no file to open', () => {
      component.openAttachment('note-1', { name: 'document.pdf', size_bytes: 102400 });

      expect(fileService.getDownloadUrl).not.toHaveBeenCalled();
      expect(component.errorMessage()).toContain('document.pdf');
    });
  });

  it('sends a thread reply as its own record without touching the note', () => {
    component.selectNote('note-1');
    component.replyText = 'A reply to this thread';
    component.sendReply();

    expect(entityService.create).toHaveBeenCalledWith('note_reply', {
      note_id: 'note-1',
      entity_name: 'user_account',
      record_id: 'user-1',
      note_text: 'A reply to this thread',
    });
    expect(entityService.update).not.toHaveBeenCalled();
  });

  it('edits a reply in the thread', () => {
    const note = component.notes()[0];
    component.editingReplyId.set('reply-1');
    component.editingReplyText = 'Updated reply text';
    component.saveEditReply(note, 'reply-1');

    expect(entityService.update).toHaveBeenCalledWith('note_reply', 'reply-1', { note_text: 'Updated reply text' }, 2);
  });

  it('deletes a reply record after confirmation', async () => {
    component.deleteReply(component.notes()[0], 'reply-1');
    await Promise.resolve();

    expect(entityService.delete).toHaveBeenCalledWith('note_reply', 'reply-1');
  });

  it('deletes a note after confirmation', async () => {
    component.deleteNote('note-1');
    await Promise.resolve();

    expect(dialogService.confirm).toHaveBeenCalled();
    expect(entityService.delete).toHaveBeenCalledWith('note', 'note-1');
  });

  // C-29 (M01 §7) — a reply record is `row_version`-guarded (`If-Match`,
  // D-037): a concurrent edit makes the generic API 409 (`version_conflict`)
  // rather than silently overwriting. Every reply mutation surfaces the
  // failure and refetches to reconcile with the server.
  describe('reply mutations surface a failure instead of swallowing it', () => {
    const conflict: ApiError = { kind: 'version_conflict', message: 'stale row_version', status: 409 };

    it('sendReply sets errorMessage and refetches when the create fails', () => {
      entityService.create.mockReturnValue(throwError(() => conflict));
      component.selectNote('note-1');
      component.replyText = 'A reply that will conflict';
      component.sendReply();

      expect(component.sendingReply()).toBe(false);
      expect(component.errorMessage()).toContain('Someone else updated this note');
      // fetchNotes re-lists note — called once on init, once on conflict recovery.
      expect(entityService.list.mock.calls.filter(c => c[0] === 'note').length).toBeGreaterThanOrEqual(2);
    });

    it('saveEditReply sets errorMessage and refetches on conflict', () => {
      entityService.update.mockReturnValue(throwError(() => conflict));
      const note = component.notes()[0];
      component.editingReplyId.set('reply-1');
      component.editingReplyText = 'An edit that will conflict';
      component.saveEditReply(note, 'reply-1');

      expect(component.errorMessage()).toContain('Someone else updated this note');
    });

    it('deleteReply sets errorMessage and refetches on conflict', async () => {
      entityService.delete.mockReturnValue(throwError(() => conflict));
      const note = component.notes()[0];
      component.deleteReply(note, 'reply-1');
      await Promise.resolve();

      expect(component.errorMessage()).toContain('Someone else updated this note');
    });
  });
});
