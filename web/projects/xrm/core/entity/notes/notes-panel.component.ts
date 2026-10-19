import {
  ChangeDetectionStrategy, ChangeDetectorRef, Component, DestroyRef,
  ElementRef, Injector, OnInit, computed, effect, inject, input, signal, untracked, viewChild,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Observable, catchError, forkJoin, map, of } from 'rxjs';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  ApiError, ApiService, AuthService, MentionCandidate, MentionPickerComponent, MentionSearch, TranslatePipe,
} from '@attome/base';
import { DialogService } from '@attome/base/dialog';
import { EntityService } from '../services/entity.service';
import { FileUploadService } from '../field/file-upload.service';
import { UploadPipeline } from '../field/upload-pipeline';
import { TranslateTextComponent } from '../translate/translate-text.component';

/**
 * `note`'s multi-`file` field (`platform-bundles/attome-api-note.json`).
 * Attachment bytes — the note's own and its replies' — go through the D-144
 * upload pipeline into this field; `attachments`/`replies` keep only display
 * metadata plus the resulting object `key`, which is what `openAttachment`
 * exchanges for a presigned download URL. The server only presigns a key the
 * record's `files` array actually holds, so every save rewrites `files` from
 * the keys the note and its replies still reference.
 */
const NOTE_FILES_FIELD = 'files';

export interface NoteAttachment {
  name: string;
  size_bytes?: number;
  size_formatted?: string;
  content_type?: string;
  url?: string;
  key?: string;
}

export interface NoteReply {
  id: string;
  author_id?: string | null;
  author_name: string;
  author_initials: string;
  note_text: string;
  created_at: string;
  attachments?: NoteAttachment[];
}

export interface NoteItem {
  id: string;
  title: string;
  note_text: string;
  entity_name: string;
  record_id: string;
  created_at: string;
  created_by: string | null;
  modified_at?: string | null;
  author_name?: string;
  author_initials?: string;
  author_action?: string;
  attachments?: NoteAttachment[];
  replies?: NoteReply[];
  row_version?: number;
}

const EXTENSION_ICONS: Record<string, string> = {
  pdf: 'las la-file-pdf',
  doc: 'las la-file-word',
  docx: 'las la-file-word',
  xls: 'las la-file-excel',
  xlsx: 'las la-file-excel',
  csv: 'las la-file-csv',
  ppt: 'las la-file-powerpoint',
  pptx: 'las la-file-powerpoint',
  zip: 'las la-file-archive',
  rar: 'las la-file-archive',
  '7z': 'las la-file-archive',
  jpg: 'las la-file-image',
  jpeg: 'las la-file-image',
  png: 'las la-file-image',
  gif: 'las la-file-image',
  svg: 'las la-file-image',
  webp: 'las la-file-image',
  mp4: 'las la-file-video',
  mp3: 'las la-file-audio',
  txt: 'las la-file-alt',
  json: 'las la-file-code',
};

@Component({
  selector: 'xrm-notes-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [CommonModule, FormsModule, TranslatePipe, TranslateTextComponent, MentionPickerComponent],
  styleUrls: ['./notes-panel.component.css'],
  templateUrl: './notes-panel.component.html',
})
export class NotesPanelComponent implements OnInit {
  readonly entityName = input.required<string>();
  readonly recordId = input.required<string>();

  private readonly entityService = inject(EntityService);
  private readonly fileService = inject(FileUploadService);
  private readonly dialogService = inject(DialogService);
  private readonly authService = inject(AuthService);
  private readonly cdr = inject(ChangeDetectorRef);
  private readonly destroyRef = inject(DestroyRef);
  private readonly injector = inject(Injector);

  /**
   * C4-T2: who and what `@` can name in a note or reply — people, teams and
   * (from global search) records. A source the caller may not read adds
   * nothing rather than failing the others.
   */
  readonly mentionSearch: MentionSearch = (query: string) => {
    const term = query.trim();
    const none = of([] as MentionCandidate[]);
    const people: Observable<MentionCandidate[]> = this.entityService
      .lookupSearch('user_account', term, 'user_name').pipe(
        map(page => page.data.slice(0, 5).map(r => ({
          kind: 'user' as const,
          id: r.id,
          label: String(r.data['user_name'] || r.data['email'] || r.id),
          detail: r.data['email'] ? String(r.data['email']) : undefined,
        }))),
        catchError(() => none),
      );
    const teams: Observable<MentionCandidate[]> = this.entityService
      .lookupSearch('team', term, 'name').pipe(
        map(page => page.data.slice(0, 3).map(r => ({
          kind: 'team' as const,
          id: r.id,
          label: String(r.data['name'] || r.id),
        }))),
        catchError(() => none),
      );
    const api = this.api;
    const records: Observable<MentionCandidate[]> = term.length < 2 || !api
      ? none
      : api.get<{ items: { entity_logicalname: string; record_id: string; title?: string | null }[] }>(
          '/api/v1/search', { q: term, page_size: '5' },
        ).pipe(
          map(res => res.items.map(h => ({
            kind: 'record' as const,
            id: h.record_id,
            entity: h.entity_logicalname,
            label: h.title || h.record_id,
            detail: h.entity_logicalname,
          }))),
          catchError(() => none),
        );
    return forkJoin([people, teams, records]).pipe(map(([p, t, r]) => [...p, ...t, ...r]));
  };

  /** Resolved on first use, so a host without an HTTP client still renders. */
  private get api(): ApiService | null {
    return this.injector.get(ApiService, null);
  }

  /**
   * C4-T1: tells the people and teams a saved text names. Best effort: the
   * note is saved either way, and the server skips anyone who may not read
   * the record.
   */
  private notifyMentions(text: string): void {
    if (!text.includes('@[')) return;
    const path = `/api/v1/${encodeURIComponent(this.entityName())}/${encodeURIComponent(this.recordId())}/mentions`;
    this.api?.post(path, { text }).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      error: () => undefined,
    });
  }

  readonly titleInput = viewChild<ElementRef<HTMLInputElement>>('titleInput');
  readonly contentInput = viewChild<ElementRef<HTMLTextAreaElement>>('contentInput');
  readonly createFileInput = viewChild<ElementRef<HTMLInputElement>>('createFileInput');
  readonly replyFileInput = viewChild<ElementRef<HTMLInputElement>>('replyFileInput');

  readonly loading = signal(true);
  readonly saving = signal(false);
  readonly sendingReply = signal(false);
  readonly errorMessage = signal<string | null>(null);

  readonly notes = signal<NoteItem[]>([]);
  readonly selectedNoteId = signal<string | null>(null);
  readonly viewMode = signal<'create' | 'edit' | 'detail'>('create');
  readonly openMenuId = signal<string | null>(null);

  // Form (Create/Edit) state
  editingNoteId: string | null = null;
  formNoteTitle = '';
  formNoteText = '';
  readonly existingAttachments = signal<NoteAttachment[]>([]);
  readonly pendingFiles = signal<File[]>([]);

  // Reply Composer state
  replyText = '';
  readonly replyPendingFiles = signal<File[]>([]);

  // Reply Edit state
  readonly editingReplyId = signal<string | null>(null);
  editingReplyText = '';

  readonly selectedNote = computed(() => {
    const id = this.selectedNoteId();
    if (!id) return null;
    return this.notes().find(n => n.id === id) ?? null;
  });

  private userCache = new Map<string, { name: string; initials: string }>();
  private readonly uploadPipeline = new UploadPipeline(this.fileService);
  /** Name of the file currently moving through the upload pipeline, if any. */
  readonly uploadingFile = signal<string | null>(null);

  constructor() {
    this.destroyRef.onDestroy(() => this.uploadPipeline.cancel());
    effect(() => {
      const e = this.entityName();
      const r = this.recordId();
      untracked(() => {
        if (e && r) {
          this.loadUsersAndNotes();
        }
      });
    });
  }

  ngOnInit(): void {
    const clickHandler = () => {
      if (this.openMenuId()) {
        this.openMenuId.set(null);
      }
    };
    document.addEventListener('click', clickHandler);
    this.destroyRef.onDestroy(() => {
      document.removeEventListener('click', clickHandler);
    });
  }

  loadUsersAndNotes(): void {
    this.loading.set(true);
    this.entityService.list('user_account', { limit: 100 }).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: res => {
        for (const user of res.data) {
          const raw = user.data as Record<string, unknown>;
          const user_name = String(raw['user_name'] || '');
          const email = String(raw['email'] || '');
          const name = user_name || email || 'User';
          const initials = this.calcInitials(name);
          this.userCache.set(user.id, { name, initials });
        }
        this.fetchNotes();
      },
      error: () => {
        this.fetchNotes();
      },
    });
  }

  getCurrentUserInfo(): { name: string; initials: string } {
    const currentUserId = this.authService.userId();
    if (currentUserId && this.userCache.has(currentUserId)) {
      return this.userCache.get(currentUserId)!;
    }
    // Check first note's author if available
    const firstNoteAuthor = this.notes()[0]?.author_name;
    if (firstNoteAuthor) {
      return { name: firstNoteAuthor, initials: this.calcInitials(firstNoteAuthor) };
    }
    return { name: 'Dev Agent', initials: 'DA' };
  }

  fetchNotes(autoSelectId?: string): void {
    const eName = this.entityName();
    const rId = this.recordId();

    if (!rId) {
      this.notes.set([]);
      this.loading.set(false);
      return;
    }

    this.entityService.list('note', {
      filters: [
        { field: 'entity_name', op: 'eq', value: eName },
        { field: 'record_id', op: 'eq', value: rId },
      ],
      sorts: [{ field: 'created_at', dir: 'desc' }],
      limit: 100,
    }).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: res => {
        const mapped: NoteItem[] = res.data.map(item => {
          const raw = item.data as Record<string, unknown>;
          const created_by = (raw['created_by'] as string) || null;
          const userMeta = created_by ? this.userCache.get(created_by) : null;
          const author_name = userMeta ? userMeta.name : (created_by ? 'User' : 'System');
          const author_initials = userMeta ? userMeta.initials : this.calcInitials(author_name);

          let parsedAttachments: NoteAttachment[] = [];
          if (raw['attachments']) {
            if (typeof raw['attachments'] === 'string') {
              try {
                parsedAttachments = JSON.parse(raw['attachments']);
              } catch {
                parsedAttachments = [];
              }
            } else if (Array.isArray(raw['attachments'])) {
              parsedAttachments = raw['attachments'] as NoteAttachment[];
            }
          }

          let parsedReplies: NoteReply[] = [];
          if (raw['replies']) {
            if (typeof raw['replies'] === 'string') {
              try {
                parsedReplies = JSON.parse(raw['replies']);
              } catch {
                parsedReplies = [];
              }
            } else if (Array.isArray(raw['replies'])) {
              parsedReplies = raw['replies'] as NoteReply[];
            }
          }

          // Remap old "You" / "ME" to actual user name and initials
          parsedReplies = parsedReplies.map(r => {
            let rName = r.author_name;
            let rInitials = r.author_initials;

            if (r.author_id && this.userCache.has(r.author_id)) {
              const u = this.userCache.get(r.author_id)!;
              rName = u.name;
              rInitials = u.initials;
            } else if (rName === 'You' || rInitials === 'ME' || !rName) {
              const currentUser = this.getCurrentUserInfo();
              rName = currentUser.name;
              rInitials = currentUser.initials;
            }

            return {
              ...r,
              author_name: rName,
              author_initials: rInitials || this.calcInitials(rName),
            };
          });

          const title = String(raw['title'] || '');
          const noteText = String(raw['note_text'] || '');

          return {
            id: item.id,
            title: title || (noteText.length > 30 ? noteText.slice(0, 30) + '…' : noteText || 'Untitled Note'),
            note_text: noteText,
            entity_name: String(raw['entity_name'] || eName),
            record_id: String(raw['record_id'] || rId),
            created_at: item.created_at || new Date().toISOString(),
            created_by,
            modified_at: item.updated_at,
            author_name,
            author_initials,
            author_action: author_name.toLowerCase().includes('system') ? 'automated log' : 'left a note',
            attachments: parsedAttachments,
            replies: parsedReplies,
            row_version: item.row_version,
          };
        });

        this.notes.set(mapped);
        this.loading.set(false);

        if (autoSelectId) {
          this.selectNote(autoSelectId);
        } else if (this.viewMode() === 'detail' && !this.selectedNote()) {
          if (mapped.length > 0) {
            this.selectNote(mapped[0].id);
          } else {
            this.startCreateNote();
          }
        }
      },
      error: () => {
        this.notes.set([]);
        this.loading.set(false);
      },
    });
  }

  selectNote(id: string): void {
    this.selectedNoteId.set(id);
    this.viewMode.set('detail');
    this.errorMessage.set(null);
    this.editingReplyId.set(null);
  }

  startCreateNote(): void {
    this.selectedNoteId.set(null);
    this.editingNoteId = null;
    this.formNoteTitle = '';
    this.formNoteText = '';
    this.existingAttachments.set([]);
    this.pendingFiles.set([]);
    this.viewMode.set('create');
    this.errorMessage.set(null);
    setTimeout(() => {
      this.titleInput()?.nativeElement.focus();
    }, 50);
  }

  startEditNote(note: NoteItem): void {
    this.selectedNoteId.set(note.id);
    this.editingNoteId = note.id;
    this.formNoteTitle = note.title;
    this.formNoteText = note.note_text;
    this.existingAttachments.set([...(note.attachments || [])]);
    this.pendingFiles.set([]);
    this.viewMode.set('edit');
    this.errorMessage.set(null);
    this.openMenuId.set(null);
    setTimeout(() => {
      this.titleInput()?.nativeElement.focus();
    }, 50);
  }

  /** Cancel create/edit (the Cancel buttons, and Esc in the form's fields).
   * With no note to go back to, the draft is cleared instead. */
  cancelForm(): void {
    if (this.editingNoteId) {
      this.selectNote(this.editingNoteId);
    } else {
      const list = this.notes();
      if (list.length > 0) {
        this.selectNote(list[0].id);
      } else {
        this.formNoteTitle = '';
        this.formNoteText = '';
        this.pendingFiles.set([]);
        this.errorMessage.set(null);
      }
    }
  }

  focusContentArea(): void {
    this.contentInput()?.nativeElement.focus();
  }

  triggerCreateFileInput(): void {
    this.createFileInput()?.nativeElement.click();
  }

  onFilesSelected(event: Event): void {
    const target = event.target as HTMLInputElement;
    if (target.files && target.files.length > 0) {
      const added = Array.from(target.files);
      this.pendingFiles.update(files => [...files, ...added]);
      target.value = '';
    }
  }

  removePendingFile(index: number): void {
    this.pendingFiles.update(files => files.filter((_, i) => i !== index));
  }

  removeExistingAttachment(index: number): void {
    this.existingAttachments.update(atts => atts.filter((_, i) => i !== index));
  }

  saveFormNote(): void {
    const title = this.formNoteTitle.trim();
    const text = this.formNoteText.trim();
    const files = this.pendingFiles();

    if (!title || !text) {
      this.errorMessage.set('Please provide both a title and note content.');
      return;
    }

    this.saving.set(true);
    this.errorMessage.set(null);

    if (this.viewMode() === 'edit' && this.editingNoteId) {
      void this.saveEditedNote(this.editingNoteId, title, text, files);
    } else {
      this.createNote(title, text, files);
    }
  }

  // An upload needs the note's own id (the file key is scoped to it), so an
  // edit uploads first and saves once; a new note is created bare, then its
  // files are uploaded and attached by a follow-up update.
  private async saveEditedNote(noteId: string, title: string, text: string, files: File[]): Promise<void> {
    const activeNote = this.selectedNote();
    // No `await` runs before `update` when there is nothing to upload.
    const { uploaded, failures } = files.length > 0
      ? await this.uploadFiles(noteId, files)
      : { uploaded: [], failures: [] };
    const allAttachments = [...this.existingAttachments(), ...uploaded];

    const updatePayload: Record<string, unknown> = {
      title,
      note_text: text,
      attachments: JSON.stringify(allAttachments),
      [NOTE_FILES_FIELD]: this.noteFileKeys(allAttachments, activeNote?.replies),
    };

    this.entityService.update('note', noteId, updatePayload, activeNote?.row_version ?? 0).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: () => {
        this.saving.set(false);
        this.pendingFiles.set([]);
        this.refreshAfterSave(noteId, failures);
      },
      error: err => {
        this.saving.set(false);
        this.errorMessage.set(err?.message || 'Failed to update note.');
      },
    });
  }

  private createNote(title: string, text: string, files: File[]): void {
    const createPayload: Record<string, unknown> = {
      entity_name: this.entityName(),
      record_id: this.recordId(),
      title,
      note_text: text,
    };

    this.entityService.create('note', createPayload).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: res => {
        this.notifyMentions(text);
        this.formNoteTitle = '';
        this.formNoteText = '';
        this.pendingFiles.set([]);
        this.existingAttachments.set([]);
        if (files.length === 0) {
          this.saving.set(false);
          this.fetchNotes(res.id);
          return;
        }
        void this.attachToNewNote(res.id, res.row_version, files);
      },
      error: err => {
        this.saving.set(false);
        this.errorMessage.set(err?.message || 'Failed to save note. Please try again.');
      },
    });
  }

  private async attachToNewNote(noteId: string, rowVersion: number, files: File[]): Promise<void> {
    const { uploaded, failures } = await this.uploadFiles(noteId, files);
    if (uploaded.length === 0) {
      this.saving.set(false);
      this.refreshAfterSave(noteId, failures);
      return;
    }

    this.entityService.update('note', noteId, {
      attachments: JSON.stringify(uploaded),
      [NOTE_FILES_FIELD]: this.noteFileKeys(uploaded, []),
    }, rowVersion).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: () => {
        this.saving.set(false);
        this.refreshAfterSave(noteId, failures);
      },
      error: err => {
        // The note itself was saved; only attaching its files failed.
        this.saving.set(false);
        this.refreshAfterSave(noteId, [`the note was saved but its files were not attached (${err?.message || 'unknown error'})`]);
      },
    });
  }

  /**
   * Runs each file through the D-144 pipeline one at a time (one presigned PUT
   * and one scan poll in flight, as `MultiAttachmentComponent` does). A file
   * that is rejected or fails does not stop the rest.
   */
  private async uploadFiles(noteId: string, files: File[]): Promise<{ uploaded: NoteAttachment[]; failures: string[] }> {
    const uploaded: NoteAttachment[] = [];
    const failures: string[] = [];
    for (const file of files) {
      this.uploadingFile.set(file.name);
      const result = await this.uploadPipeline.run(
        { entityName: 'note', recordId: noteId, fieldName: NOTE_FILES_FIELD },
        file,
      );
      if (result.kind === 'clean') {
        uploaded.push({
          name: file.name,
          size_bytes: file.size,
          size_formatted: this.formatBytes(file.size),
          content_type: file.type,
          key: result.finalKey,
        });
      } else {
        failures.push(`${file.name}: ${result.message}`);
      }
    }
    this.uploadingFile.set(null);
    return { uploaded, failures };
  }

  /** Every object key the note and its replies still reference — the value `files` must hold. */
  private noteFileKeys(attachments: NoteAttachment[] | undefined, replies: NoteReply[] | undefined): string[] {
    const keys = new Set<string>();
    for (const att of attachments ?? []) if (att.key) keys.add(att.key);
    for (const reply of replies ?? []) {
      for (const att of reply.attachments ?? []) if (att.key) keys.add(att.key);
    }
    return [...keys];
  }

  /**
   * `fetchNotes(id)` re-runs `selectNote`, which clears `errorMessage` — so
   * when some files failed, select first, set the message, then refetch
   * without an `autoSelectId` (the same recovery the reply-conflict handlers
   * below use) so the message survives the reload.
   */
  private refreshAfterSave(noteId: string, failures: string[]): void {
    if (failures.length === 0) {
      this.fetchNotes(noteId);
      return;
    }
    this.selectNote(noteId);
    this.errorMessage.set(`Some files were not attached — ${failures.join('; ')}`);
    this.fetchNotes();
  }

  triggerReplyFileInput(): void {
    this.replyFileInput()?.nativeElement.click();
  }

  onReplyFilesSelected(event: Event): void {
    const target = event.target as HTMLInputElement;
    if (target.files && target.files.length > 0) {
      const added = Array.from(target.files);
      this.replyPendingFiles.update(files => [...files, ...added]);
      target.value = '';
    }
  }

  removeReplyFile(index: number): void {
    this.replyPendingFiles.update(files => files.filter((_, i) => i !== index));
  }

  /** Escape in the note text: closes an open mention list first. */
  onContentEscape(event: KeyboardEvent): void {
    event.stopPropagation();
    if ((event.target as HTMLElement | null)?.getAttribute('aria-expanded') === 'true') return;
    this.cancelForm();
  }

  onReplyKeydown(event: KeyboardEvent): void {
    // C4-T2: while the mention list is open, Enter picks from it.
    if ((event.target as HTMLElement | null)?.getAttribute('aria-expanded') === 'true') return;
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      this.sendReply();
    }
  }

  sendReply(): void {
    const activeNote = this.selectedNote();
    if (!activeNote) return;

    const text = this.replyText.trim();
    const files = this.replyPendingFiles();

    if (!text && files.length === 0) return;

    this.sendingReply.set(true);
    void this.postReply(activeNote, text, files);
  }

  private async postReply(activeNote: NoteItem, text: string, files: File[]): Promise<void> {
    // Reply files live in the parent note's `files` field (a reply is not a
    // record of its own). No `await` runs before `update` without files.
    const { uploaded: attachmentsMeta, failures } = files.length > 0
      ? await this.uploadFiles(activeNote.id, files)
      : { uploaded: [] as NoteAttachment[], failures: [] as string[] };

    if (!text && attachmentsMeta.length === 0) {
      this.sendingReply.set(false);
      this.errorMessage.set(`Some files were not attached — ${failures.join('; ')}`);
      return;
    }

    const user = this.getCurrentUserInfo();

    const newReply: NoteReply = {
      id: crypto.randomUUID(),
      author_id: this.authService.userId(),
      author_name: user.name,
      author_initials: user.initials,
      note_text: text,
      created_at: new Date().toISOString(),
      attachments: attachmentsMeta.length > 0 ? attachmentsMeta : undefined,
    };

    const currentReplies = activeNote.replies ? [...activeNote.replies] : [];
    const updatedReplies = [...currentReplies, newReply];
    const replyPatch: Record<string, unknown> = { replies: JSON.stringify(updatedReplies) };
    if (attachmentsMeta.length > 0) {
      replyPatch[NOTE_FILES_FIELD] = this.noteFileKeys(activeNote.attachments, updatedReplies);
    }

    this.entityService.update('note', activeNote.id, replyPatch, activeNote.row_version ?? 0).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: () => {
        this.notifyMentions(text);
        this.replyText = '';
        this.replyPendingFiles.set([]);
        this.sendingReply.set(false);
        this.refreshAfterSave(activeNote.id, failures);
      },
      error: (err: ApiError) => {
        // C-29 (M01 §7) — `replies` is a `row_version`-guarded field
        // (`If-Match`, D-037), not last-writer-wins: a concurrent reply from
        // another tab/user makes this `update` 409 (`version_conflict`)
        // rather than silently clobbering it. Previously this handler
        // swallowed that conflict — the composer cleared nothing, but the
        // reply was never sent and the user got no indication why, and the
        // stale in-memory `replies` list (from before the other party's
        // reply landed) stayed on screen. Surface it and refetch so the view
        // reconciles with what the server actually holds, same recovery
        // `saveEditReply`/`deleteReply` below now use.
        //
        // Deliberately `fetchNotes()` with no `autoSelectId` here: passing
        // this note's own id (it's already the selected note) would re-run
        // `selectNote()`, which resets `errorMessage` back to null as one of
        // its normal "starting a fresh view" side effects — clobbering the
        // message this very branch just set. No `autoSelectId` still
        // reconciles `notes()` with the server, and the existing "still on
        // this note, still in detail view" fallback in `fetchNotes` leaves
        // the selection untouched when the note is still there.
        this.sendingReply.set(false);
        this.errorMessage.set(this.conflictMessage(err));
        this.fetchNotes();
      },
    });
  }

  /** A `version_conflict` means someone else's reply/edit/delete landed on
   * this note since it was loaded — the row_version guard did its job; this
   * just gives the user an explanation instead of a mutation that silently
   * did nothing. */
  private conflictMessage(err: ApiError): string {
    return err?.kind === 'version_conflict'
      ? 'Someone else updated this note. Refreshing with the latest version — please try again.'
      : err?.message || 'Failed to save the reply.';
  }

  startEditReply(reply: NoteReply): void {
    this.openMenuId.set(null);
    this.editingReplyId.set(reply.id);
    this.editingReplyText = reply.note_text;
  }

  cancelEditReply(): void {
    this.editingReplyId.set(null);
    this.editingReplyText = '';
  }

  saveEditReply(note: NoteItem, replyId: string): void {
    const text = this.editingReplyText.trim();
    if (!text) return;

    const currentReplies = note.replies ? [...note.replies] : [];
    const updatedReplies = currentReplies.map(r => r.id === replyId ? { ...r, note_text: text } : r);

    this.entityService.update('note', note.id, { replies: JSON.stringify(updatedReplies) }, note.row_version ?? 0).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: () => {
        this.editingReplyId.set(null);
        this.editingReplyText = '';
        this.fetchNotes(note.id);
      },
      // C-29 (M01 §7) — previously had no error branch at all: a concurrent
      // edit/delete elsewhere made this `update` 409 and the UI silently
      // stayed in edit mode showing the (never-saved) new text, with no
      // indication to the user that nothing was persisted. Same recovery as
      // `sendReply` above — `fetchNotes()` with no `autoSelectId`, so the
      // reconciling refetch doesn't re-run `selectNote()` and wipe the
      // `errorMessage` this branch just set.
      error: (err: ApiError) => {
        this.errorMessage.set(this.conflictMessage(err));
        this.fetchNotes();
      },
    });
  }

  deleteReply(note: NoteItem, replyId: string): void {
    this.openMenuId.set(null);
    this.dialogService.confirm({
      title: 'Delete reply',
      message: 'Are you sure you want to delete this reply?',
      confirmText: 'Delete',
      variant: 'danger',
    }).then(ok => {
      if (ok) {
        const currentReplies = note.replies ? [...note.replies] : [];
        const updatedReplies = currentReplies.filter(r => r.id !== replyId);
        const patch: Record<string, unknown> = { replies: JSON.stringify(updatedReplies) };
        if (currentReplies.some(r => r.id === replyId && r.attachments?.some(a => a.key))) {
          patch[NOTE_FILES_FIELD] = this.noteFileKeys(note.attachments, updatedReplies);
        }
        this.entityService.update('note', note.id, patch, note.row_version ?? 0).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
          next: () => {
            this.fetchNotes(note.id);
          },
          // C-29 (M01 §7) — same silent-conflict gap as saveEditReply: a
          // 409 here used to leave the (still-present) reply on screen with
          // no explanation of why the delete didn't take. Same no-
          // `autoSelectId` reasoning as `sendReply`/`saveEditReply` above.
          error: (err: ApiError) => {
            this.errorMessage.set(this.conflictMessage(err));
            this.fetchNotes();
          },
        });
      }
    });
  }

  toggleMenu(menuId: string, event: MouseEvent): void {
    event.stopPropagation();
    if (this.openMenuId() === menuId) {
      this.openMenuId.set(null);
    } else {
      this.openMenuId.set(menuId);
    }
  }

  copyNoteText(text: string): void {
    navigator.clipboard.writeText(text);
    this.openMenuId.set(null);
  }

  deleteNote(noteId: string): void {
    this.openMenuId.set(null);
    this.dialogService.confirm({
      title: 'Delete note',
      message: 'Are you sure you want to delete this note thread?',
      confirmText: 'Delete',
      variant: 'danger',
    }).then(ok => {
      if (ok) {
        this.entityService.delete('note', noteId).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
          next: () => {
            this.notes.update(current => current.filter(n => n.id !== noteId));
            const remaining = this.notes();
            if (remaining.length > 0) {
              this.selectNote(remaining[0].id);
            } else {
              this.startCreateNote();
            }
          },
        });
      }
    });
  }

  openAttachment(noteId: string, att: NoteAttachment): void {
    if (!att.key) {
      // Attachments saved before uploads were wired up carry only a name and
      // size — their bytes never left the browser, so there is nothing to open.
      this.errorMessage.set(`"${att.name}" was saved without its file content and cannot be opened.`);
      return;
    }
    this.fileService.getDownloadUrl('note', noteId, NOTE_FILES_FIELD, att.key)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: res => window.open(res.download_url, '_blank', 'noopener'),
        error: (err: ApiError) => this.errorMessage.set(err?.message || `Could not open "${att.name}".`),
      });
  }

  getAttachmentIcon(filename: string): string {
    const ext = filename.split('.').pop()?.toLowerCase() || '';
    return EXTENSION_ICONS[ext] || 'las la-file-alt';
  }

  calcInitials(name: string): string {
    if (!name) return 'U';
    const parts = name.trim().split(/[\s._-]+/);
    if (parts.length >= 2) {
      return (parts[0][0] + parts[1][0]).toUpperCase();
    }
    return name.slice(0, 2).toUpperCase();
  }

  formatShortTime(dateStr?: string | null): string {
    if (!dateStr) return '';
    try {
      const d = new Date(dateStr);
      if (isNaN(d.getTime())) return '';
      const now = new Date();
      const isToday = d.toDateString() === now.toDateString();
      if (isToday) {
        return d.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
      }
      return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
    } catch {
      return '';
    }
  }

  formatDetailedDate(dateStr?: string | null): string {
    if (!dateStr) return '';
    try {
      const d = new Date(dateStr);
      if (isNaN(d.getTime())) return '';
      const now = new Date();
      const yesterday = new Date();
      yesterday.setDate(now.getDate() - 1);

      const timePart = d.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
      if (d.toDateString() === now.toDateString()) {
        return `Today at ${timePart}`;
      }
      if (d.toDateString() === yesterday.toDateString()) {
        return `Yesterday at ${timePart}`;
      }
      const datePart = d.toLocaleDateString([], { month: 'short', day: 'numeric', year: d.getFullYear() !== now.getFullYear() ? 'numeric' : undefined });
      return `${datePart} at ${timePart}`;
    } catch {
      return dateStr || '';
    }
  }

  formatBytes(bytes?: number | null): string {
    if (bytes == null || isNaN(bytes)) return '';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }
}
