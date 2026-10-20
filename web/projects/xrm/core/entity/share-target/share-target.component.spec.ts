import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { AuthService, LangService } from '@attome/base';
import { FileUploadService } from '../field/file-upload.service';
import { UploadPipeline } from '../field/upload-pipeline';
import { EntityService } from '../services/entity.service';
import { of } from 'rxjs';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ShareTargetComponent } from './share-target.component';

/** A Cache Storage holding one share of two files, as `src/sw.js` keeps it. */
function sharedCache() {
  const entries = new Map<string, Response>([
    ['/share-target/meta', new Response(JSON.stringify({
      title: '', text: 'From my phone', url: '',
      files: [{ name: 'a.pdf', type: 'application/pdf' }, { name: 'b.png', type: 'image/png' }],
    }))],
    ['/share-target/file/0', new Response('pdf')],
    ['/share-target/file/1', new Response('png')],
  ]);
  const cache = { match: vi.fn(async (key: string) => entries.get(key)?.clone()) };
  return { open: vi.fn(async () => cache), delete: vi.fn(async () => true) };
}

describe('ShareTargetComponent (B19-T2)', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  async function setUp(store = sharedCache()) {
    vi.stubGlobal('caches', store);
    const entities = {
      create: vi.fn(() => of({ id: 'doc-1', entity_id: '', data: {} })),
      update: vi.fn(() => of({ id: 'doc-1', entity_id: '', data: {} })),
    };
    TestBed.configureTestingModule({
      imports: [ShareTargetComponent],
      providers: [
        provideRouter([]),
        { provide: EntityService, useValue: entities },
        { provide: FileUploadService, useValue: {} },
        { provide: AuthService, useValue: { userId: signal('u-1') } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en') } },
      ],
    });
    const fixture = TestBed.createComponent(ShareTargetComponent);
    await fixture.componentInstance.ngOnInit();
    fixture.detectChanges();
    return { fixture, root: fixture.nativeElement as HTMLElement, entities, store };
  }

  it('lists the shared files', async () => {
    const { root } = await setUp();
    expect(root.querySelector('[data-share-file="a.pdf"]')).not.toBeNull();
    expect(root.querySelector('[data-share-file="b.png"]')).not.toBeNull();
  });

  it('saves each file as one of my documents, then forgets the share', async () => {
    const run = vi.spyOn(UploadPipeline.prototype, 'run').mockResolvedValue({ kind: 'clean', finalKey: 'k' });
    const { fixture, root, entities, store } = await setUp();
    await fixture.componentInstance.save();
    fixture.detectChanges();
    expect(entities.create).toHaveBeenCalledWith('attome_document', {
      name: 'a.pdf', entity_name: 'user_account', record_id: 'u-1', folder: 'shared',
    });
    expect(run).toHaveBeenCalledTimes(2);
    expect(entities.update).toHaveBeenCalledWith('attome_document', 'doc-1', { file: 'k' }, 0);
    expect(store.delete).toHaveBeenCalledWith('attome-share');
    expect(root.querySelector('[data-share-done]')).not.toBeNull();
  });

  it('keeps the share when a file is refused', async () => {
    vi.spyOn(UploadPipeline.prototype, 'run').mockResolvedValue({ kind: 'rejected', message: 'infected' });
    const { fixture, root, store } = await setUp();
    await fixture.componentInstance.save();
    fixture.detectChanges();
    expect(store.delete).not.toHaveBeenCalled();
    expect(root.querySelector('[data-share-done]')).toBeNull();
  });

  it('shows nothing to save when no share was kept', async () => {
    const empty = { open: vi.fn(async () => ({ match: vi.fn(async () => undefined) })), delete: vi.fn() };
    const { root } = await setUp(empty as never);
    expect(root.querySelector('[data-share-empty]')).not.toBeNull();
  });
});
