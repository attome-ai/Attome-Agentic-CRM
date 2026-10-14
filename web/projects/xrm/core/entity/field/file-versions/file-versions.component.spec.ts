import { TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { of, throwError } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService, UserPreferencesService } from '@attome/base';
import { DialogService } from '@attome/base/dialog';

import { FileVersionsComponent } from './file-versions.component';
import { FileUploadService, FileVersion } from '../file-upload.service';
import { RecordChange, RecordChangeNotifier } from '../../services/record-change-notifier.service';

const SESSION = '00000000-0000-0000-0000-000000000000';

function version(no: number, isCurrent = false): FileVersion {
  return {
    version_no: no,
    object_key: `contact/rec-1/resume/${SESSION}-cv-v${no}.pdf`,
    size: 2048,
    hash: null,
    content_type: 'application/pdf',
    uploaded_by: '0190a1b2-0000-7000-8000-000000000009',
    scan_status: 'clean',
    is_current: isCurrent,
    created_at: '2026-09-01T10:00:00Z',
  };
}

describe('FileVersionsComponent', () => {
  let fileSvc: {
    listVersions:   ReturnType<typeof vi.fn>;
    restoreVersion: ReturnType<typeof vi.fn>;
    purgeVersion:   ReturnType<typeof vi.fn>;
    getDownloadUrl: ReturnType<typeof vi.fn>;
  };
  let confirm: ReturnType<typeof vi.fn>;
  let changes: RecordChange[];

  beforeEach(() => {
    fileSvc = {
      listVersions:   vi.fn(() => of({ items: [version(2, true), version(1)], total: 2, page: 1, page_size: 2 })),
      restoreVersion: vi.fn(() => of({ version_no: 1, object_key: version(1).object_key })),
      purgeVersion:   vi.fn(() => of(undefined)),
      getDownloadUrl: vi.fn(() => of({ download_url: 'http://storage/v1', expires_in_secs: 900 })),
    };
    confirm = vi.fn(() => Promise.resolve(true));
    changes = [];
    TestBed.configureTestingModule({
      imports: [FileVersionsComponent],
      providers: [
        { provide: FileUploadService, useValue: fileSvc },
        { provide: DialogService, useValue: { confirm } },
        {
          provide: LangService,
          useValue: {
            translate: (key: string, params?: Record<string, unknown>) =>
              params ? `${key}:${JSON.stringify(params)}` : key,
            intlLocale: () => 'en-US',
            current: signal('en'),
          },
        },
        { provide: UserPreferencesService, useValue: { timezone: signal(null), calendar: () => null, digits: () => null } },
      ],
    });
    TestBed.inject(RecordChangeNotifier).changes.subscribe(c => changes.push(c));
  });

  afterEach(() => vi.restoreAllMocks());

  function create() {
    const fixture = TestBed.createComponent(FileVersionsComponent);
    fixture.componentRef.setInput('entityName', 'contact');
    fixture.componentRef.setInput('recordId', 'rec-1');
    fixture.componentRef.setInput('fieldName', 'resume');
    fixture.detectChanges();
    return { fixture, cmp: fixture.componentInstance, el: fixture.nativeElement as HTMLElement };
  }

  it('stays closed and fetches nothing until opened', () => {
    const { el } = create();
    expect(el.querySelector('.xfv-panel')).toBeNull();
    expect(el.querySelector('.xfv-trigger')!.getAttribute('aria-expanded')).toBe('false');
    expect(fileSvc.listVersions).not.toHaveBeenCalled();
  });

  it('lists versions newest first, marking the current one and offering restore/purge only on the others', () => {
    const { fixture, el } = create();
    (el.querySelector('.xfv-trigger') as HTMLButtonElement).click();
    fixture.detectChanges();

    expect(fileSvc.listVersions).toHaveBeenCalledWith('contact', 'rec-1', 'resume');
    const items = el.querySelectorAll('.xfv-item');
    expect(items.length).toBe(2);
    expect(items[0].querySelector('.xfv-badge')).not.toBeNull();
    expect(items[0].querySelectorAll('.xfv-icon-btn').length).toBe(1);
    expect(items[1].querySelectorAll('.xfv-icon-btn').length).toBe(3);
    expect(items[1].textContent).toContain('cv-v1.pdf');
  });

  it('shows an empty state', () => {
    fileSvc.listVersions.mockReturnValue(of({ items: [], total: 0, page: 1, page_size: 1 }));
    const { fixture, cmp, el } = create();
    cmp.toggle();
    fixture.detectChanges();
    expect(el.querySelector('.xfv-empty')!.textContent).toContain('fileVersions.empty');
  });

  it('shows a load failure as an alert', () => {
    fileSvc.listVersions.mockReturnValue(throwError(() => ({ message: 'Forbidden' })));
    const { fixture, cmp, el } = create();
    cmp.toggle();
    fixture.detectChanges();
    expect(el.querySelector('[role="alert"]')!.textContent).toContain('Forbidden');
  });

  it('downloads one version through ?version=', () => {
    const openSpy = vi.spyOn(window, 'open').mockImplementation(() => null);
    const { cmp } = create();

    cmp.download(version(1));

    expect(fileSvc.getDownloadUrl).toHaveBeenCalledWith('contact', 'rec-1', 'resume', { version: 1 });
    expect(openSpy).toHaveBeenCalledWith('http://storage/v1', '_blank', 'noopener');
  });

  it('restores a version, emits it, tells the form to re-read the field and reloads the list', () => {
    const { cmp } = create();
    const restored: unknown[] = [];
    cmp.restored.subscribe(r => restored.push(r));
    cmp.toggle();

    cmp.restore(version(1));

    expect(fileSvc.restoreVersion).toHaveBeenCalledWith('contact', 'rec-1', 'resume', 1);
    expect(restored).toEqual([{ version_no: 1, object_key: version(1).object_key }]);
    expect(changes).toEqual([{ entityName: 'contact', recordId: 'rec-1', fields: ['resume'] }]);
    expect(fileSvc.listVersions).toHaveBeenCalledTimes(2);
    expect(cmp.busyVersion()).toBeNull();
  });

  it('never restores the current version', () => {
    const { cmp } = create();
    cmp.restore(version(2, true));
    expect(fileSvc.restoreVersion).not.toHaveBeenCalled();
  });

  it('shows a restore conflict and does not notify the form', () => {
    fileSvc.restoreVersion.mockReturnValue(throwError(() => ({ message: 'this version is already current' })));
    const { cmp } = create();

    cmp.restore(version(1));

    expect(cmp.error()).toBe('this version is already current');
    expect(changes).toEqual([]);
  });

  it('purges only after confirmation', async () => {
    const { cmp } = create();
    cmp.toggle();

    await cmp.purge(version(1));

    expect(confirm).toHaveBeenCalledWith(expect.objectContaining({ variant: 'danger' }));
    expect(fileSvc.purgeVersion).toHaveBeenCalledWith('contact', 'rec-1', 'resume', 1);
    expect(cmp.versions().map(v => v.version_no)).toEqual([2]);
  });

  it('does not purge when the confirm is cancelled', async () => {
    confirm.mockResolvedValue(false);
    const { cmp } = create();

    await cmp.purge(version(1));

    expect(fileSvc.purgeVersion).not.toHaveBeenCalled();
  });

  it('surfaces a retention/legal-hold refusal from purge', async () => {
    fileSvc.purgeVersion.mockReturnValue(throwError(() => ({ message: 'under legal hold' })));
    const { cmp } = create();
    cmp.toggle();

    await cmp.purge(version(1));

    expect(cmp.error()).toBe('under legal hold');
    expect(cmp.versions().length).toBe(2);
  });

  it('closes on Escape and returns focus to the trigger', () => {
    const { fixture, cmp, el } = create();
    cmp.toggle();
    fixture.detectChanges();

    cmp.onPanelKeydown(new KeyboardEvent('keydown', { key: 'Escape' }));
    fixture.detectChanges();

    expect(el.querySelector('.xfv-panel')).toBeNull();
    expect(document.activeElement === el.querySelector('.xfv-trigger') || !el.isConnected).toBe(true);
  });
});
