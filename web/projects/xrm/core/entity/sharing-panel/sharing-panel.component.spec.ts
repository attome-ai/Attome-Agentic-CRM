import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { SharingPanelComponent } from './sharing-panel.component';
import { RecordShare, SharingPanelService } from './sharing-panel.service';

const SHARE: RecordShare = {
  id: 's1', principal_type: 'user', principal_id: 'u1', capability: 'view', granted_at: '2026-10-27T00:00:00Z',
};
const DENY: RecordShare = {
  id: 's2', principal_type: 'team', principal_id: 't1', capability: 'deny', granted_at: '2026-10-27T00:00:00Z',
};

describe('SharingPanelComponent', () => {
  let svc: Record<string, ReturnType<typeof vi.fn>>;

  beforeEach(() => {
    svc = {
      record: vi.fn((entity: string) => of(entity === 'organization'
        ? { id: 'o1', entity_id: 'e', row_version: 1, data: { name: 'Riyadh' } }
        : { id: 'r1', entity_id: 'e', row_version: 1, data: { owner_ref: 'u9', owner_type: 0, organization_ref: 'o1' } })),
      name: vi.fn((_kind: string, id: string) => of(`name-${id}`)),
      shares: vi.fn().mockReturnValue(of([SHARE, DENY])),
      search: vi.fn((kind: string) => of([{ kind, id: kind === 'user' ? 'u2' : 't2', label: `${kind}-2` }])),
      share: vi.fn().mockReturnValue(of({ ...SHARE, id: 's3', principal_id: 'u2', capability: 'action' })),
      unshare: vi.fn().mockReturnValue(of(undefined)),
      explain: vi.fn().mockReturnValue(of({
        user_id: 'u2', action: 'read', allowed: true,
        sources: [
          { source: 'role_level', effect: 'not_applicable', detail: 'Team level', winning: false },
          { source: 'user_share', effect: 'grants', detail: 'Shared to view', winning: true },
        ],
      })),
    };
    TestBed.configureTestingModule({
      imports: [SharingPanelComponent],
      providers: [
        { provide: SharingPanelService, useValue: svc },
        { provide: LangService, useValue: { translate: (k: string) => k, errorText: (e: { message: string }) => e.message, intlLocale: () => 'en' } },
      ],
    });
    TestBed.overrideComponent(SharingPanelComponent, { set: { template: '' } });
  });

  function create(): SharingPanelComponent {
    const fixture = TestBed.createComponent(SharingPanelComponent);
    fixture.componentRef.setInput('entityName', 'contact');
    fixture.componentRef.setInput('recordId', 'r1');
    fixture.detectChanges();
    return fixture.componentInstance;
  }

  it('shows the owner, the unit and the shares by name', () => {
    const c = create();
    expect(c.owner()).toBe('name-u9');
    expect(c.unit()).toBe('Riyadh');
    expect(c.shares().map(r => r.label)).toEqual(['name-u1', 'name-t1']);
    expect(svc['name']).toHaveBeenCalledWith('team', 't1');
  });

  it('adds and removes a share', () => {
    const c = create();
    c.pickedId.set('u2');
    c.capability.set('action');
    c.share();
    expect(svc['share']).toHaveBeenCalledWith('contact', 'r1', { kind: 'user', id: 'u2', label: 'user-2' }, 'action');
    expect(c.shares()[0]).toEqual({ share: expect.objectContaining({ id: 's3' }), label: 'user-2' });
    c.unshare(SHARE);
    expect(svc['unshare']).toHaveBeenCalledWith('contact', 'r1', 's1');
    expect(c.shares().map(r => r.share.id)).toEqual(['s3', 's2']);
  });

  it('searches teams after switching kind', () => {
    const c = create();
    c.setKind('team');
    expect(c.options()).toEqual([{ kind: 'team', id: 't2', label: 'team-2' }]);
  });

  it('explains why a chosen person has access', () => {
    const c = create();
    c.explainUser.set('u2');
    c.explainAction.set('update');
    c.explain();
    expect(svc['explain']).toHaveBeenCalledWith('contact', 'r1', 'u2', 'update');
    expect(c.explanation()?.sources.find(s => s.winning)?.source).toBe('user_share');
  });

  it('says so when the person cannot manage sharing', () => {
    svc['shares'].mockReturnValue(throwError(() => ({ kind: 'forbidden', status: 403, message: 'no' })));
    const c = create();
    expect(c.forbidden()).toBe(true);
    expect(c.error()).toBeNull();
  });
});
