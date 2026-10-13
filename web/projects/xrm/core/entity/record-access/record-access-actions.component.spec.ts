import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { AccessService } from '@attome/xrm/core/access/data';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { RecordAccessActionsComponent } from './record-access-actions.component';

describe('RecordAccessActionsComponent (U7 Phase A)', () => {
  let admin: boolean;
  let hasPrivilege: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    admin = false;
    hasPrivilege = vi.fn((key: string) => admin && key === 'system.admin');
    TestBed.configureTestingModule({
      imports: [RecordAccessActionsComponent],
      providers: [
        { provide: AccessService, useValue: { ready: () => of(undefined), hasPrivilege } },
        { provide: LangService, useValue: { intlLocale: () => 'en-US', translate: (key: string) => key } },
      ],
    });
  });

  function render(recordIds: string[], allowShare = true) {
    const fixture = TestBed.createComponent(RecordAccessActionsComponent);
    fixture.componentRef.setInput('entity', 'ticket');
    fixture.componentRef.setInput('recordIds', recordIds);
    fixture.componentRef.setInput('allowShare', allowShare);
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    return { fixture, el, q: (id: string) => el.querySelector<HTMLButtonElement>(`[data-testid="${id}"]`) };
  }

  it('renders nothing for a non-admin', () => {
    const { q } = render(['r1']);
    expect(q('record-assign')).toBeNull();
    expect(q('record-share')).toBeNull();
    expect(hasPrivilege).toHaveBeenCalledWith('system.admin');
  });

  it('offers Assign and Share on one record to an admin', () => {
    admin = true;
    const { q } = render(['r1']);
    expect(q('record-assign')).not.toBeNull();
    expect(q('record-share')).not.toBeNull();
  });

  it('offers Assign only for a selection, or when Share is turned off', () => {
    admin = true;
    expect(render(['r1', 'r2']).q('record-share')).toBeNull();
    const single = render(['r1'], false);
    expect(single.q('record-share')).toBeNull();
    expect(single.q('record-assign')).not.toBeNull();
  });

  it('forwards a change from the dialog to the host', () => {
    admin = true;
    const { fixture } = render(['r1']);
    const cmp = fixture.componentInstance;
    const changed = vi.fn();
    cmp.changed.subscribe(changed);
    cmp.open('assign');
    expect(cmp.mode()).toBe('assign');
    cmp.onClosed(false);
    expect(changed).not.toHaveBeenCalled();
    cmp.open('share');
    cmp.onClosed(true);
    expect(cmp.mode()).toBeNull();
    expect(changed).toHaveBeenCalledTimes(1);
  });
});
