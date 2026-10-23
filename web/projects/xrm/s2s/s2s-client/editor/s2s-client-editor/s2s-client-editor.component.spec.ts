import { TestBed } from '@angular/core/testing';
import { EMPTY, of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { S2sAdminService } from '../../../services/s2s-admin.service';
import { S2sClientEditorComponent } from './s2s-client-editor.component';

describe('S2sClientEditorComponent route input', () => {
  const getClient = vi.fn(() => EMPTY);
  const listLogs = vi.fn(() => EMPTY);

  beforeEach(() => {
    getClient.mockClear();
    listLogs.mockClear();
    TestBed.configureTestingModule({
      imports: [S2sClientEditorComponent],
      providers: [{ provide: S2sAdminService, useValue: { getClient, listLogs } }],
    });
    TestBed.overrideComponent(S2sClientEditorComponent, { set: { template: '' } });
  });

  it('loads client metadata and logs from the route-bound id input', () => {
    const fixture = TestBed.createComponent(S2sClientEditorComponent);
    fixture.componentRef.setInput('id', 'client-1');

    fixture.detectChanges();

    expect(getClient).toHaveBeenCalledWith('client-1');
    expect(listLogs).toHaveBeenCalledWith('client-1');
  });

  it('sends the act-as grant when saving', () => {
    const client = {
      id: 'client-1', client_id: 'c', name: 'C', description: null, status: 'active',
      service_user_ref: null, rate_limit_rpm: 60, max_concurrent: 2, allowed_cidrs: null,
      max_payload_bytes: 1, auto_disable_days: 90, can_act_as_user: true, oauth_public_key_set: false, oauth_scopes: ["records.read"], last_used_at: null,
      row_version: 3, created_at: '', updated_at: '', keys: [], permissions: [],
    };
    getClient.mockReturnValueOnce(of(client) as never);
    const updateClient = vi.fn(() => EMPTY);
    TestBed.overrideProvider(S2sAdminService, { useValue: { getClient, listLogs, updateClient } });
    const fixture = TestBed.createComponent(S2sClientEditorComponent);
    fixture.componentRef.setInput('id', 'client-1');
    fixture.detectChanges();

    expect(fixture.componentInstance.editCanActAs).toBe(true);
    fixture.componentInstance.editCanActAs = false;
    fixture.componentInstance.saveMeta();
    expect(updateClient).toHaveBeenCalledWith(
      'client-1',
      expect.objectContaining({ can_act_as_user: false, oauth_scopes: ["records.read"], row_version: 3 }),
    );
  });
});
