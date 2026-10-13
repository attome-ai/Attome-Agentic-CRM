import { TestBed } from '@angular/core/testing';
import { EMPTY } from 'rxjs';
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
});
