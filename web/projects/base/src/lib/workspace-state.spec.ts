import { TestBed } from '@angular/core/testing';
import { HttpClient, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ATTOME_CONFIG } from './config';
import {
  WORKSPACE_HEADER, WorkspaceState, workspaceHeaderApplies, workspaceInterceptor,
} from './workspace-state';

const BASE = 'http://localhost:7865';

describe('workspaceInterceptor (T5-T7)', () => {
  let http: HttpClient;
  let httpMock: HttpTestingController;
  let state: WorkspaceState;

  beforeEach(() => {
    sessionStorage.clear();
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([workspaceInterceptor])),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG, useValue: { apiUrl: BASE } },
      ],
    });
    http = TestBed.inject(HttpClient);
    httpMock = TestBed.inject(HttpTestingController);
    state = TestBed.inject(WorkspaceState);
  });

  afterEach(() => {
    httpMock.verify();
    sessionStorage.clear();
  });

  function headerOn(path: string, method: 'GET' | 'POST' = 'GET'): string | null {
    if (method === 'GET') http.get(`${BASE}${path}`).subscribe();
    else http.post(`${BASE}${path}`, {}).subscribe();
    const req = httpMock.expectOne(`${BASE}${path}`);
    const value = req.request.headers.get(WORKSPACE_HEADER);
    req.flush({});
    return value;
  }

  it('names no workspace until one is chosen', () => {
    expect(headerOn('/api/v1/contact')).toBeNull();
  });

  it('names the chosen workspace on reads and writes', () => {
    state.enter({ id: 'ws-1', name: 'Sales rework' });
    expect(headerOn('/api/v1/contact')).toBe('ws-1');
    expect(headerOn('/api/v1/admin/entities', 'POST')).toBe('ws-1');
  });

  it('leaves the workspace and sign-in routes on live', () => {
    state.enter({ id: 'ws-1', name: 'Sales rework' });
    expect(headerOn('/api/v1/admin/workspaces')).toBeNull();
    expect(headerOn('/api/v1/admin/workspaces/ws-1/publish', 'POST')).toBeNull();
    expect(headerOn('/api/v1/auth/session')).toBeNull();
  });

  it('stops naming it after leaving', () => {
    state.enter({ id: 'ws-1', name: 'Sales rework' });
    state.leave();
    expect(state.inside()).toBe(false);
    expect(headerOn('/api/v1/contact')).toBeNull();
  });

  it('keeps the choice across a reload of this tab', () => {
    state.enter({ id: 'ws-2', name: 'Pricing' });
    expect(JSON.parse(sessionStorage.getItem('attome-workspace') ?? 'null')).toEqual({ id: 'ws-2', name: 'Pricing' });
  });

  it('treats a blank id as leaving', () => {
    state.enter({ id: 'ws-1', name: 'Sales rework' });
    state.enter({ id: '  ', name: '' });
    expect(state.active()).toBeNull();
  });
});

describe('workspaceHeaderApplies', () => {
  it('applies to API paths outside the workspace and sign-in routes', () => {
    expect(workspaceHeaderApplies('/api/v1/contact?page=2')).toBe(true);
    expect(workspaceHeaderApplies('/api/v1/admin/workspaces/x/refresh')).toBe(false);
    expect(workspaceHeaderApplies('/api/v1/auth/refresh')).toBe(false);
    expect(workspaceHeaderApplies('/assets/i18n/en.json')).toBe(false);
  });
});
