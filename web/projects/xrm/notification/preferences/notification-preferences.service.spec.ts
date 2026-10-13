import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ATTOME_CONFIG } from '@attome/base';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { NotificationPreferencesService } from './notification-preferences.service';

describe('NotificationPreferencesService', () => {
  const API = 'http://localhost:7865';
  const URL = `${API}/api/v1/me/notification-preferences`;
  let service: NotificationPreferencesService;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), { provide: ATTOME_CONFIG, useValue: { apiUrl: API } }],
    });
    service = TestBed.inject(NotificationPreferencesService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('reads the caller\'s own preferences, naming no user', () => {
    service.load().subscribe();
    const req = http.expectOne(URL);
    expect(req.request.method).toBe('GET');
    expect(req.request.params.keys()).toEqual([]);
    req.flush({ categories: [], channels: [], items: [] });
  });

  it('writes the items as the PUT body', () => {
    const items = [{ category: 'reminder', channel: 'email', enabled: false, row_version: null }];
    service.save(items).subscribe();
    const req = http.expectOne(URL);
    expect(req.request.method).toBe('PUT');
    expect(req.request.body).toEqual({ items });
    req.flush({ categories: ['reminder'], channels: ['email'], items: [] });
  });
});
