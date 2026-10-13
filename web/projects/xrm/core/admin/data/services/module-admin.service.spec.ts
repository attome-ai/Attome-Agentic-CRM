import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ATTOME_CONFIG } from '@attome/base';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ModuleAdminService } from './module-admin.service';

describe('ModuleAdminService', () => {
  let service: ModuleAdminService;
  let httpMock: HttpTestingController;

  const API = 'http://localhost:7865';
  const MODULES = `${API}/api/v1/admin/license/modules`;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG, useValue: { apiUrl: API } },
      ],
    });
    service = TestBed.inject(ModuleAdminService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  it('reads the module configuration', () => {
    service.getModuleConfiguration().subscribe();
    const req = httpMock.expectOne(MODULES);
    expect(req.request.method).toBe('GET');
    req.flush({ enabled: true, modules: [] });
  });

  it('writes the module configuration as a PUT of {enabled, modules}', () => {
    service.updateModuleConfiguration(true, ['core', 'workflow']).subscribe();
    const req = httpMock.expectOne(MODULES);
    expect(req.request.method).toBe('PUT');
    expect(req.request.body).toEqual({ enabled: true, modules: ['core', 'workflow'] });
    req.flush({ enabled: true, modules: [{ name: 'core', enabled: true, licensed: true }] });
  });

  it('can disable module gating with an empty module list', () => {
    // Distinguishes "no modules enabled" from "field omitted" — an empty array
    // must survive as an empty array, not be dropped as falsy.
    service.updateModuleConfiguration(false, []).subscribe();
    const req = httpMock.expectOne(MODULES);
    expect(req.request.body).toEqual({ enabled: false, modules: [] });
    req.flush({ enabled: false, modules: [] });
  });

  it('sends session credentials', () => {
    service.getModuleConfiguration().subscribe();
    const req = httpMock.expectOne(MODULES);
    expect(req.request.withCredentials).toBe(true);
    req.flush({ enabled: true, modules: [] });
  });
});
