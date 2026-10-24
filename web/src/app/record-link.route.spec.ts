import { Component, signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { ATTOME_CONFIG, AuthService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it } from 'vitest';

import { RECORD_LINK_ROUTE } from './record-link.route';

@Component({ standalone: true, template: '' })
class BlankComponent {}

async function follow(loggedIn: boolean, url: string): Promise<string> {
  TestBed.resetTestingModule();
  TestBed.configureTestingModule({
    providers: [
      provideRouter([
        RECORD_LINK_ROUTE,
        { path: 'login', component: BlankComponent },
        { path: 'xrm/entity/:entity/form', component: BlankComponent },
        { path: '', component: BlankComponent },
      ]),
      { provide: AuthService, useValue: { sessionReady: () => of(true), isLoggedIn: signal(loggedIn) } },
      { provide: ATTOME_CONFIG, useValue: { apiUrl: '', loginRoute: '/login' } },
    ],
  });
  const router = TestBed.inject(Router);
  await router.navigateByUrl(url);
  return router.url;
}

describe('record link (B16-T11)', () => {
  it('deep link requires auth', async () => {
    expect(await follow(false, '/r/contact/0192f0a0-0000-7000-8000-000000000001'))
      .toBe('/login?returnUrl=%2Fr%2Fcontact%2F0192f0a0-0000-7000-8000-000000000001');
  });

  it('opens the record once signed in, and refuses a malformed entity', async () => {
    expect(await follow(true, '/r/contact/abc')).toBe('/xrm/entity/contact/form?id=abc');
    expect(await follow(true, '/r/Not-An-Entity/abc')).toBe('/');
  });
});
