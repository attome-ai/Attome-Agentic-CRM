import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ATTOME_CONFIG, LangService } from '@attome/base';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { MySessionsComponent, type MySession } from './my-sessions.component';

describe('MySessionsComponent', () => {
  const API = 'http://localhost:7865';
  let fixture: ComponentFixture<MySessionsComponent>;
  let http: HttpTestingController;

  const session = (id: string, current: boolean): MySession => ({
    id,
    device_label: 'chrome/windows',
    user_agent: 'Mozilla/5.0',
    sign_in_method: 'password',
    client_kind: 'web',
    created_at: '2026-10-29T08:00:00Z',
    last_activity_at: null,
    is_current: current,
  });

  const page = (items: MySession[]) => ({ items, total: items.length, page: 1, page_size: 200 });
  const el = () => fixture.nativeElement as HTMLElement;
  const list = () => http.expectOne((r) => r.url === `${API}/api/v1/auth/sessions`);

  beforeEach(async () => {
    TestBed.resetTestingModule();
    await TestBed.configureTestingModule({
      imports: [MySessionsComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG, useValue: { apiUrl: API } },
        { provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' } },
      ],
    }).compileComponents();
    http = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(MySessionsComponent);
    fixture.detectChanges();
  });

  afterEach(() => http.verify());

  it('lists the sessions and marks this device without an end button', () => {
    list().flush(page([session('a', true), session('b', false)]));
    fixture.detectChanges();
    const rows = el().querySelectorAll('tbody tr');
    expect(rows.length).toBe(2);
    expect(rows[0].textContent).toContain('mySessions.thisDevice');
    expect(rows[0].querySelector('button')).toBeNull();
    expect(rows[1].querySelector('button')?.textContent).toContain('mySessions.end');
  });

  it('ends one session, then reloads the list', () => {
    list().flush(page([session('a', true), session('b', false)]));
    fixture.detectChanges();
    (el().querySelectorAll('tbody tr')[1].querySelector('button') as HTMLButtonElement).click();
    const req = http.expectOne(`${API}/api/v1/auth/sessions/b`);
    expect(req.request.method).toBe('DELETE');
    req.flush(null, { status: 204, statusText: 'No Content' });
    list().flush(page([session('a', true)]));
    fixture.detectChanges();
    expect(el().querySelectorAll('tbody tr').length).toBe(1);
    expect(el().textContent).not.toContain('mySessions.endOthers');
  });

  it('ends every other session', () => {
    list().flush(page([session('a', true), session('b', false), session('c', false)]));
    fixture.detectChanges();
    const buttons = Array.from(el().querySelectorAll('button'));
    const endOthers = buttons.find((b) => b.textContent?.includes('mySessions.endOthers'));
    endOthers?.click();
    const req = http.expectOne(`${API}/api/v1/auth/sessions/end-others`);
    expect(req.request.method).toBe('POST');
    req.flush(null, { status: 204, statusText: 'No Content' });
    list().flush(page([session('a', true)]));
  });
});
