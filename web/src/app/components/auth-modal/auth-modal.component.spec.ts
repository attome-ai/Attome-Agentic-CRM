import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ApiError, AuthService, LangService } from '@attome/base';
import { Observable, of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthModalService } from '../../services/auth-modal.service';
import { AuthModalComponent } from './auth-modal.component';

/**
 * The public website's sign-in dialog. It is rendered on every route by
 * AppComponent, so the behavior worth pinning is what it does *not* do while
 * closed — no Google config fetch, no script tag, no dismissal handling — plus
 * the credential path, which the GSI SDK invokes directly rather than through
 * any DOM affordance.
 */

// See login.component.spec.ts — the first TestBed fixture in a file runs past
// vitest's 5s default on a cold worker.
vi.setConfig({ testTimeout: 30_000 });

function authStub(overrides: Record<string, unknown> = {}) {
  return {
    getGoogleConfig: vi.fn((): Observable<unknown> => of({ client_id: null })),
    loginWithGoogle: vi.fn((): Observable<unknown> => of({ user_id: 'user-1' })),
    ...overrides,
  };
}

interface Mounted {
  fixture:   ComponentFixture<AuthModalComponent>;
  component: AuthModalComponent;
  modal:     AuthModalService;
  auth:      ReturnType<typeof authStub>;
}

function mount(overrides: Record<string, unknown> = {}): Mounted {
  const auth = authStub(overrides);
  TestBed.configureTestingModule({
    imports: [AuthModalComponent],
    providers: [
      { provide: AuthService, useValue: auth },
      { provide: LangService, useValue: { translate: (key: string) => key, errorText: (e: ApiError) => `errors.${e.kind}` } },
    ],
  });

  const fixture = TestBed.createComponent(AuthModalComponent);
  fixture.detectChanges();
  return { fixture, component: fixture.componentInstance, modal: TestBed.inject(AuthModalService), auth };
}

function open(mounted: Mounted): void {
  mounted.modal.open();
  mounted.fixture.detectChanges();
}

/** The GSI SDK calls this component's callback directly — there is no button to click in jsdom. */
function deliverCredential(component: AuthModalComponent, credential: string): void {
  (component as unknown as { handleCredential(r: { credential: string }): void })
    .handleCredential({ credential });
}

describe('AuthModalComponent', () => {
  beforeEach(() => {
    TestBed.resetTestingModule();
  });

  it('renders nothing and fetches no Google config until it is opened', () => {
    const { fixture, auth } = mount();

    expect(auth.getGoogleConfig).not.toHaveBeenCalled();
    expect(fixture.nativeElement.querySelector('.modal-backdrop')).toBeNull();
  });

  it('fetches the Google config on first open and never again', () => {
    const mounted = mount({ getGoogleConfig: vi.fn(() => of({ client_id: 'google-client-id' })) });

    open(mounted);
    expect(mounted.auth.getGoogleConfig).toHaveBeenCalledTimes(1);
    expect(mounted.fixture.nativeElement.querySelector('.modal-backdrop')).toBeTruthy();

    mounted.component.close();
    mounted.fixture.detectChanges();
    open(mounted);

    expect(mounted.auth.getGoogleConfig).toHaveBeenCalledTimes(1);
  });

  it('closes on Escape only while open', () => {
    const mounted = mount();

    // Escape with the dialog already closed must stay a no-op — the handler is
    // bound to the document, not to the dialog.
    mounted.component.onEscape();
    expect(mounted.modal.isOpen()).toBe(false);

    open(mounted);
    mounted.component.onEscape();

    expect(mounted.modal.isOpen()).toBe(false);
  });

  it('dismisses a backdrop click but not a click inside the card', () => {
    const mounted = mount();
    open(mounted);

    const card = document.createElement('div');
    card.className = 'modal-card';
    mounted.component.closeOnBackdrop({ target: card } as unknown as MouseEvent);
    expect(mounted.modal.isOpen()).toBe(true);

    const backdrop = document.createElement('div');
    backdrop.className = 'modal-backdrop';
    mounted.component.closeOnBackdrop({ target: backdrop } as unknown as MouseEvent);
    expect(mounted.modal.isOpen()).toBe(false);
  });

  it('closes the dialog once a Google credential is accepted', () => {
    const mounted = mount();
    open(mounted);

    deliverCredential(mounted.component, 'jwt-from-gsi');

    expect(mounted.auth.loginWithGoogle).toHaveBeenCalledWith({ credential: 'jwt-from-gsi' });
    expect(mounted.component.loading()).toBe(false);
    expect(mounted.modal.isOpen()).toBe(false);
  });

  it('keeps the dialog open and shows the failure when sign-in is rejected', () => {
    const error: ApiError = { status: 401, kind: 'unauthorized', message: 'that account is disabled' };
    const mounted = mount({ loginWithGoogle: vi.fn(() => throwError(() => error)) });
    open(mounted);

    deliverCredential(mounted.component, 'jwt-from-gsi');
    mounted.fixture.detectChanges();

    // NGB-2.3: the server's English prose is never shown.
    expect(mounted.component.error()).toBe('authModal.googleError');
    expect(mounted.component.loading()).toBe(false);
    expect(mounted.modal.isOpen()).toBe(true);
    expect(mounted.fixture.nativeElement.querySelector('.error-banner').textContent)
      .toContain('authModal.googleError');
  });

  it('clears a previous failure when the dialog is reopened', () => {
    const error: ApiError = { status: 401, kind: 'unauthorized', message: 'that account is disabled' };
    const mounted = mount({ loginWithGoogle: vi.fn(() => throwError(() => error)) });
    open(mounted);
    deliverCredential(mounted.component, 'jwt-from-gsi');

    mounted.component.close();
    mounted.fixture.detectChanges();
    open(mounted);

    expect(mounted.component.error()).toBeNull();
  });
});
