import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { SignPageComponent, SignerView, codeComplete } from './sign-page.component';

const view = (over: Partial<SignerView> = {}): SignerView => ({
  envelope_title: 'NDA', envelope_status: 'sent', signer_name: 'Huda', signer_status: 'notified',
  may_sign: true, documents: [{ document_id: 'd1', name: 'NDA.pdf', sha256: 'ab'.repeat(32) }], ...over,
});

describe('codeComplete (K4-T1)', () => {
  it('needs six digits, Arabic-Indic counted', () => {
    expect(codeComplete('123456')).toBe(true);
    expect(codeComplete('١٢٣٤٥٦')).toBe(true);
    expect(codeComplete('12 34')).toBe(false);
  });
});

describe('SignPageComponent (K4-T1)', () => {
  const api = { get: vi.fn(), post: vi.fn() };
  const current = signal<'en' | 'ar'>('en');

  beforeEach(() => {
    vi.resetAllMocks();
    current.set('en');
    TestBed.configureTestingModule({
      imports: [SignPageComponent],
      providers: [
        { provide: ApiService, useValue: api },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, current, errorText: () => 'failed', isRtl: () => current() === 'ar' },
        },
      ],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(SignPageComponent);
    fixture.componentRef.setInput('token', 'tok.sig');
    fixture.detectChanges();
    TestBed.flushEffects();
    fixture.detectChanges();
    return fixture;
  }

  const q = (root: HTMLElement, id: string) => root.querySelector(`[data-testid="${id}"]`) as HTMLElement;

  it('asks for a code, then signs with the code and typed name', () => {
    api.get.mockReturnValueOnce(of(view())).mockReturnValueOnce(of(view({ signer_status: 'signed', may_sign: false })));
    api.post.mockReturnValueOnce(of({ result: 'code_sent', envelope_status: 'sent' }))
      .mockReturnValueOnce(of({ result: 'signed', envelope_status: 'completed' }));
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    expect(api.get).toHaveBeenCalledWith('/api/v1/esign/sign/tok.sig');

    q(root, 'es-code').click();
    fixture.detectChanges();
    expect(api.post).toHaveBeenCalledWith('/api/v1/esign/sign/tok.sig', { action: 'code' });
    expect(q(root, 'es-code-sent')).not.toBeNull();

    const code = q(root, 'es-code-input') as HTMLInputElement;
    code.value = '123456';
    code.dispatchEvent(new Event('input'));
    const name = q(root, 'es-name') as HTMLInputElement;
    name.value = 'Huda Saleh';
    name.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    q(root, 'es-sign').click();
    fixture.detectChanges();
    expect(api.post).toHaveBeenLastCalledWith('/api/v1/esign/sign/tok.sig',
      { action: 'sign', code: '123456', typed_name: 'Huda Saleh' });
    expect(q(root, 'es-status').textContent).toContain('esignSign.signed');
  });

  it('says when the link is not valid', () => {
    api.get.mockReturnValue(throwError(() => new Error('404')));
    const root: HTMLElement = render().nativeElement;
    expect(q(root, 'es-invalid')).not.toBeNull();
  });

  it('mirrors in Arabic and waits its turn', () => {
    current.set('ar');
    api.get.mockReturnValue(of(view({ may_sign: false, signer_status: 'waiting' })));
    const root: HTMLElement = render().nativeElement;
    expect(q(root, 'es').getAttribute('dir')).toBe('rtl');
    expect(q(root, 'es-status').textContent).toContain('esignSign.notYourTurn');
    expect(q(root, 'es-sign')).toBeNull();
  });
});
