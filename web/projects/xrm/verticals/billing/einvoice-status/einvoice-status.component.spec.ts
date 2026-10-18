import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { signal } from '@angular/core';
import { of, throwError } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { EinvoiceDocument, EinvoiceStatusComponent, zatcaMessages } from './einvoice-status.component';

const REJECTED: EinvoiceDocument = {
  id: 'd1', invoice_id: 'i1', profile: 'standard', status: 'rejected', icv: 7, invoice_hash: 'h', qr: 'q',
  attempts: 1, last_error: 'ZATCA refused the document',
  validation: {
    status: 'ERROR',
    errorMessages: [{ type: 'ERROR', code: 'BR-KSA-37', message: 'The building number must contain 4 digits' }],
    warningMessages: [{ type: 'WARNING', code: 'BR-KSA-08', message: 'Seller identification missing' }],
  },
};

describe('EinvoiceStatusComponent (AG2-T4)', () => {
  function create(get: ReturnType<typeof vi.fn>) {
    TestBed.configureTestingModule({
      imports: [EinvoiceStatusComponent],
      providers: [
        { provide: ApiService, useValue: { get } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en') } },
      ],
    });
    const fixture = TestBed.createComponent(EinvoiceStatusComponent);
    fixture.componentRef.setInput('invoiceId', 'i1');
    fixture.detectChanges();
    return fixture;
  }

  it('shows the status and ZATCA errors before warnings', () => {
    const get = vi.fn(() => of(REJECTED));
    const fixture = create(get);
    expect(get).toHaveBeenCalledWith('/api/v1/billing/invoices/i1/einvoice');
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('section')?.getAttribute('data-status')).toBe('rejected');
    const items = Array.from(el.querySelectorAll('li')).map(li => li.getAttribute('data-kind'));
    expect(items).toEqual(['ERROR', 'WARNING']);
    expect(el.textContent).toContain('BR-KSA-37');
    expect(zatcaMessages({ ...REJECTED, validation: null })).toEqual([]);
  });

  it('stays hidden for an invoice without an e-invoice', () => {
    const fixture = create(vi.fn(() => throwError(() => ({ message: 'not found' }))));
    expect((fixture.nativeElement as HTMLElement).querySelector('section')).toBeNull();
  });
});
