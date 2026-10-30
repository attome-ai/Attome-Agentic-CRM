import { Component, signal } from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule } from '@angular/forms';
import { TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { HttpEventType } from '@angular/common/http';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { CurrencyService, LangService } from '@attome/base';
import { FieldInputComponent, fromLocalDateTimeInput, toLocalDateTimeInput } from './field-input.component';
import { EntityService } from '../../services/entity.service';
import { FileUploadService } from '../file-upload.service';
import {
  XRM_FIELD_POLICY, type FieldLockState, type FieldRuleMessage, type XrmFieldPolicy,
} from '../../business-rules/field-policy';
import { FieldSchema } from '@attome/xrm';

// `FieldInputComponent` injects `CurrencyService` unconditionally (every
// field type, same as `FileUploadService`) — the real service needs
// `ATTOME_CONFIG`/`HttpClient`, neither provided in these describe blocks, so
// every TestBed configuration below mocks it instead.
const MOCK_CURRENCY_SERVICE = {
  currencies: signal([{ code: 'USD', decimals: 2, symbol: '$', name: 'US Dollar', is_base: true }]),
  baseCurrency: signal('USD'),
  info: (code?: string | null) => ({ code: code ?? 'USD', decimals: 2, symbol: '$', name: 'US Dollar' }),
  decimals: () => 2,
  format: (n: number, code?: string | null) => `${n.toFixed(2)} ${code ?? 'USD'}`,
};

const FILE_FIELD: FieldSchema = {
  id: 'f1', entity_id: 'e1', name: 'resume', display_name: 'Resume',
  field_type: 'file', options: null, sort_order: 0, is_required: false,
};

function textField(name: string, options: FieldSchema['options'] = null): FieldSchema {
  return {
    id: 'ft', entity_id: 'e1', name, display_name: name,
    field_type: 'text', options, sort_order: 0, is_required: false,
  };
}

@Component({
  standalone: true,
  imports: [ReactiveFormsModule, FieldInputComponent],
  template: `
    <form [formGroup]="form">
      <attome-field-input [field]="field" />
    </form>
  `,
})
class TextHostComponent {
  field!: FieldSchema;
  form = new FormGroup({});
}

// C-29 (M01 §7) — `textType()` used to infer email/tel/url purely from the
// field's *name*; it now prefers the field's own `TextOptions.text_type`
// metadata (attome-field's additive `options` field, no new column) and falls
// back to the exact same name heuristic only when that metadata is absent —
// so a field created before this option existed keeps behaving exactly as
// it did.
describe('FieldInputComponent — text input type (metadata over name heuristic)', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [TextHostComponent],
      providers: [
        { provide: EntityService, useValue: {} },
        // FieldInputComponent's constructor unconditionally injects
        // FileUploadService regardless of field type — a mock here matches
        // the file-field describe block above rather than letting the real
        // service (and its own ApiService -> ATTOME_CONFIG dependency,
        // unprovided in this describe block) construct.
        { provide: FileUploadService, useValue: {} },
        { provide: CurrencyService, useValue: MOCK_CURRENCY_SERVICE },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
  });

  function fieldInputFor(field: FieldSchema): FieldInputComponent {
    const fixture = TestBed.createComponent(TextHostComponent);
    fixture.componentInstance.field = field;
    fixture.componentInstance.form.addControl(field.name, new FormControl(''));
    fixture.detectChanges();
    return fixture.debugElement.query(By.directive(FieldInputComponent))
      .componentInstance as FieldInputComponent;
  }

  it('prefers explicit text_type metadata even when the field name would heuristically resolve differently', () => {
    // 'phone' alone would resolve to 'tel' by name — text_type wins anyway.
    const field = fieldInputFor(textField('phone', { text_type: 'email' }));
    expect(field.textType()).toBe('email');
  });

  it('falls back to the name heuristic when no text_type is set (untouched deployment)', () => {
    expect(fieldInputFor(textField('contact_email')).textType()).toBe('email');
    expect(fieldInputFor(textField('phone')).textType()).toBe('tel');
    expect(fieldInputFor(textField('website')).textType()).toBe('url');
    expect(fieldInputFor(textField('description')).textType()).toBe('text');
  });

  it('ignores text_type on a non-text field type', () => {
    const field = fieldInputFor({
      id: 'fc', entity_id: 'e1', name: 'status', display_name: 'Status',
      field_type: 'choice', options: { choices: ['a'], multi: false } as never,
      sort_order: 0, is_required: false,
    });
    expect(field.textType()).toBe('text');
  });
});

const SESSION_ID_36 = '00000000-0000-0000-0000-000000000000';

@Component({
  standalone: true,
  imports: [ReactiveFormsModule, FieldInputComponent],
  template: `
    <form [formGroup]="form">
      <attome-field-input [field]="field" [entityName]="entityName" [recordId]="recordId" />
    </form>
  `,
})
class HostComponent {
  field = FILE_FIELD;
  entityName: string | null = 'contact';
  recordId: string | null = 'rec-1';
  form = new FormGroup({ resume: new FormControl<string | null>(null) });
}

function makeFile(): File {
  return new File(['hello'], 'cv.pdf', { type: 'application/pdf' });
}

interface MockFileUploadService {
  createSession:   ReturnType<typeof vi.fn>;
  putToStorage:    ReturnType<typeof vi.fn>;
  finalize:        ReturnType<typeof vi.fn>;
  getStatus:       ReturnType<typeof vi.fn>;
  getDownloadUrl:  ReturnType<typeof vi.fn>;
}

describe('FieldInputComponent — file field (P-file-upload-pipeline, D-144)', () => {
  let fileSvc: MockFileUploadService;

  beforeEach(() => {
    fileSvc = {
      createSession:  vi.fn(),
      putToStorage:   vi.fn(),
      finalize:       vi.fn(),
      getStatus:      vi.fn(),
      getDownloadUrl: vi.fn(),
    };
    TestBed.configureTestingModule({
      imports: [HostComponent],
      providers: [
        { provide: FileUploadService, useValue: fileSvc },
        { provide: EntityService, useValue: {} },
        { provide: CurrencyService, useValue: MOCK_CURRENCY_SERVICE },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
  });

  function createFixture(entityName: string | null = 'contact', recordId: string | null = 'rec-1') {
    const fixture = TestBed.createComponent(HostComponent);
    fixture.componentInstance.entityName = entityName;
    fixture.componentInstance.recordId = recordId;
    fixture.detectChanges();
    const field = fixture.debugElement.query(By.directive(FieldInputComponent))
      .componentInstance as FieldInputComponent;
    return { fixture, field };
  }

  it('gates the upload control until the record has been saved (a session needs an existing record_id)', () => {
    const { fixture } = createFixture(null, null);
    expect(fixture.nativeElement.textContent).toContain('Save the record before attaching a file');
    expect(fixture.nativeElement.querySelector('input[type="file"]')).toBeNull();
  });

  it('runs create-session -> PUT -> finalize -> poll -> clean and writes final_key onto the control', async () => {
    const finalKey = `contact/rec-1/resume/${SESSION_ID_36}-cv.pdf`;
    const { fixture, field } = createFixture();
    fileSvc.createSession.mockReturnValue(of({
      session_id: SESSION_ID_36, upload_url: 'http://storage/x', expires_in_secs: 900,
    }));
    fileSvc.putToStorage.mockReturnValue(of({ type: HttpEventType.Response }));
    fileSvc.finalize.mockReturnValue(of({ session_id: SESSION_ID_36, status: 'uploaded' }));
    fileSvc.getStatus.mockReturnValue(of({
      status: 'clean', reject_reason: null, actual_size_bytes: 5,
      actual_content_type: 'application/pdf', final_key: finalKey,
    }));

    await field.onFileSelected([makeFile()] as unknown as FileList);

    expect(fileSvc.createSession).toHaveBeenCalledWith(
      'contact', 'rec-1', 'resume',
      expect.objectContaining({ filename: 'cv.pdf', declared_size_bytes: 5 }),
    );
    expect(fileSvc.finalize).toHaveBeenCalledWith('contact', 'rec-1', 'resume', SESSION_ID_36);
    expect(field.fileState()).toBe('idle');
    expect(fixture.componentInstance.form.get('resume')!.value).toBe(finalKey);
    expect(fixture.componentInstance.form.get('resume')!.dirty).toBe(true);
  });

  it('surfaces a rejection when finalize rejects the upload (declared size/type mismatch) without polling', async () => {
    const { field } = createFixture();
    fileSvc.createSession.mockReturnValue(of({
      session_id: 's1', upload_url: 'http://storage/x', expires_in_secs: 900,
    }));
    fileSvc.putToStorage.mockReturnValue(of({ type: HttpEventType.Response }));
    fileSvc.finalize.mockReturnValue(of({ session_id: 's1', status: 'rejected' }));

    await field.onFileSelected([makeFile()] as unknown as FileList);

    expect(field.fileState()).toBe('rejected');
    expect(fileSvc.getStatus).not.toHaveBeenCalled();
  });

  it('surfaces the async scan job reject_reason once polling settles as rejected', async () => {
    const { field } = createFixture();
    fileSvc.createSession.mockReturnValue(of({
      session_id: 's1', upload_url: 'http://storage/x', expires_in_secs: 900,
    }));
    fileSvc.putToStorage.mockReturnValue(of({ type: HttpEventType.Response }));
    fileSvc.finalize.mockReturnValue(of({ session_id: 's1', status: 'uploaded' }));
    fileSvc.getStatus.mockReturnValue(of({
      status: 'rejected', reject_reason: 'rejected', actual_size_bytes: null,
      actual_content_type: null, final_key: null,
    }));

    await field.onFileSelected([makeFile()] as unknown as FileList);

    expect(field.fileState()).toBe('rejected');
    expect(field.fileMessage()).toBe('rejected');
  });

  it('surfaces an error message when the storage PUT itself fails', async () => {
    const { field } = createFixture();
    fileSvc.createSession.mockReturnValue(of({
      session_id: 's1', upload_url: 'http://storage/x', expires_in_secs: 900,
    }));
    fileSvc.putToStorage.mockImplementation(() => {
      throw new Error('network down');
    });

    await field.onFileSelected([makeFile()] as unknown as FileList);

    expect(field.fileState()).toBe('error');
  });

  it('does not offer a download for a locally-pending value not yet persisted on the record', () => {
    const { fixture, field } = createFixture();
    fixture.componentInstance.form.get('resume')!.setValue('contact/rec-1/resume/key');
    fixture.detectChanges();

    expect(field.canDownload()).toBe(false);
    expect(fixture.nativeElement.textContent).toContain('Save the record to keep this file');
  });

  it('offers a download for the value the record already had at load time', () => {
    const fixture = TestBed.createComponent(HostComponent);
    fixture.componentInstance.form.get('resume')!.setValue('contact/rec-1/resume/existing-key');
    fixture.detectChanges(); // ngOnInit runs with this already-persisted value
    const field = fixture.debugElement.query(By.directive(FieldInputComponent))
      .componentInstance as FieldInputComponent;

    expect(field.canDownload()).toBe(true);
  });

  it('resolves a presigned download URL and opens it in a new tab', () => {
    const { fixture } = createFixture();
    fixture.componentInstance.form.get('resume')!.setValue('contact/rec-1/resume/existing-key');
    fixture.detectChanges();
    const field = fixture.debugElement.query(By.directive(FieldInputComponent))
      .componentInstance as FieldInputComponent;
    // Re-init so fileInitialValue matches the value set above (ngOnInit already
    // ran against the original null value in createFixture's own detectChanges).
    field.ngOnInit();
    fileSvc.getDownloadUrl.mockReturnValue(of({ download_url: 'http://storage/dl', expires_in_secs: 900 }));
    const openSpy = vi.spyOn(window, 'open').mockImplementation(() => null);

    field.downloadFile();

    expect(fileSvc.getDownloadUrl).toHaveBeenCalledWith('contact', 'rec-1', 'resume');
    expect(openSpy).toHaveBeenCalledWith('http://storage/dl', '_blank', 'noopener');
  });

  it('clears a file value and marks the control dirty', () => {
    const { fixture, field } = createFixture();
    fixture.componentInstance.form.get('resume')!.setValue('contact/rec-1/resume/key');

    field.clearFile();

    expect(fixture.componentInstance.form.get('resume')!.value).toBeNull();
    expect(fixture.componentInstance.form.get('resume')!.dirty).toBe(true);
    expect(field.fileState()).toBe('idle');
  });
});

// U9 (D-604, D-605) — formula (read-only), rich text (editor), image (picker).
describe('FieldInputComponent — U9 field types', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [TextHostComponent],
      providers: [
        { provide: EntityService, useValue: {} },
        { provide: FileUploadService, useValue: { getDownloadUrl: vi.fn(() => of({ download_url: 'u' })) } },
        { provide: CurrencyService, useValue: MOCK_CURRENCY_SERVICE },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
  });

  function render(field: FieldSchema, control: FormControl) {
    const fixture = TestBed.createComponent(TextHostComponent);
    fixture.componentInstance.field = field;
    fixture.componentInstance.form.addControl(field.name, control);
    fixture.detectChanges();
    return fixture;
  }

  function field(name: string, fieldType: FieldSchema['field_type'], options: FieldSchema['options'] = null): FieldSchema {
    return {
      id: name, entity_id: 'e1', name, display_name: name,
      field_type: fieldType, options, sort_order: 0, is_required: false,
    };
  }

  it('shows a formula read-only, formatted for its result type, with its expression', () => {
    const control = new FormControl({ value: 1234.5 as unknown, disabled: true });
    const fixture = render(
      field('total', 'formula', { expression: 'quantity * unit_price', result_type: 'number' }),
      control,
    );
    const el = fixture.nativeElement as HTMLElement;
    const output = el.querySelector('output.formula-value') as HTMLOutputElement;
    expect(output.textContent?.trim()).toBe((1234.5).toLocaleString());
    expect(el.querySelector('input')).toBeNull();
    expect(el.textContent).toContain('fieldInput.formulaHint');

    control.setValue(null);
    fixture.detectChanges();
    expect(output.textContent?.trim()).toBe('fieldInput.formulaEmpty');
  });

  it('edits rich text with the allow-listed editor', () => {
    const fixture = render(field('notes', 'rich_text'), new FormControl('<p>x</p>'));
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('xrm-rich-text-editor')).not.toBeNull();
    expect(el.querySelector('.rte-surface')?.innerHTML).toBe('<p>x</p>');
  });

  it('uploads an image with the image picker', () => {
    const fixture = render(field('photo', 'image'), new FormControl(null));
    expect((fixture.nativeElement as HTMLElement).querySelector('xrm-image-upload')).not.toBeNull();
  });
});

// D-789 section 5 — `attome-field-input` honours the business-rule policy the
// enclosing `<xrm-base-form>` provides through `XRM_FIELD_POLICY`.
@Component({
  standalone: true,
  imports: [ReactiveFormsModule, FieldInputComponent],
  template: `
    <form [formGroup]="form">
      <attome-field-input [field]="field" />
    </form>
  `,
})
class PolicyHostComponent {
  field!: FieldSchema;
  form = new FormGroup({ amount: new FormControl<unknown>(5) });
}

describe('FieldInputComponent — business-rule policy (D-789)', () => {
  const lockSig = signal<FieldLockState | null>(null);
  const messagesSig = signal<readonly FieldRuleMessage[]>([]);
  const serverErrorSig = signal<string | null>(null);
  const requiredLockedSig = signal(false);
  const policy: XrmFieldPolicy = {
    lock: () => lockSig(),
    ruleErrors: () => messagesSig(),
    serverError: () => serverErrorSig(),
    requiredLocked: () => requiredLockedSig(),
    value: () => 5,
  };

  beforeEach(() => {
    lockSig.set(null);
    messagesSig.set([]);
    serverErrorSig.set(null);
    requiredLockedSig.set(false);
    TestBed.configureTestingModule({
      imports: [PolicyHostComponent],
      providers: [
        { provide: EntityService, useValue: {} },
        { provide: FileUploadService, useValue: {} },
        { provide: CurrencyService, useValue: MOCK_CURRENCY_SERVICE },
        { provide: LangService, useValue: { translate: (key: string) => key } },
        { provide: XRM_FIELD_POLICY, useValue: policy },
      ],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(PolicyHostComponent);
    fixture.componentInstance.field = {
      id: 'a', entity_id: 'e1', name: 'amount', display_name: 'Amount',
      field_type: 'number', options: null, sort_order: 0, is_required: true,
    };
    fixture.detectChanges();
    return fixture;
  }

  it('renders the ordinary input when no rule applies', () => {
    const el = render().nativeElement as HTMLElement;
    expect(el.querySelector('input[type="number"]')).not.toBeNull();
    expect(el.querySelector('.xf-lock-note')).toBeNull();
  });

  it('renders nothing for a hidden field', () => {
    lockSig.set({ effect: 'hidden', ruleName: 'Closed deals' });
    const fixture = render();
    const host = (fixture.nativeElement as HTMLElement).querySelector('attome-field-input') as HTMLElement;
    expect(host.querySelector('.xf-field')).toBeNull();
    expect(host.style.display).toBe('none');
  });

  it('renders a disabled field read-only with a lock naming the rule', () => {
    lockSig.set({ effect: 'disabled', ruleName: 'Closed deals' });
    const el = render().nativeElement as HTMLElement;
    expect(el.querySelector('input[type="number"]')).toBeNull();
    const out = el.querySelector('output.xf-locked-value') as HTMLOutputElement;
    expect(out.textContent?.trim()).toBe((5).toLocaleString());
    expect(out.getAttribute('aria-describedby')).toBe('amount-lock');
    expect(el.querySelector('#amount-lock')?.textContent).toContain('fieldPolicy.lockedBy');
  });

  it('follows the policy live: unlocking brings the input back', () => {
    lockSig.set({ effect: 'disabled', ruleName: 'R' });
    const fixture = render();
    lockSig.set(null);
    fixture.detectChanges();
    expect((fixture.nativeElement as HTMLElement).querySelector('input[type="number"]')).not.toBeNull();
  });

  it('shows rule messages, a save refusal, and required-but-locked', () => {
    messagesSig.set([{ message: 'Too large', severity: 'error', ruleName: 'R' }]);
    serverErrorSig.set("'amount' is locked by the rule 'R' and cannot be changed");
    lockSig.set({ effect: 'disabled', ruleName: 'R' });
    requiredLockedSig.set(true);
    const el = render().nativeElement as HTMLElement;
    expect(el.querySelector('.xf-rule-message')?.textContent).toContain('Too large');
    expect(el.querySelector('[data-testid="field-server-error"]')?.textContent).toContain('locked by the rule');
    expect(el.textContent).toContain('fieldPolicy.requiredLocked');
  });
});

describe('date_time input values (Y2-T1)', () => {
  it('shows a stored moment in the viewer zone and stores it back as the same instant', () => {
    const stored = '2026-10-25T08:30:00.000Z';
    const shown = toLocalDateTimeInput(stored);
    expect(shown).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/);
    expect(fromLocalDateTimeInput(shown)).toBe(stored);
  });

  it('treats empty and unparseable values safely', () => {
    expect(toLocalDateTimeInput(null)).toBe('');
    expect(toLocalDateTimeInput('not a date')).toBe('');
    expect(fromLocalDateTimeInput('')).toBeNull();
    expect(fromLocalDateTimeInput('nope')).toBeUndefined();
  });
});
