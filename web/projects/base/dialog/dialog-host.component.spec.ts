import { ComponentFixture, TestBed } from '@angular/core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DialogHostComponent } from './dialog-host.component';
import { DialogService } from './dialog.service';
import { ATTOME_CONFIG, pushModal, provideAttomeI18n } from '@attome/base';

/** The compiled component's own style bundle (NGB-3.2/3.4 assertions). */
function hostStyles(): string {
  const cmp = DialogHostComponent as unknown as { ɵcmp?: { styles?: string[] } };
  return (cmp.ɵcmp?.styles ?? []).join('\n');
}

describe('DialogHostComponent', () => {
  let fixture: ComponentFixture<DialogHostComponent>;
  let component: DialogHostComponent;
  let dialogService: DialogService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [DialogHostComponent],
      providers: [
        DialogService,
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
        provideAttomeI18n(),
      ],
    });
    fixture = TestBed.createComponent(DialogHostComponent);
    component = fixture.componentInstance;
    dialogService = TestBed.inject(DialogService);
    fixture.detectChanges();
  });

  afterEach(() => {
    vi.useRealTimers();
    document.body.innerHTML = '';
  });

  it('renders nothing when no dialog is active', () => {
    expect(fixture.nativeElement.querySelector('.attome-dialog-backdrop')).toBeNull();
  });

  it('renders confirm dialog and resolves on confirm button click', async () => {
    const promise = dialogService.confirm({
      title: 'Delete Item',
      message: 'Delete this permanent record?',
      variant: 'danger',
      confirmText: 'Delete',
    });
    fixture.detectChanges();

    const card = fixture.nativeElement.querySelector('.attome-dialog-card');
    expect(card).not.toBeNull();
    expect(card.textContent).toContain('Delete Item');
    expect(card.textContent).toContain('Delete this permanent record?');

    const confirmBtn = fixture.nativeElement.querySelector('.attome-dialog-btn-danger');
    expect(confirmBtn).not.toBeNull();
    expect(confirmBtn.textContent.trim()).toBe('Delete');

    confirmBtn.click();
    fixture.detectChanges();

    const result = await promise;
    expect(result).toBe(true);
  });

  it('renders prompt dialog with stem selection logic', async () => {
    const promise = dialogService.prompt({
      title: 'Rename document',
      value: '07891af1-87c2-4814-a9b4-dcc80af1e09e.webp',
      confirmText: 'Rename',
      selectStem: true,
    });
    fixture.detectChanges();

    const input = fixture.nativeElement.querySelector('.attome-dialog-input') as HTMLInputElement;
    expect(input).not.toBeNull();
    expect(input.value).toBe('07891af1-87c2-4814-a9b4-dcc80af1e09e.webp');

    // Simulate user editing input
    component.onInputChange({ target: { value: 'new_name.webp' } } as unknown as Event);
    fixture.detectChanges();

    component.onSubmitPrompt();
    fixture.detectChanges();

    const result = await promise;
    expect(result).toBe('new_name.webp');
  });

  it('validates prompt input using custom validator', () => {
    dialogService.prompt({
      title: 'New Folder',
      validator: (val: string) => val.includes('/') ? 'No slashes' : null,
    });
    fixture.detectChanges();

    component.onInputChange({ target: { value: 'folder/subfolder' } } as unknown as Event);
    fixture.detectChanges();

    expect(component.promptValidationMessage()).toBe('No slashes');
    expect(component.isPromptSubmittable()).toBe(false);

    component.onInputChange({ target: { value: 'valid_folder' } } as unknown as Event);
    fixture.detectChanges();

    expect(component.promptValidationMessage()).toBeNull();
    expect(component.isPromptSubmittable()).toBe(true);
  });

  it('renders error dialog and closes on dismiss', async () => {
    const promise = dialogService.error({
      title: 'Rename Failed',
      message: 'Could not rename the document.',
    });
    fixture.detectChanges();

    const card = fixture.nativeElement.querySelector('.attome-dialog-card');
    expect(card.textContent).toContain('Rename Failed');
    expect(card.textContent).toContain('Could not rename the document.');

    const closeBtn = fixture.nativeElement.querySelector('.attome-dialog-btn-secondary');
    closeBtn.click();
    fixture.detectChanges();

    await promise;
    expect(dialogService.state()).toBeNull();
  });

  it('closes on escape key', async () => {
    const promise = dialogService.confirm({ message: 'Cancel test' });
    fixture.detectChanges();

    component.onEscape();
    fixture.detectChanges();

    const result = await promise;
    expect(result).toBe(false);
  });

  it('leaves Escape to a modal opened above it (NGB-4.3)', async () => {
    const promise = dialogService.confirm({ message: 'Cancel test' });
    fixture.detectChanges();

    // A step-up prompt opened from inside the dialog's flow is the top-most
    // modal; Escape must close that one, not this dialog underneath it.
    const above = pushModal();
    try {
      component.onEscape();
      fixture.detectChanges();
      expect(dialogService.state()).not.toBeNull();
    } finally {
      above.release();
    }

    component.onEscape();
    fixture.detectChanges();
    await expect(promise).resolves.toBe(false);
  });

  // ── NGB-3.2 — the a11y reference the frontend skill points authors at ──────

  it('names and describes the card, and marks an error as an alertdialog', () => {
    dialogService.confirm({ title: 'Delete Item', message: 'Are you sure?' });
    fixture.detectChanges();

    let card = fixture.nativeElement.querySelector('.attome-dialog-card') as HTMLElement;
    expect(card.getAttribute('role')).toBe('dialog');
    expect(card.getAttribute('aria-modal')).toBe('true');
    const titleId = card.getAttribute('aria-labelledby') as string;
    const messageId = card.getAttribute('aria-describedby') as string;
    expect(titleId).toBeTruthy();
    expect(messageId).toBeTruthy();
    expect((fixture.nativeElement.querySelector('#' + titleId) as HTMLElement).textContent).toContain('Delete Item');
    expect((fixture.nativeElement.querySelector('#' + messageId) as HTMLElement).textContent).toContain('Are you sure?');

    dialogService.close();
    fixture.detectChanges();

    dialogService.error({ message: 'Boom' });
    fixture.detectChanges();
    card = fixture.nativeElement.querySelector('.attome-dialog-card') as HTMLElement;
    expect(card.getAttribute('role')).toBe('alertdialog');
    // ...and it is labelled too, not just role-switched.
    expect((fixture.nativeElement.querySelector('#' + titleId) as HTMLElement).textContent)
      .toContain('Action Failed');
  });

  it('hides the decorative icon from assistive technology', () => {
    dialogService.confirm({ message: 'x' });
    fixture.detectChanges();
    const icon = fixture.nativeElement.querySelector('.attome-dialog-icon-wrapper i') as HTMLElement;
    expect(icon.getAttribute('aria-hidden')).toBe('true');
  });

  it('labels the prompt input (PromptOptions.label, default title)', () => {
    dialogService.prompt({ title: 'Rename document', label: 'New name' });
    fixture.detectChanges();
    let input = fixture.nativeElement.querySelector('.attome-dialog-input') as HTMLInputElement;
    let label = fixture.nativeElement.querySelector('label[for="' + input.id + '"]') as HTMLLabelElement;
    expect(label.textContent.trim()).toBe('New name');

    dialogService.close();
    fixture.detectChanges();

    dialogService.prompt({ title: 'New Folder' });
    fixture.detectChanges();
    input = fixture.nativeElement.querySelector('.attome-dialog-input') as HTMLInputElement;
    label = fixture.nativeElement.querySelector('label[for="' + input.id + '"]') as HTMLLabelElement;
    expect(label.textContent.trim()).toBe('New Folder');
  });

  it('ties a prompt validation error to the input', () => {
    dialogService.prompt({ title: 'New Folder' });
    fixture.detectChanges();
    const input = fixture.nativeElement.querySelector('.attome-dialog-input') as HTMLInputElement;
    expect(input.getAttribute('aria-invalid')).toBeNull();
    expect(input.getAttribute('aria-describedby')).toBeNull();

    component.onInputChange({ target: { value: '   ' } } as unknown as Event);
    fixture.detectChanges();

    expect(input.getAttribute('aria-invalid')).toBe('true');
    const errorId = input.getAttribute('aria-describedby') as string;
    expect(errorId).toBeTruthy();
    const errorEl = fixture.nativeElement.querySelector('#' + errorId) as HTMLElement;
    expect(errorEl.textContent.trim()).toBe(component.promptValidationMessage());
    // NGB-3.3 — the empty-value message is catalog copy now, not a literal.
    expect(component.promptValidationMessage()).toBe('Value cannot be empty.');
  });

  it('falls back to catalog copy for its default strings (NGB-3.3)', () => {
    dialogService.confirm({ message: 'Proceed?' });
    fixture.detectChanges();
    const card = fixture.nativeElement.querySelector('.attome-dialog-card') as HTMLElement;
    expect(card.textContent).toContain('Confirm Action');
    expect(card.textContent).toContain('Cancel');
  });

  it('honours reduced motion and the theme tokens (NGB-3.2 / NGB-3.4)', () => {
    const styles = hostStyles();
    expect(styles).toContain('prefers-reduced-motion');
    // Angular's emulated view encapsulation rewrites `var(--color-x)` to
    // `var(--%NS%color-x)`, so match the token name rather than the literal.
    expect(styles).toMatch(/var\(--(%NS%)?color-bg-alt/);
    expect(styles).toMatch(/var\(--(%NS%)?color-accent/);
  });

  it('traps Tab inside the card and returns focus to the trigger (NGB-3.1)', async () => {
    const trigger = document.createElement('button');
    trigger.textContent = 'open';
    document.body.appendChild(trigger);
    trigger.focus();

    vi.useFakeTimers();
    const promise = dialogService.confirm({ message: 'Trapped?', confirmText: 'OK', cancelText: 'No' });
    fixture.detectChanges();
    await vi.advanceTimersByTimeAsync(60);

    const card = fixture.nativeElement.querySelector('.attome-dialog-card') as HTMLElement;
    expect(card.contains(document.activeElement)).toBe(true);

    // Tab from the last focusable wraps back to the first.
    const buttons = Array.from(card.querySelectorAll('button')) as HTMLButtonElement[];
    buttons[buttons.length - 1].focus();
    const tab = new KeyboardEvent('keydown', { key: 'Tab', bubbles: true, cancelable: true });
    document.activeElement?.dispatchEvent(tab);
    expect(tab.defaultPrevented).toBe(true);
    expect(document.activeElement).toBe(buttons[0]);

    component.onCancel();
    fixture.detectChanges();
    await promise;
    expect(document.activeElement).toBe(trigger);
  });
});
