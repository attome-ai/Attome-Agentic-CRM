import { Component } from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule } from '@angular/forms';
import { TestBed } from '@angular/core/testing';
import { By } from '@angular/platform-browser';
import { beforeEach, describe, expect, it } from 'vitest';
import { LangService } from '@attome/base';

import { RichTextEditorComponent } from './rich-text-editor.component';

@Component({
  standalone: true,
  imports: [ReactiveFormsModule, RichTextEditorComponent],
  template: `
    <form [formGroup]="form">
      <xrm-rich-text-editor fieldName="notes" label="Notes" />
    </form>
  `,
})
class HostComponent {
  form = new FormGroup({ notes: new FormControl<string | null>(null) });
}

describe('RichTextEditorComponent', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [HostComponent],
      providers: [{ provide: LangService, useValue: { translate: (key: string) => key } }],
    });
  });

  function create(initial: string | null = null) {
    const fixture = TestBed.createComponent(HostComponent);
    fixture.componentInstance.form.controls.notes.setValue(initial);
    fixture.detectChanges();
    const cmp = fixture.debugElement.query(By.directive(RichTextEditorComponent))
      .componentInstance as RichTextEditorComponent;
    const surface = fixture.nativeElement.querySelector('.rte-surface') as HTMLDivElement;
    return { fixture, cmp, surface, ctrl: fixture.componentInstance.form.controls.notes };
  }

  function select(node: Node): void {
    const range = document.createRange();
    range.selectNodeContents(node);
    const sel = window.getSelection()!;
    sel.removeAllRanges();
    sel.addRange(range);
  }

  it('renders the stored value through Angular\'s sanitizer', () => {
    const { surface } = create('<p>Hi <strong>there</strong></p><script>window.pwned = 1</script>'
      + '<img src="x" onerror="window.pwned = 1">');
    expect(surface.querySelector('strong')?.textContent).toBe('there');
    expect(surface.querySelector('script')).toBeNull();
    expect(surface.innerHTML).not.toContain('onerror');
  });

  it('is a labelled multi-line textbox with a labelled toolbar', () => {
    const { fixture, surface } = create();
    expect(surface.getAttribute('role')).toBe('textbox');
    expect(surface.getAttribute('aria-multiline')).toBe('true');
    expect(surface.getAttribute('aria-label')).toBe('Notes');
    const toolbar = fixture.nativeElement.querySelector('[role="toolbar"]') as HTMLElement;
    expect(toolbar.getAttribute('aria-label')).toBe('fieldInput.richTextToolbar');
    for (const btn of Array.from(toolbar.querySelectorAll('button'))) {
      expect(btn.getAttribute('aria-label')).toBeTruthy();
    }
  });

  it('writes typed content to the control, and an empty editor as null', () => {
    const { surface, ctrl } = create();
    surface.innerHTML = '<p>typed</p>';
    surface.dispatchEvent(new Event('input'));
    expect(ctrl.value).toBe('<p>typed</p>');
    expect(ctrl.dirty).toBe(true);
    surface.innerHTML = '<br>';
    surface.dispatchEvent(new Event('input'));
    expect(ctrl.value).toBeNull();
  });

  it('wraps the selection in <strong> for bold', () => {
    const { cmp, surface, ctrl } = create('<p>make me bold</p>');
    select(surface.querySelector('p')!);
    cmp.wrap('strong');
    expect(surface.querySelector('p strong')?.textContent).toBe('make me bold');
    expect(ctrl.value).toContain('<strong>make me bold</strong>');
  });

  it('turns the selection into a list item', () => {
    const { cmp, surface, ctrl } = create('<p>item</p>');
    select(surface.querySelector('p')!);
    cmp.list('ul');
    expect(surface.querySelector('ul li')?.textContent).toBe('item');
    expect(ctrl.value).toContain('<ul><li>item</li></ul>');
  });

  it('links only to schemes the server keeps', () => {
    const { cmp, fixture, surface, ctrl } = create('<p>site</p>');
    select(surface.querySelector('p')!);
    cmp.openLink();
    fixture.detectChanges();
    cmp.linkUrl.set('javascript:alert(1)');
    cmp.applyLink();
    expect(cmp.linkInvalid()).toBe(true);
    expect(surface.querySelector('a')).toBeNull();

    cmp.linkUrl.set('https://example.com');
    cmp.applyLink();
    expect(surface.querySelector('a')?.getAttribute('href')).toBe('https://example.com');
    expect(ctrl.value).toContain('href="https://example.com"');
  });

  it('re-renders when the host form patches the control', () => {
    const { fixture, surface } = create();
    fixture.componentInstance.form.patchValue({ notes: '<p>loaded</p>' });
    expect(surface.innerHTML).toBe('<p>loaded</p>');
  });
});
