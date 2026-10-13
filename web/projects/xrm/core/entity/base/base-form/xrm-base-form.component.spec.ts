import { ChangeDetectionStrategy, Component, signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ReactiveFormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ATTOME_CONFIG, LangService } from '@attome/base';
import type { EntitySchema } from '@attome/xrm';
import { EntityService } from '../../services/entity.service';
import { EngineFormBase, type XrmFormTabDef } from '../xrm-form.base';
import { XrmFieldVisibleDirective } from '../../business-rules/field-visible.directive';
import { XrmTabDirective } from './xrm-tab.directive';
import { XrmBaseFormComponent } from './xrm-base-form.component';

const SCHEMA = {
  id: 'e1', name: 'Widget', logical_name: 'widget',
  fields: [{
    id: 'f1', entity_id: 'e1', name: 'name', display_name: 'Name',
    field_type: 'text', options: null, sort_order: 0, is_required: false,
  }],
} as unknown as EntitySchema;

/** A minimal entity form on the base form: one slot of each kind. */
@Component({
  selector: 'xrm-test-widget-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ReactiveFormsModule, XrmBaseFormComponent, XrmTabDirective, XrmFieldVisibleDirective],
  template: `
    <xrm-base-form [form]="this" [formGroup]="form()" idPrefix="widget"
                   [saveDisabled]="locked()" [saveLabel]="saveLabelKey()"
                   [readOnly]="readOnlyMode()" [customTitle]="ownTitle()">
      <ng-template xrmTab="details">
        <p data-testid="details-body">details</p>
        <input data-testid="name-input" formControlName="name" />
        <span *xrmFieldVisible="'name'" data-testid="name-probe">probe</span>
      </ng-template>
      <h1 xrmHeaderTitle class="xf-title" data-testid="own-title">Own title</h1>
      <span xrmHeaderMeta data-testid="meta">meta</span>
      <button xrmHeaderActions type="button" data-testid="extra-action">extra</button>
      <div xrmOperations data-testid="ops">ops</div>
      <ng-template xrmTab="versions"><p data-testid="versions-body">versions</p></ng-template>
      <ng-template xrmTab="undeclared"><p data-testid="undeclared-body">never</p></ng-template>
    </xrm-base-form>
  `,
})
class TestWidgetFormComponent extends EngineFormBase {
  readonly locked = signal(false);
  readonly saveLabelKey = signal<string | null>(null);
  readonly readOnlyMode = signal(false);
  readonly ownTitle = signal(false);
  protected override defineTabs(): XrmFormTabDef[] {
    return [
      { id: 'details', label: 'Details', icon: 'las la-list-alt' },
      { id: 'versions', label: 'Versions', icon: 'las la-code-branch' },
    ];
  }
}

describe('XrmBaseFormComponent (D-773)', () => {
  let svc: { getSchema: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    svc = { getSchema: vi.fn().mockReturnValue(of(SCHEMA)) };
    TestBed.configureTestingModule({
      imports: [TestWidgetFormComponent],
      providers: [
        { provide: EntityService, useValue: svc },
        { provide: Router, useValue: { navigate: vi.fn(), parseUrl: () => ({ queryParamMap: { get: () => null } }), url: '/' } },
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
        // Echoes the key, so assertions target catalog keys (FE-2).
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(TestWidgetFormComponent);
    fixture.componentRef.setInput('name', 'widget');
    fixture.detectChanges();
    return { fixture, host: fixture.componentInstance, el: fixture.nativeElement as HTMLElement };
  }

  it('renders the frame around the form\'s own content, one slot of each kind', () => {
    const { el } = render();
    expect(el.querySelector('.xf-title')?.textContent).toContain('Widget');
    expect(el.querySelector('[data-testid="entity-edit-submit"]')).not.toBeNull();
    expect(el.querySelector('#widget-panel-details [data-testid="details-body"]')).not.toBeNull();
    expect(el.querySelector('.xf-header [data-testid="meta"]')).not.toBeNull();
    expect(el.querySelector('.xf-actions [data-testid="extra-action"]')).not.toBeNull();
    expect(el.querySelector('.xf-body [data-testid="ops"]')).not.toBeNull();
  });

  it('renders a custom tab panel under the prefixed ids, hidden until selected', () => {
    const { fixture, host, el } = render();
    const panel = el.querySelector<HTMLElement>('#widget-panel-versions');
    expect(panel?.querySelector('[data-testid="versions-body"]')).not.toBeNull();
    expect(panel?.hidden).toBe(true);
    expect(el.querySelector('#widget-tab-versions')?.getAttribute('aria-controls')).toBe('widget-panel-versions');

    host.selectTab('versions');
    fixture.detectChanges();
    expect(panel?.hidden).toBe(false);
    expect(el.querySelector<HTMLElement>('#widget-panel-details')?.hidden).toBe(true);
  });

  it('ignores an xrmTab template whose id the form did not declare', () => {
    const { el } = render();
    expect(el.querySelector('[data-testid="undeclared-body"]')).toBeNull();
  });

  it('shows one banner at a time: conflict, then error, then validation', () => {
    const { fixture, host, el } = render();
    host.validationError.set(true);
    host.error.set('boom');
    host.conflict.set(true);
    fixture.detectChanges();
    expect(el.querySelector('[data-testid="version-conflict-alert"]')).not.toBeNull();
    expect(el.querySelectorAll('.xf-error-banner').length).toBe(1);

    host.conflict.set(false);
    fixture.detectChanges();
    expect(el.querySelector('.xf-error-banner')?.textContent).toContain('boom');

    host.error.set(null);
    fixture.detectChanges();
    expect(el.querySelector('[data-testid="entity-validation-alert"]')).not.toBeNull();
  });

  it('applies the form\'s extra save guard and custom save label', () => {
    const { fixture, host, el } = render();
    const submit = () => el.querySelector<HTMLButtonElement>('[data-testid="entity-edit-submit"]')!;
    expect(submit().disabled).toBe(false);          // create mode: savable
    expect(submit().textContent).toContain('xrmForm.create');

    host.locked.set(true);
    host.saveLabelKey.set('widgetForm.publish');
    fixture.detectChanges();
    expect(submit().disabled).toBe(true);
    expect(submit().textContent).toContain('widgetForm.publish');
  });

  it('a read-only form has no Save button', () => {
    const { fixture, host, el } = render();
    host.readOnlyMode.set(true);
    fixture.detectChanges();
    expect(el.querySelector('[data-testid="entity-edit-submit"]')).toBeNull();
    expect(el.querySelector('.xf-actions')?.textContent).toContain('xrmForm.back');
  });

  it('replaces the default title with the form\'s own title slot', () => {
    const { fixture, host, el } = render();
    expect(el.querySelector('[data-testid="own-title"]')).toBeNull();
    host.ownTitle.set(true);
    fixture.detectChanges();
    expect(el.querySelector('.xf-header [data-testid="own-title"]')?.textContent).toContain('Own title');
    expect(el.querySelector('.xf-breadcrumb')).toBeNull();
  });

  it('submits through the host form\'s save()', () => {
    const { host, el } = render();
    const save = vi.spyOn(host, 'save').mockImplementation(() => undefined);
    el.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));
    expect(save).toHaveBeenCalledTimes(1);
  });

  it('does not save the host record when a nested form inside it submits', () => {
    const { host, el } = render();
    const save = vi.spyOn(host, 'save').mockImplementation(() => undefined);
    const outer = el.querySelector('form')!;
    const inner = document.createElement('form');
    outer.appendChild(inner);
    inner.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    expect(save).not.toHaveBeenCalled();
  });

  it('marks the first tab while the form has unsaved edits', () => {
    const { fixture, host, el } = render();
    expect(el.querySelector('[data-testid="unsaved-dot"]')).toBeNull();
    host.dirty.set(true);
    fixture.detectChanges();
    expect(el.querySelector('#widget-tab-details [data-testid="unsaved-dot"]')).not.toBeNull();
    expect(el.querySelector('#widget-tab-versions [data-testid="unsaved-dot"]')).toBeNull();
  });

  it('turns off native browser validation on its form', () => {
    const { el } = render();
    expect(el.querySelector('form')!.hasAttribute('novalidate')).toBe(true);
  });

  it('binds projected controls to the host form group through [formGroup] on the element', () => {
    const { fixture, host, el } = render();
    const input = el.querySelector<HTMLInputElement>('[data-testid="name-input"]')!;
    input.value = 'Alpha';
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    expect(host.form().get('name')?.value).toBe('Alpha');
  });

  it('shows the translated schema-failure banner when the schema cannot load', () => {
    svc.getSchema.mockReturnValue(throwError(() => new Error('nope')));
    const { el } = render();
    expect(el.querySelector('.xf-error-banner')?.textContent).toContain('xrmForm.schemaFailed');
    expect(el.querySelector('form')).toBeNull();
  });

  // D-789 section 5 — the base form provides XRM_FIELD_POLICY to its projected content.
  it('hides a field a business rule hides, in projected content too', () => {
    svc.getSchema.mockReturnValue(of({
      ...SCHEMA,
      business_rules: [{
        name: 'always_hide', display_name: null, condition: { all: [] },
        policies: [{ type: 'hidden', field: 'name' }],
      }],
    }));
    const { fixture, host, el } = render();
    fixture.detectChanges();
    expect(el.querySelector('[data-testid="name-probe"]')).toBeNull();
    expect(host.form().get('name')?.disabled).toBe(true);
  });

  it('shows the probe when no rule hides the field', () => {
    const { el } = render();
    expect(el.querySelector('[data-testid="name-probe"]')).not.toBeNull();
  });

  // D-791 rule 6 — write warnings reach the form.
  it('shows the warnings of the last save', () => {
    const { fixture, host, el } = render();
    host.saveWarnings.set([{ rule_id: 'r', rule_name: 'Big deals', message: 'Needs approval' }]);
    fixture.detectChanges();
    const banner = el.querySelector('[data-testid="rule-warnings"]');
    expect(banner?.getAttribute('role')).toBe('status');
    expect(banner?.textContent).toContain('Needs approval');
    expect(banner?.textContent).toContain('fieldPolicy.byRule');
  });
});
