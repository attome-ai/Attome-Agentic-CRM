import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { AuthService, LangService, ThemeService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  COMPONENT_MODULE_LOADER, CustomComponentHostComponent, propertyValue, scriptModuleLoader,
} from './custom-component-host.component';
import { PageContext } from './page-context';
import { ComponentView, PageDataService } from './page-data.service';

const ID = '0190a8a0-0000-7000-8000-0000000000c1';

class GaugeElement extends HTMLElement {
  recordId: unknown;
  limit: unknown;
  warnAt: unknown;
}
if (!customElements.get('test-credit-gauge')) customElements.define('test-credit-gauge', GaugeElement);

class BrokenElement extends HTMLElement {
  set recordId(_value: unknown) { throw new Error('broken setter'); }
}
if (!customElements.get('test-broken-gauge')) customElements.define('test-broken-gauge', BrokenElement);

const view = (patch: Partial<ComponentView> = {}): ComponentView => ({
  id: ID, name: 'credit_gauge', tag: 'test-credit-gauge', module: 'com.example.credit/gauge.js',
  module_url: '/api/v1/packages/com.example.credit/files?path=gauge.js', integrity: 'sha256-abc',
  properties: [
    { name: 'recordId', type: 'record_id', bind: 'record_id' },
    { name: 'limit', type: 'number', bind: 'field_value' },
    { name: 'warnAt', type: 'number', default: 0.8 },
  ],
  events: [], label_en: 'Credit gauge', label_ar: 'مؤشر الائتمان',
  ...patch,
});

describe('propertyValue (T3-T2)', () => {
  const bound = { recordId: 'r1', record: { credit_limit: 5000, limit: 10 }, entity: 'account', userId: 'u1', theme: 'dark' as const };

  it('binds, then takes the builder value, then the default', () => {
    expect(propertyValue({ name: 'recordId', bind: 'record_id' }, {}, bound)).toBe('r1');
    expect(propertyValue({ name: 'e', bind: 'entity_name' }, {}, bound)).toBe('account');
    expect(propertyValue({ name: 'u', bind: 'user_id' }, {}, bound)).toBe('u1');
    expect(propertyValue({ name: 't', bind: 'theme' }, {}, bound)).toBe('dark');
    expect(propertyValue({ name: 'limit', bind: 'field_value' }, {}, bound)).toBe(10);
    expect(propertyValue({ name: 'limit', bind: 'field_value' }, { fields: { limit: 'credit_limit' } }, bound)).toBe(5000);
    expect(propertyValue({ name: 'warnAt', default: 0.8 }, { warnAt: 0.9 }, bound)).toBe(0.9);
    expect(propertyValue({ name: 'warnAt', default: 0.8 }, {}, bound)).toBe(0.8);
  });
});

describe('scriptModuleLoader (T3-T2)', () => {
  it('adds one module script with its integrity per URL', async () => {
    const load = scriptModuleLoader(document);
    const url = `/api/v1/packages/com.example.a/files?path=a.js&n=${Math.random()}`;
    const first = load(url, 'sha256-xyz');
    const second = load(url, 'sha256-xyz');
    const scripts = [...document.head.querySelectorAll('script')].filter(s => s.src.endsWith(url.split('/').pop()!));
    expect(scripts.length).toBe(1);
    expect(scripts[0].type).toBe('module');
    expect(scripts[0].integrity).toBe('sha256-xyz');
    scripts[0].dispatchEvent(new Event('load'));
    await expect(first).resolves.toBeUndefined();
    await expect(second).resolves.toBeUndefined();
  });

  it('rejects when the module does not load', async () => {
    const load = scriptModuleLoader(document);
    const url = `/api/v1/packages/com.example.b/files?path=b.js&n=${Math.random()}`;
    const pending = load(url, 'sha256-bad');
    const script = [...document.head.querySelectorAll('script')].find(s => s.src.endsWith(url.split('/').pop()!))!;
    script.dispatchEvent(new Event('error'));
    await expect(pending).rejects.toThrow();
  });
});

describe('CustomComponentHostComponent (T3-T2)', () => {
  let component: ReturnType<typeof vi.fn>;
  let loader: ReturnType<typeof vi.fn>;
  let ctx: PageContext;

  beforeEach(() => {
    component = vi.fn(() => of(view()));
    loader = vi.fn(() => Promise.resolve());
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      imports: [CustomComponentHostComponent],
      providers: [
        PageContext,
        { provide: PageDataService, useValue: { component } },
        { provide: COMPONENT_MODULE_LOADER, useValue: loader },
        { provide: AuthService, useValue: { userId: signal('u1') } },
        { provide: ThemeService, useValue: { isDark: signal(false) } },
        { provide: LangService, useValue: { translate: (k: string) => k, isRtl: () => false } },
      ],
    });
    ctx = TestBed.inject(PageContext);
    ctx.recordId.set('r1');
    ctx.record.set({ limit: 7000 });
  });

  async function render(id = ID) {
    const fixture = TestBed.createComponent(CustomComponentHostComponent);
    fixture.componentRef.setInput('componentId', id);
    fixture.componentRef.setInput('props', { warnAt: 0.9 });
    fixture.detectChanges();
    await fixture.whenStable();
    await new Promise(resolve => setTimeout(resolve, 0));
    fixture.detectChanges();
    return fixture;
  }

  it('renders the element in a shadow root with its bound and set properties', async () => {
    const fixture = await render();
    expect(loader).toHaveBeenCalledWith(view().module_url, 'sha256-abc');
    const mount = fixture.nativeElement.querySelector('.cch-mount') as HTMLElement;
    const element = mount.shadowRoot?.querySelector('test-credit-gauge') as GaugeElement | null;
    expect(element).not.toBeNull();
    expect(element!.recordId).toBe('r1');
    expect(element!.limit).toBe(7000);
    expect(element!.warnAt).toBe(0.9);
    expect(fixture.nativeElement.querySelector('[data-component-error]')).toBeNull();
    // Nothing of the component is in the page's own DOM.
    expect(fixture.nativeElement.querySelector('test-credit-gauge')).toBeNull();
  });

  it('follows the page: a new record reaches the element', async () => {
    const fixture = await render();
    ctx.recordId.set('r2');
    fixture.detectChanges();
    await fixture.whenStable();
    const mount = fixture.nativeElement.querySelector('.cch-mount') as HTMLElement;
    expect((mount.shadowRoot!.querySelector('test-credit-gauge') as GaugeElement).recordId).toBe('r2');
  });

  it('shows the error box when no installed package carries the module', async () => {
    component.mockReturnValue(of(view({ module_url: null, integrity: null })));
    const fixture = await render();
    expect(loader).not.toHaveBeenCalled();
    expect(fixture.nativeElement.querySelector('[data-component-error]')).not.toBeNull();
  });

  it('shows the error box when the module does not load', async () => {
    loader.mockReturnValue(Promise.reject(new Error('integrity')));
    const fixture = await render();
    expect(fixture.nativeElement.querySelector('[data-component-error]')).not.toBeNull();
  });

  it('shows the error box when the component is not published', async () => {
    component.mockReturnValue(throwError(() => ({ status: 404 })));
    const fixture = await render();
    expect(fixture.nativeElement.querySelector('[data-component-error]')).not.toBeNull();
  });

  it('a component that throws breaks only its own box', async () => {
    component.mockReturnValue(of(view({ tag: 'test-broken-gauge' })));
    const fixture = await render();
    expect(fixture.nativeElement.querySelector('[data-component-error]')).not.toBeNull();
  });
});
