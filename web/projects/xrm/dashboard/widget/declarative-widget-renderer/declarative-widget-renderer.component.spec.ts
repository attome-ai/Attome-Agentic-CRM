import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { ATTOME_CONFIG, LangService, provideAttomeI18n } from '@attome/base';
import { provideXrmI18n } from '@attome/xrm/core/i18n';

import { DeclarativeWidgetRendererComponent } from './declarative-widget-renderer.component';
import type { DeclarativeWidgetConfig } from './declarative-widget.types';

/**
 * The security test that matters most for M67 Phase 1: a `declarative_widget`
 * config carries admin/viewer-influenced strings (labels, link targets,
 * conditional-color values, row data) that end up in the DOM. This suite
 * proves that no matter how those strings are chosen, they never execute as
 * HTML/script — the whole reason "declarative JSON schema" was chosen over
 * "customer code" for M67 Step 1.
 *
 * Every case here plants a classic injection payload somewhere a real admin
 * or a malicious/compromised upstream config source could put one, renders
 * the component, and asserts:
 *   1. no `<script>`/`<img>`/`<svg>`/event-handler element was actually
 *      created in the DOM (the payload never became markup), and
 *   2. the raw payload text is still present somewhere as inert text (proving
 *      the value really did reach the template, so the first assertion is
 *      not vacuously true because the string never arrived).
 */
describe('DeclarativeWidgetRendererComponent — no HTML injection through config strings', () => {
  afterEach(() => localStorage.clear());

  function render(config: DeclarativeWidgetConfig, rows: Record<string, unknown>[]) {
    TestBed.configureTestingModule({
      imports: [DeclarativeWidgetRendererComponent],
      providers: [
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
        provideAttomeI18n(), provideXrmI18n(),
      ],
    });
    const fixture = TestBed.createComponent(DeclarativeWidgetRendererComponent);
    fixture.componentRef.setInput('config', config);
    fixture.componentRef.setInput('rows', rows);
    fixture.detectChanges();
    return fixture;
  }

  function assertNoLiveMarkup(root: HTMLElement): void {
    expect(root.querySelectorAll('script').length).toBe(0);
    expect(root.querySelectorAll('img').length).toBe(0);
    expect(root.querySelectorAll('svg').length).toBe(0);
    expect(root.querySelectorAll('iframe').length).toBe(0);
    // No element anywhere carries an inline event-handler attribute — proves
    // an attribute-injection payload (e.g. `" onmouseover="...`) never landed
    // as a live attribute either, not just that <script> tags are absent.
    for (const el of Array.from(root.querySelectorAll('*'))) {
      for (const attr of Array.from(el.attributes)) {
        expect(attr.name.startsWith('on')).toBe(false);
      }
    }
  }

  it('a malicious column label renders as inert text, never as markup', () => {
    const payload = '<img src=x onerror="window.__dw_pwned = true">';
    const config: DeclarativeWidgetConfig = {
      query_ref: 'q1',
      columns: [{ field: 'name', label: payload }],
    };
    const fixture = render(config, [{ name: 'Acme' }]);
    const root: HTMLElement = fixture.nativeElement;

    assertNoLiveMarkup(root);
    expect(root.textContent).toContain(payload);
    expect((window as unknown as { __dw_pwned?: boolean }).__dw_pwned).toBeUndefined();
  });

  it('a malicious label_ar renders as inert text when Arabic is active', async () => {
    const payload = '<script>window.__dw_pwned_ar = true</script>';
    const config: DeclarativeWidgetConfig = {
      query_ref: 'q1',
      columns: [{ field: 'name', label: 'Name', label_ar: payload }],
    };
    // Force the Arabic branch of columnLabel() to be exercised.
    TestBed.configureTestingModule({
      imports: [DeclarativeWidgetRendererComponent],
      providers: [
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
        provideAttomeI18n(), provideXrmI18n(),
      ],
    });
    const fixture = TestBed.createComponent(DeclarativeWidgetRendererComponent);
    const lang = TestBed.inject(LangService);
    await lang.set('ar');
    fixture.componentRef.setInput('config', config);
    fixture.componentRef.setInput('rows', [{ name: 'Acme' }]);
    fixture.detectChanges();
    const root: HTMLElement = fixture.nativeElement;

    assertNoLiveMarkup(root);
    expect(root.textContent).toContain(payload);
    expect((window as unknown as { __dw_pwned_ar?: boolean }).__dw_pwned_ar).toBeUndefined();
  });

  it('a malicious row value in a plain text column renders as inert text', () => {
    const payload = '<svg onload="window.__dw_pwned_row = true">';
    const config: DeclarativeWidgetConfig = {
      query_ref: 'q1',
      columns: [{ field: 'note', label: 'Note' }],
    };
    const fixture = render(config, [{ note: payload }]);
    const root: HTMLElement = fixture.nativeElement;

    assertNoLiveMarkup(root);
    expect(root.textContent).toContain(payload);
    expect((window as unknown as { __dw_pwned_row?: boolean }).__dw_pwned_row).toBeUndefined();
  });

  it('a malicious row value inside a badge-formatted column also renders as inert text', () => {
    const payload = '"><script>window.__dw_pwned_badge = true</script>';
    const config: DeclarativeWidgetConfig = {
      query_ref: 'q1',
      columns: [{ field: 'status', label: 'Status', format: { kind: 'badge' } }],
    };
    const fixture = render(config, [{ status: payload }]);
    const root: HTMLElement = fixture.nativeElement;

    assertNoLiveMarkup(root);
    expect(root.querySelector('.dw-cell--badge')?.textContent).toContain(payload);
    expect((window as unknown as { __dw_pwned_badge?: boolean }).__dw_pwned_badge).toBeUndefined();
  });

  it('a javascript: scheme link target is never rendered as a clickable href', () => {
    const config: DeclarativeWidgetConfig = {
      query_ref: 'q1',
      columns: [
        {
          field: 'name',
          label: 'Name',
          link: { kind: 'external', target: 'javascript:window.__dw_pwned_link = true' },
        },
      ],
    };
    const fixture = render(config, [{ name: 'Acme' }]);
    const root: HTMLElement = fixture.nativeElement;

    assertNoLiveMarkup(root);
    // Fail-safe: no <a> at all for an unsafe target, not an <a> with a
    // neutered-but-present javascript: href.
    const anchors = Array.from(root.querySelectorAll('a'));
    for (const a of anchors) {
      expect(a.getAttribute('href')?.toLowerCase().startsWith('javascript:')).not.toBe(true);
    }
    expect(root.textContent).toContain('Acme');
  });

  it('a data: scheme link target is never rendered as a clickable href', () => {
    const config: DeclarativeWidgetConfig = {
      query_ref: 'q1',
      columns: [
        {
          field: 'name',
          label: 'Name',
          link: { kind: 'external', target: 'data:text/html,<script>alert(1)</script>' },
        },
      ],
    };
    const fixture = render(config, [{ name: 'Acme' }]);
    const root: HTMLElement = fixture.nativeElement;

    assertNoLiveMarkup(root);
    expect(root.querySelectorAll('a').length).toBe(0);
  });

  it('a safe https link with a malicious {field} substitution keeps the payload as inert href text, never breaks out of the attribute', () => {
    const config: DeclarativeWidgetConfig = {
      query_ref: 'q1',
      columns: [
        {
          field: 'name',
          label: 'Name',
          link: { kind: 'external', target: 'https://example.com/{name}' },
        },
      ],
    };
    const payload = '"><script>window.__dw_pwned_href = true</script>';
    const fixture = render(config, [{ name: payload }]);
    const root: HTMLElement = fixture.nativeElement;

    assertNoLiveMarkup(root);
    const anchor = root.querySelector('a');
    expect(anchor).not.toBeNull();
    // Property binding, not string concatenation into markup: the whole
    // substituted string is the href VALUE, never parsed as HTML.
    expect(anchor?.getAttribute('href')).toBe(`https://example.com/${payload}`);
    expect((window as unknown as { __dw_pwned_href?: boolean }).__dw_pwned_href).toBeUndefined();
  });

  it('a non-hex conditional-color value is ignored rather than injected into a style attribute', () => {
    const config: DeclarativeWidgetConfig = {
      query_ref: 'q1',
      columns: [
        {
          field: 'amount',
          label: 'Amount',
          conditional_colors: [
            {
              when: { field: 'amount', operator: 'gt', value: 0 },
              color: 'red; background:url(javascript:window.__dw_pwned_style=true)',
            },
          ],
        },
      ],
    };
    const fixture = render(config, [{ amount: 100 }]);
    const root: HTMLElement = fixture.nativeElement;

    assertNoLiveMarkup(root);
    const cell = root.querySelector('.dw-cell') as HTMLElement;
    expect(cell.style.color).toBe('');
    expect(cell.getAttribute('style') ?? '').not.toContain('javascript:');
    expect((window as unknown as { __dw_pwned_style?: boolean }).__dw_pwned_style).toBeUndefined();
  });

  it('a valid hex conditional color is applied verbatim as a CSS color, nothing more', () => {
    const config: DeclarativeWidgetConfig = {
      query_ref: 'q1',
      columns: [
        {
          field: 'amount',
          label: 'Amount',
          conditional_colors: [{ when: { field: 'amount', operator: 'gt', value: 0 }, color: '#22c55e' }],
        },
      ],
    };
    const fixture = render(config, [{ amount: 100 }]);
    const cell = (fixture.nativeElement as HTMLElement).querySelector('.dw-cell') as HTMLElement;
    expect(cell.style.color).toBe('rgb(34, 197, 94)');
  });

  it('an action link renders as plain text, never as a button that does nothing (Phase 4.5)', () => {
    const config: DeclarativeWidgetConfig = {
      query_ref: 'q1',
      columns: [{ field: 'name', label: 'Name', link: { kind: 'action', action_id: 'record.get' } }],
    };
    const fixture = render(config, [{ name: 'Acme', id: 'r-1' }]);
    const host = fixture.nativeElement as HTMLElement;

    expect(host.querySelector('button')).toBeNull();
    expect(host.querySelector('.dw-cell')?.textContent?.trim()).toBe('Acme');
  });

  it('renders a well-formed config with normal formatting and no surprises', () => {
    const config: DeclarativeWidgetConfig = {
      query_ref: 'q1',
      columns: [
        { field: 'name', label: 'Name' },
        { field: 'amount', label: 'Amount', format: { kind: 'currency', currency_code: 'USD' } },
      ],
    };
    const fixture = render(config, [{ name: 'Acme', amount: 1234.5 }]);
    const root: HTMLElement = fixture.nativeElement;
    expect(root.textContent).toContain('Acme');
    expect(root.textContent).toMatch(/\$1,234\.50/);
  });

  it('shows the empty-state message when there are no rows', () => {
    const config: DeclarativeWidgetConfig = { query_ref: 'q1', columns: [{ field: 'name', label: 'Name' }] };
    const fixture = render(config, []);
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('No records found.');
  });
});
