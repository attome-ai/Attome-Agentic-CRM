import { ComponentFixture, TestBed } from '@angular/core/testing';
import { of } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiService, LangService, TemplateRendererService } from '@attome/base';
import { TemplatePreviewComponent } from './template-preview.component';

const SCHEMA = {
  fields: [
    { id: '1', entity_id: 'e', name: 'title', display_name: 'Title', field_type: 'text', options: null, sort_order: 0, is_required: false },
  ],
};

describe('TemplatePreviewComponent', () => {
  let fixture: ComponentFixture<TemplatePreviewComponent>;
  const render = vi.fn();
  const post = vi.fn();

  afterEach(() => vi.useRealTimers());

  beforeEach(() => {
    vi.useFakeTimers();
    render.mockReset();
    post.mockReset();
    TestBed.configureTestingModule({
      imports: [TemplatePreviewComponent],
      providers: [
        { provide: ApiService, useValue: { get: () => of(SCHEMA), post } },
        { provide: TemplateRendererService, useValue: { render } },
        { provide: LangService, useValue: { intlLocale: () => 'en-US', translate: (k: string) => k } },
      ],
    });
    fixture = TestBed.createComponent(TemplatePreviewComponent);
    fixture.componentRef.setInput('entity', 'account');
    fixture.componentRef.setInput('template', '{{ title }}');
  });

  async function settle(): Promise<void> {
    fixture.detectChanges();
    await vi.advanceTimersByTimeAsync(300);
    fixture.detectChanges();
  }

  it('renders in the browser with sample values', async () => {
    render.mockResolvedValue({ ok: true, output: '<b>Title</b>' });
    await settle();
    const [template, , context, locale] = render.mock.lastCall as [string, unknown, { fields: unknown }, string];
    expect(template).toBe('{{ title }}');
    expect(context.fields).toEqual({ title: 'Title' });
    expect(locale).toBe('en-US');
    const frame = fixture.nativeElement.querySelector('iframe') as HTMLIFrameElement;
    expect(frame.getAttribute('sandbox')).toBe('');
    expect(post).not.toHaveBeenCalled();
  });

  it('shows a template error', async () => {
    render.mockResolvedValue({ ok: false, diagnostics: [{ code: 'x', message: 'line 1: no such field' }] });
    await settle();
    expect(fixture.nativeElement.textContent).toContain('line 1: no such field');
  });

  it('falls back to the server preview when the module fails', async () => {
    render.mockRejectedValue(new Error('no wasm'));
    post.mockReturnValue(of({ rendered: '<i>server</i>' }));
    fixture.componentRef.setInput('recordId', 'r1');
    await settle();
    expect(post.mock.calls[0][1]).toMatchObject({ entity: 'account', record_id: 'r1' });
    expect(fixture.nativeElement.querySelector('iframe')).not.toBeNull();
  });
});
