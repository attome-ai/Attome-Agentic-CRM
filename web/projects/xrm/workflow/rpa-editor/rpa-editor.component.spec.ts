import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService, SdkService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { RpaEditorComponent, type RpaStep, describeStep, framePoint } from './rpa-editor.component';
import { sdkFromApi } from '../../testing/sdk-from-api';

const PNG = 'iVBORw0KGgo=';

describe('RpaEditorComponent (M16-T3)', () => {
  function create(steps: RpaStep[] = []) {
    const post = vi.fn((path: string, body: Record<string, unknown>) => {
      if (path.endsWith('/record')) {
        return of({ session: '0190a0b0-0000-7000-8000-000000000001', step: { kind: 'goto', url: body['url'] }, password: false, png_base64: PNG });
      }
      if (body['action'] === 'click') {
        return of({ session: null, step: { kind: 'click', selector: '#password' }, password: true, png_base64: PNG });
      }
      return of({ session: null, step: { kind: 'fill', selector: '#password', value: '{{secret:password}}' }, password: true, png_base64: PNG });
    });
    const del = vi.fn(() => of(undefined));
    TestBed.configureTestingModule({
      imports: [RpaEditorComponent],
      providers: [
        { provide: ApiService, useValue: { post, delete: del } },
        { provide: SdkService, deps: [ApiService], useFactory: sdkFromApi },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, current: signal('en'), isRtl: signal(false) },
        },
      ],
    });
    const fixture = TestBed.createComponent(RpaEditorComponent);
    fixture.componentRef.setInput('system', 'portal');
    fixture.componentRef.setInput('allowedHosts', ['portal.example.com']);
    fixture.componentRef.setInput('steps', steps);
    const emitted: RpaStep[][] = [];
    fixture.componentInstance.stepsChange.subscribe(s => {
      emitted.push(s);
      fixture.componentRef.setInput('steps', s);
    });
    fixture.detectChanges();
    return { fixture, post, del, emitted };
  }

  it('records a start, a click and a password typed as a secret', () => {
    const { fixture, post, emitted } = create();
    const c = fixture.componentInstance;
    c.start(' https://portal.example.com/login ');
    expect(post).toHaveBeenCalledWith('/api/v1/admin/integrations/rpa/portal/record', {
      url: 'https://portal.example.com/login', allowed_hosts: ['portal.example.com'],
    });
    expect(c.session()).toBe('0190a0b0-0000-7000-8000-000000000001');
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('.rpa-view img')).not.toBeNull();

    c.clickFrame({
      detail: 1, clientX: 50, clientY: 40,
      currentTarget: { getBoundingClientRect: () => ({ left: 0, top: 0, width: 640, height: 400 }) },
    } as unknown as MouseEvent);
    expect(post).toHaveBeenLastCalledWith(
      '/api/v1/admin/integrations/rpa/portal/record/0190a0b0-0000-7000-8000-000000000001',
      { action: 'click', x: 100, y: 80 },
    );
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('[data-testid="rpa-password"]')).not.toBeNull();

    c.typeText('hunter2');
    const steps = emitted.at(-1)!;
    expect(steps.map(s => s.kind)).toEqual(['goto', 'click', 'fill']);
    expect(steps[2].value).toBe('{{secret:password}}');
    expect(JSON.stringify(steps)).not.toContain('hunter2');
  });

  it('keyboard activations of the view record nothing', () => {
    const { fixture, post } = create();
    const c = fixture.componentInstance;
    c.start('https://portal.example.com');
    post.mockClear();
    c.clickFrame({ detail: 0 } as MouseEvent);
    expect(post).not.toHaveBeenCalled();
  });

  it('edits the list by hand and stops the recording', () => {
    const steps: RpaStep[] = [{ kind: 'goto', url: 'https://a.example' }, { kind: 'click', selector: '#go' }];
    const { fixture, del, emitted } = create(steps);
    const c = fixture.componentInstance;
    expect(fixture.nativeElement.querySelectorAll('[data-testid="rpa-step"]').length).toBe(2);
    c.move(1, -1);
    expect(emitted.at(-1)!.map(s => s.kind)).toEqual(['click', 'goto']);
    c.remove(0);
    expect(emitted.at(-1)!.map(s => s.kind)).toEqual(['goto']);
    c.addScreenshot();
    expect(emitted.at(-1)!.at(-1)).toEqual({ kind: 'screenshot' });

    c.start('https://a.example');
    c.stop();
    expect(del).toHaveBeenCalledWith('/api/v1/admin/integrations/rpa/portal/record/0190a0b0-0000-7000-8000-000000000001');
    expect(c.session()).toBeNull();
  });

  it('maps points and describes steps', () => {
    expect(framePoint(10, 10, { left: 0, top: 0, width: 1280, height: 800 })).toEqual({ x: 10, y: 10 });
    expect(framePoint(-1, 10, { left: 0, top: 0, width: 1280, height: 800 })).toBeNull();
    expect(describeStep({ kind: 'press', key: 'Enter', selector: '#q' })).toBe('press Enter in #q');
  });
});
