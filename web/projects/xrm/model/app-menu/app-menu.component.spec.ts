import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { ModelService } from '../model.service';
import { AppMenuComponent, linkFor } from './app-menu.component';

describe('linkFor (A21-T2)', () => {
  it('opens forms in the renderer and links by their url', () => {
    expect(linkFor({ label: 'A', kind: 'form', target: 'f1' })).toEqual({ route: '/model/forms/f1' });
    expect(linkFor({ label: 'B', kind: 'url', url: '/model/explorer' })).toEqual({ route: '/model/explorer' });
    expect(linkFor({ label: 'C', kind: 'url', url: 'https://example.com' })).toEqual({ href: 'https://example.com' });
    expect(linkFor({ label: 'D', kind: 'dashboard', target: 'd1' })).toBeNull();
  });
});

describe('AppMenuComponent', () => {
  it('draws the groups and items the server sent', () => {
    const menu = vi.fn().mockReturnValue(of({
      id: 'm1', name: 'Sales app', landing: null,
      groups: [{ label: 'Sales', items: [
        { label: 'Accounts', kind: 'form', target: 'f1' },
        { label: 'Help', kind: 'url', url: 'https://example.com', badge: 'new' },
      ] }],
    }));
    TestBed.configureTestingModule({
      imports: [AppMenuComponent],
      providers: [
        provideRouter([]),
        { provide: ModelService, useValue: { menu } },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
    const fixture = TestBed.createComponent(AppMenuComponent);
    fixture.componentRef.setInput('menuId', 'm1');
    fixture.detectChanges();
    expect(menu).toHaveBeenCalledWith('m1');
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('.am-group-label')?.textContent?.trim()).toBe('Sales');
    expect(el.querySelectorAll('[data-item]').length).toBe(2);
    expect(el.querySelector('[data-item="Sales/Help"] a')?.getAttribute('rel')).toContain('noopener');
    expect(el.querySelector('.am-badge')?.textContent?.trim()).toBe('new');
  });
});
