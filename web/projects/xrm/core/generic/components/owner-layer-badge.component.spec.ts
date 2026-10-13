import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { ChangesetContextService } from '@attome/xrm/core/admin/data';
import { beforeEach, describe, expect, it } from 'vitest';
import { OwnerLayerBadgeComponent } from './owner-layer-badge.component';

describe('OwnerLayerBadgeComponent', () => {
  const editingLayer = signal<string | null>(null);

  beforeEach(() => {
    editingLayer.set(null);
    TestBed.configureTestingModule({
      providers: [
        // Echo the key and its params, so the assertions can see both.
        { provide: LangService, useValue: {
          translate: (k: string, p?: Record<string, unknown>) => (p ? `${k}${JSON.stringify(p)}` : k),
        } },
        { provide: ChangesetContextService, useValue: { editingLayer } },
      ],
    });
  });

  function mount(layer: string | null | undefined, variant: 'compact' | 'full' = 'compact', editing?: string | null) {
    const fixture = TestBed.createComponent(OwnerLayerBadgeComponent);
    fixture.componentRef.setInput('layer', layer);
    fixture.componentRef.setInput('variant', variant);
    if (editing !== undefined) fixture.componentRef.setInput('editingLayer', editing);
    fixture.detectChanges();
    return fixture;
  }

  it('renders nothing for an absent or unknown layer', () => {
    expect(mount(undefined).nativeElement.textContent.trim()).toBe('');
    expect(mount('galaxy').nativeElement.textContent.trim()).toBe('');
  });

  it('shows the layer, unlocked, when it matches the default project editing layer', () => {
    const el: HTMLElement = mount('project').nativeElement;
    expect(el.querySelector('.xrm-owner-layer')?.textContent).toContain('changesets.layer.project');
    expect(el.querySelector('.is-locked')).toBeNull();
    expect(el.querySelector('.la-lock')).toBeNull();
  });

  it('locks a platform row while editing the project layer, explaining the refusal', () => {
    const el: HTMLElement = mount('platform').nativeElement;
    const badge = el.querySelector('.xrm-owner-layer')!;
    expect(badge.classList).toContain('is-locked');
    expect(el.querySelector('.la-lock')?.getAttribute('aria-hidden')).toBe('true');
    expect(badge.getAttribute('title')).toContain('changesets.lockedNote');
    // Compact: the reason is screen-reader text, not a printed note.
    expect(el.querySelector('[role="note"]')).toBeNull();
    expect(el.querySelector(':scope > .visually-hidden')?.textContent).toContain('changesets.lockedNote');
  });

  it('prints the reason as a note in the full variant', () => {
    const note = mount('platform', 'full').nativeElement.querySelector('[role="note"]');
    expect(note?.textContent).toContain('changesets.lockedNote');
    expect(note?.textContent).toContain('changesets.layer.platform');
    expect(note?.textContent).toContain('changesets.layer.project');
  });

  it("follows the effective changeset's layer", () => {
    editingLayer.set('platform');
    const fixture = mount('platform');
    expect(fixture.nativeElement.querySelector('.is-locked')).toBeNull();
    editingLayer.set('product');
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('.is-locked')).not.toBeNull();
  });

  it('an explicit editingLayer input wins over the changeset context', () => {
    editingLayer.set('project');
    expect(mount('platform', 'compact', 'platform').nativeElement.querySelector('.is-locked')).toBeNull();
  });
});
