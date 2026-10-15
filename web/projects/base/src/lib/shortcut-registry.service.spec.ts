import { TestBed } from '@angular/core/testing';
import { describe, expect, it } from 'vitest';

import { ShortcutRegistry, isTypingTarget } from './shortcut-registry.service';

describe('ShortcutRegistry (B10-T2)', () => {
  it('lists registered shortcuts until they are removed', () => {
    const registry = TestBed.inject(ShortcutRegistry);
    const remove = registry.register({ keys: 'g i', labelKey: 'inbox' });
    registry.register({ keys: '?', labelKey: 'help' });
    expect(registry.shortcuts().map(s => s.keys)).toEqual(['g i', '?']);
    remove();
    expect(registry.shortcuts().map(s => s.keys)).toEqual(['?']);
  });

  it('leaves typing in a field alone', () => {
    expect(isTypingTarget(document.createElement('input'))).toBe(true);
    expect(isTypingTarget(document.createElement('textarea'))).toBe(true);
    expect(isTypingTarget(document.createElement('div'))).toBe(false);
    expect(isTypingTarget(null)).toBe(false);
  });
});
