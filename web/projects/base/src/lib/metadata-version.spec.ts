import { TestBed } from '@angular/core/testing';
import { describe, expect, it } from 'vitest';

import { MetadataVersion } from './metadata-version';

describe('MetadataVersion (Y8-T8)', () => {
  it('takes the first version as the baseline and reports newer ones', () => {
    const versions = TestBed.inject(MetadataVersion);
    const seen: number[] = [];
    versions.changes.subscribe(v => seen.push(v));

    versions.observe('41');
    expect(versions.version()).toBe(41);
    expect(seen).toEqual([]);

    versions.observe('41');
    versions.observe('40');
    versions.observe(null);
    versions.observe('junk');
    expect(seen).toEqual([]);

    versions.observe('42');
    expect(seen).toEqual([42]);
    expect(versions.version()).toBe(42);
  });
});
