import { TestBed } from '@angular/core/testing';
import { describe, expect, it } from 'vitest';
import { UserPreferencesService, isValidTimeZone } from './user-preferences.service';

/** NGB-1.8 / NGB-F26 — the stored timezone preference is probed, not trusted. */
describe('UserPreferencesService', () => {
  function setUp() {
    TestBed.configureTestingModule({});
    return TestBed.inject(UserPreferencesService);
  }

  it('starts with no preference', () => {
    expect(setUp().timezone()).toBeNull();
  });

  it('stores a real IANA zone, trimmed', () => {
    const prefs = setUp();
    prefs.setTimezone('  Asia/Dubai  ');
    expect(prefs.timezone()).toBe('Asia/Dubai');
  });

  it('NGB-F26 stores null for a zone Intl does not know', () => {
    const prefs = setUp();
    prefs.setTimezone('Not/AZone');
    expect(prefs.timezone()).toBeNull();
  });

  it('stores null for null, undefined and blank input', () => {
    const prefs = setUp();
    prefs.setTimezone('Asia/Dubai');
    prefs.setTimezone(null);
    expect(prefs.timezone()).toBeNull();
    prefs.setTimezone('Asia/Dubai');
    prefs.setTimezone(undefined);
    expect(prefs.timezone()).toBeNull();
    prefs.setTimezone('Asia/Dubai');
    prefs.setTimezone('   ');
    expect(prefs.timezone()).toBeNull();
  });

  it('isValidTimeZone accepts a real zone and rejects an unknown one', () => {
    expect(isValidTimeZone('UTC')).toBe(true);
    expect(isValidTimeZone('Not/AZone')).toBe(false);
  });
});
