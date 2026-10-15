import { TestBed } from '@angular/core/testing';
import { describe, expect, it } from 'vitest';

import { LiveChannel, LiveRecords } from './live-channel.service';

describe('LiveChannel (A13-T4)', () => {
  it('counts watchers per entity', () => {
    const channel = TestBed.inject(LiveChannel);
    const first = channel.watch('account');
    const second = channel.watch('account');
    const other = channel.watch('contact');
    expect(channel.watching()).toEqual(['account', 'contact']);
    first();
    first();
    expect(channel.watching()).toEqual(['account', 'contact']);
    second();
    other();
    expect(channel.watching()).toEqual([]);
  });

  it('passes record frames on, and drops malformed ones', () => {
    const channel = TestBed.inject(LiveChannel);
    const seen: LiveRecords[] = [];
    channel.records.subscribe(frame => seen.push(frame));
    channel.receiveRecords('{"changes":[{"entity":"account","id":"r1","op":"update"}]}');
    channel.receiveRecords('{"overflow":true}');
    channel.receiveRecords('not json');
    expect(seen).toEqual([
      { changes: [{ entity: 'account', id: 'r1', op: 'update' }] },
      { overflow: true },
    ]);
  });
});
