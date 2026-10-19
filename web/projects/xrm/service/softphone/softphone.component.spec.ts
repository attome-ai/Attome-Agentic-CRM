import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { ApiService, LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SoftphoneComponent } from './softphone.component';
import {
  SdkCall, SoftphoneConfig, SoftphoneService, popLink, recordFromUrl, telNumber,
} from './softphone.service';

/** A stand-in for the provider SDK's Device and Call. */
class FakeCall implements SdkCall {
  handlers: Record<string, (() => void)[]> = {};
  constructor(public parameters: Record<string, string> = {}) {}
  accept = vi.fn(() => this.emit('accept'));
  reject = vi.fn();
  disconnect = vi.fn(() => this.emit('disconnect'));
  on(event: string, handler: () => void) { (this.handlers[event] ??= []).push(handler); }
  emit(event: string) { for (const h of this.handlers[event] ?? []) h(); }
}

class FakeDevice {
  static last: FakeDevice | null = null;
  handlers: Record<string, ((...a: unknown[]) => void)[]> = {};
  connected: Record<string, string>[] = [];
  constructor(public token: string) { FakeDevice.last = this; }
  register = vi.fn();
  updateToken = vi.fn();
  destroy = vi.fn();
  on(event: string, handler: (...a: unknown[]) => void) { (this.handlers[event] ??= []).push(handler); }
  emit(event: string, ...args: unknown[]) { for (const h of this.handlers[event] ?? []) h(...args); }
  connect = vi.fn(async (options: { params: Record<string, string> }) => {
    this.connected.push(options.params);
    return new FakeCall();
  });
}

const config: SoftphoneConfig = {
  available: true, identity: 'user_1', token: 'jwt', sdk_url: 'https://sdk.example/voice.js', expires_in: 3600,
};
const RECORD_URL = '/xrm/entity/contact/form?id=0198f3a2-1111-7222-8333-444455556666';

describe('softphone helpers (J6-T2)', () => {
  it('reads the record from the URL, tel: links and pop links', () => {
    expect(recordFromUrl(RECORD_URL)).toEqual({ entity: 'contact', id: '0198f3a2-1111-7222-8333-444455556666' });
    expect(recordFromUrl('/xrm/dashboard')).toBeNull();
    expect(telNumber('tel:+966%2055%20123%204567')).toBe('+966551234567');
    expect(telNumber('tel:0551234567')).toBeNull();
    expect(telNumber('mailto:a@b.c')).toBeNull();
    expect(popLink({ entity: 'lead', id: 'l1', name: null })).toEqual({ path: '/xrm/entity/lead/form', query: { id: 'l1' } });
  });
});

describe('SoftphoneService (J6-T2)', () => {
  let api: { get: ReturnType<typeof vi.fn>; post: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    (globalThis as { Twilio?: unknown }).Twilio = { Device: FakeDevice };
    FakeDevice.last = null;
    api = {
      get: vi.fn((path: string) => (path === '/api/v1/voice/lookup'
        ? of({ entity: 'contact', id: 'c1', name: 'Sara Al-Qahtani' })
        : of(config))),
      post: vi.fn(() => of({ call_id: 'call-1', activity_id: 'act-1' })),
    };
    TestBed.configureTestingModule({
      imports: [SoftphoneComponent],
      providers: [
        provideRouter([]),
        { provide: ApiService, useValue: api },
        { provide: LangService, useValue: { translate: (k: string) => k } },
      ],
    });
  });

  afterEach(() => {
    delete (globalThis as { Twilio?: unknown }).Twilio;
  });

  it('an incoming call pops the matching record', async () => {
    const phone = TestBed.inject(SoftphoneService);
    expect(await phone.start(config)).toBe(true);
    expect(FakeDevice.last?.register).toHaveBeenCalled();
    const call = new FakeCall({ From: '+966551234567' });
    FakeDevice.last?.emit('incoming', call);
    expect(phone.state()).toBe('incoming');
    expect(api.get).toHaveBeenCalledWith('/api/v1/voice/lookup', { number: '+966551234567' });
    expect(phone.pop()).toEqual({ entity: 'contact', id: 'c1', name: 'Sara Al-Qahtani' });
    phone.accept();
    expect(phone.state()).toBe('in_call');
    phone.hangUp();
    expect(phone.state()).toBe('ready');
  });

  it('click-to-call logs the call first and dials it by its id, not by number', async () => {
    const phone = TestBed.inject(SoftphoneService);
    await phone.start(config);
    await phone.call('+966551234567', { entity: 'contact', id: 'c1' });
    expect(api.post).toHaveBeenCalledWith('/api/v1/voice/calls', {
      to: '+966551234567', entity_name: 'contact', record_id: 'c1', mode: 'browser',
    });
    expect(FakeDevice.last?.connected).toEqual([{ CallRef: 'call-1' }]);
    expect(phone.state()).toBe('calling');
  });

  it('without a softphone the call rings the agent\'s own phone', async () => {
    const phone = TestBed.inject(SoftphoneService);
    expect(await phone.start({ ...config, available: false })).toBe(false);
    await phone.call('+966551234567', { entity: 'contact', id: 'c1' });
    expect(api.post.mock.calls[0][1].mode).toBe('phone');
    expect(phone.state()).toBe('off');
  });

  it('an unknown caller still rings, with no pop', async () => {
    api.get.mockImplementation((path: string) => (path === '/api/v1/voice/lookup'
      ? throwError(() => ({ status: 404 }))
      : of(config)));
    const phone = TestBed.inject(SoftphoneService);
    await phone.start(config);
    FakeDevice.last?.emit('incoming', new FakeCall({ From: '+15550001111' }));
    expect(phone.state()).toBe('incoming');
    expect(phone.pop()).toBeNull();
  });

  it('the panel shows the incoming call and its pop link', async () => {
    const fixture = TestBed.createComponent(SoftphoneComponent);
    fixture.componentRef.setInput('config', config);
    fixture.detectChanges();
    await vi.waitFor(() => expect(FakeDevice.last?.register).toHaveBeenCalled());
    FakeDevice.last?.emit('incoming', new FakeCall({ From: '+966551234567' }));
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-testid="softphone-pop"]')?.textContent).toContain('Sara Al-Qahtani');
    expect(el.querySelector('[data-testid="softphone-accept"]')).not.toBeNull();
  });
});
