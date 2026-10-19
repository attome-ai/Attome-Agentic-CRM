import { DOCUMENT } from '@angular/common';
import { Injectable, inject, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { ApiService } from '@attome/base';

/** `GET /api/v1/voice/softphone`. */
export interface SoftphoneConfig {
  available: boolean;
  identity: string | null;
  token: string | null;
  sdk_url: string | null;
  expires_in: number;
}

/** `GET /api/v1/voice/lookup`: the record a caller's number belongs to. */
export interface ScreenPop {
  entity: string;
  id: string;
  name: string | null;
}

/** The parts of the provider SDK's call this service uses. */
export interface SdkCall {
  parameters: Record<string, string>;
  accept(): void;
  reject(): void;
  disconnect(): void;
  on(event: string, handler: (...args: unknown[]) => void): void;
}

/** The parts of the provider SDK's device this service uses. */
export interface SdkDevice {
  register(): Promise<void> | void;
  connect(options: { params: Record<string, string> }): Promise<SdkCall>;
  updateToken(token: string): void;
  destroy(): void;
  on(event: string, handler: (...args: unknown[]) => void): void;
}

type DeviceConstructor = new (token: string, options?: Record<string, unknown>) => SdkDevice;

export type PhoneState = 'off' | 'ready' | 'incoming' | 'calling' | 'in_call' | 'error';

/** The record a call is about, from a record page's URL. Pure. */
export function recordFromUrl(url: string): { entity: string; id: string } | null {
  const match = /\/xrm\/entity\/([a-z0-9_]+)\/form\?(?:.*&)?id=([0-9a-f-]{36})/i.exec(url);
  return match ? { entity: match[1], id: match[2] } : null;
}

/** The number in a `tel:` link, as E.164, or null. Pure. */
export function telNumber(href: string): string | null {
  if (!href.toLowerCase().startsWith('tel:')) return null;
  const raw = decodeURIComponent(href.slice(4)).trim();
  const digits = raw.replace(/\D/g, '');
  return raw.startsWith('+') && digits.length >= 8 && digits.length <= 15 ? `+${digits}` : null;
}

/** Where a screen pop opens. Pure. */
export function popLink(pop: ScreenPop): { path: string; query: Record<string, string> } {
  return { path: `/xrm/entity/${pop.entity}/form`, query: { id: pop.id } };
}

/**
 * J6-T2: the browser softphone. With a softphone set up (a Twilio voice
 * system with an API key, a TwiML app and the SDK's address), it loads the
 * provider's SDK — only then — and registers the agent, so calls ring in the
 * browser; an incoming call is matched to its contact, lead or account
 * (screen pop). A call placed from a record is logged on it first
 * (`POST /api/v1/voice/calls`, `mode: browser`) and then dialled by the SDK
 * with that call's id, so the server dials the number it recorded, never one
 * the browser sends. Without a softphone the same call rings the agent's own
 * phone (`mode: phone`).
 */
@Injectable({ providedIn: 'root' })
export class SoftphoneService {
  private readonly api = inject(ApiService);
  private readonly doc = inject(DOCUMENT);

  readonly state = signal<PhoneState>('off');
  readonly pop = signal<ScreenPop | null>(null);
  readonly caller = signal<string | null>(null);
  readonly error = signal<string | null>(null);

  private device: SdkDevice | null = null;
  private current: SdkCall | null = null;

  /** Starts the softphone with the server's settings; false when none. */
  async start(config: SoftphoneConfig): Promise<boolean> {
    if (!config.available || !config.token || !config.sdk_url) return false;
    try {
      const Device = await this.loadSdk(config.sdk_url);
      const device = new Device(config.token, { closeProtection: true });
      device.on('incoming', call => this.incoming(call as SdkCall));
      device.on('error', e => this.fail(e));
      device.on('tokenWillExpire', () => void this.refreshToken());
      await device.register();
      this.device = device;
      this.state.set('ready');
      return true;
    } catch (e) {
      this.fail(e);
      return false;
    }
  }

  stop(): void {
    this.device?.destroy();
    this.device = null;
    this.state.set('off');
  }

  /** Calls `number` about a record: in the browser when it can, else on the agent's phone. */
  async call(number: string, record: { entity: string; id: string }): Promise<void> {
    this.error.set(null);
    const browser = this.device !== null && this.state() === 'ready';
    try {
      const placed = await firstValueFrom(this.api.post<{ call_id: string; activity_id: string }>(
        '/api/v1/voice/calls',
        { to: number, entity_name: record.entity, record_id: record.id, mode: browser ? 'browser' : 'phone' },
      ));
      if (!browser || !this.device) {
        this.state.set(this.device ? 'ready' : 'off');
        return;
      }
      this.state.set('calling');
      const call = await this.device.connect({ params: { CallRef: placed.call_id } });
      this.track(call);
    } catch (e) {
      this.fail(e);
    }
  }

  accept(): void {
    this.current?.accept();
  }

  reject(): void {
    this.current?.reject();
    this.reset();
  }

  hangUp(): void {
    this.current?.disconnect();
    this.reset();
  }

  /** An incoming call: ring, and look up who it is. */
  private incoming(call: SdkCall): void {
    this.track(call);
    this.state.set('incoming');
    const from = call.parameters?.['From'] ?? null;
    this.caller.set(from);
    this.pop.set(null);
    if (from && from.startsWith('+')) {
      this.api.get<ScreenPop>('/api/v1/voice/lookup', { number: from }).subscribe({
        next: pop => this.pop.set(pop),
        // Nobody the agent may see has this number: no pop, the call still rings.
        error: () => this.pop.set(null),
      });
    }
  }

  private track(call: SdkCall): void {
    this.current = call;
    call.on('accept', () => this.state.set('in_call'));
    for (const end of ['disconnect', 'cancel', 'reject']) {
      call.on(end, () => this.reset());
    }
  }

  private reset(): void {
    this.current = null;
    this.caller.set(null);
    this.state.set(this.device ? 'ready' : 'off');
  }

  private fail(e: unknown): void {
    this.error.set(String((e as { message?: string })?.message ?? e));
    this.state.set(this.device ? 'ready' : 'error');
  }

  private async refreshToken(): Promise<void> {
    const config = await firstValueFrom(this.api.get<SoftphoneConfig>('/api/v1/voice/softphone'));
    if (config.token) this.device?.updateToken(config.token);
  }

  /** Loads the provider's SDK once; resolves its `Device`. */
  private loadSdk(url: string): Promise<DeviceConstructor> {
    const existing = (globalThis as { Twilio?: { Device?: DeviceConstructor } }).Twilio?.Device;
    if (existing) return Promise.resolve(existing);
    return new Promise((resolve, reject) => {
      const script = this.doc.createElement('script');
      script.src = url;
      script.async = true;
      script.crossOrigin = 'anonymous';
      script.onload = () => {
        const Device = (globalThis as { Twilio?: { Device?: DeviceConstructor } }).Twilio?.Device;
        if (Device) resolve(Device);
        else reject(new Error('the softphone SDK did not load'));
      };
      script.onerror = () => reject(new Error('the softphone SDK did not load'));
      this.doc.head.appendChild(script);
    });
  }
}
