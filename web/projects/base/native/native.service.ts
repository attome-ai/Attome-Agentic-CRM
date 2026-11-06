import { Injectable } from '@angular/core';
import { EMPTY, Observable } from 'rxjs';

/** What another app shared into Attome. */
export interface SharedItem {
  url?: string;
  text?: string;
}

/** A position fix. */
export interface Position {
  latitude: number;
  longitude: number;
  /** Metres. */
  accuracy: number;
}

/** A photo: a data URL from the native camera, or the file the browser picked. */
export interface Photo {
  dataUrl?: string;
  file?: File;
}

/** The parts of the native bridge's `window.Capacitor` the service uses. */
interface CapacitorBridge {
  isNativePlatform?: () => boolean;
  Plugins?: {
    Camera?: { getPhoto(options: Record<string, unknown>): Promise<{ dataUrl?: string }> };
    Geolocation?: {
      getCurrentPosition(options?: Record<string, unknown>): Promise<{
        coords: { latitude: number; longitude: number; accuracy: number };
      }>;
    };
    App?: {
      addListener(
        event: 'appUrlOpen',
        handler: (data: { url: string }) => void,
      ): Promise<{ remove(): Promise<void> }> | { remove(): Promise<void> };
      addListener(
        event: 'appStateChange',
        handler: (state: { isActive: boolean }) => void,
      ): Promise<{ remove(): Promise<void> }> | { remove(): Promise<void> };
    };
  };
}

/** The digits of a phone number, a leading `+` dropped. Pure. */
export function phoneDigits(phone: string): string {
  return phone.replace(/\D/g, '');
}

/** The WhatsApp link to `phone`, with `text` prefilled when given. Pure. */
export function whatsAppLink(phone: string, text?: string): string {
  const base = `https://wa.me/${phoneDigits(phone)}`;
  return text ? `${base}?text=${encodeURIComponent(text)}` : base;
}

/**
 * B17-T2 — one call for what a phone can do, in the phone app and in the
 * browser alike. Inside the Capacitor shell (`mobile/`) the native bridge
 * puts `window.Capacitor` on the page, and the plugins the shell was built
 * with (`Camera`, `Geolocation`, `App`) are reached through it; in a browser
 * there is no bridge and each method falls back to the web's own way (a file
 * input, `navigator.geolocation`, a `tel:` link). Nothing is imported from
 * Capacitor's packages, so the web bundle does not grow.
 */
@Injectable({ providedIn: 'root' })
export class NativeService {
  /** The bridge, when the page runs in the shell. */
  protected bridge(): CapacitorBridge | undefined {
    return (globalThis as { Capacitor?: CapacitorBridge }).Capacitor;
  }

  /** Whether the page runs inside the native shell. */
  isNative(): boolean {
    return this.bridge()?.isNativePlatform?.() === true;
  }

  /** A photo from the camera, or `null` when none was taken. */
  async takePhoto(): Promise<Photo | null> {
    const camera = this.isNative() ? this.bridge()?.Plugins?.Camera : undefined;
    if (camera) {
      try {
        const photo = await camera.getPhoto({ resultType: 'dataUrl', quality: 80, source: 'CAMERA' });
        return photo.dataUrl ? { dataUrl: photo.dataUrl } : null;
      } catch {
        return null;
      }
    }
    return this.pickImage();
  }

  /** The browser's file picker, opening the camera on phones that offer it. */
  protected pickImage(): Promise<Photo | null> {
    return new Promise(resolve => {
      const input = document.createElement('input');
      input.type = 'file';
      input.accept = 'image/*';
      input.setAttribute('capture', 'environment');
      input.addEventListener('change', () => {
        const file = input.files?.[0];
        resolve(file ? { file } : null);
      });
      input.addEventListener('cancel', () => resolve(null));
      input.click();
    });
  }

  /** Where the device is, or `null` when it may not or cannot say. */
  async getPosition(): Promise<Position | null> {
    const geolocation = this.isNative() ? this.bridge()?.Plugins?.Geolocation : undefined;
    if (geolocation) {
      try {
        const { coords } = await geolocation.getCurrentPosition({ enableHighAccuracy: true });
        return { latitude: coords.latitude, longitude: coords.longitude, accuracy: coords.accuracy };
      } catch {
        return null;
      }
    }
    if (typeof navigator === 'undefined' || !navigator.geolocation) return null;
    return new Promise(resolve => {
      navigator.geolocation.getCurrentPosition(
        p => resolve({ latitude: p.coords.latitude, longitude: p.coords.longitude, accuracy: p.coords.accuracy }),
        () => resolve(null),
        { enableHighAccuracy: true, timeout: 15000 },
      );
    });
  }

  /**
   * What other apps share into Attome: in the shell, each link the app is
   * opened with; in a browser, nothing.
   */
  onShareIntent(): Observable<SharedItem> {
    const app = this.isNative() ? this.bridge()?.Plugins?.App : undefined;
    if (!app) return EMPTY;
    return new Observable<SharedItem>(subscriber => {
      let handle: { remove(): Promise<void> } | undefined;
      let closed = false;
      void Promise.resolve(app.addListener('appUrlOpen', data => subscriber.next({ url: data.url }))).then(h => {
        handle = h;
        if (closed) void h.remove();
      });
      return () => {
        closed = true;
        void handle?.remove();
      };
    });
  }

  /**
   * D21-T12: each time the app comes back to the foreground (after a call
   * in the phone's own dialer, say); in a browser, nothing.
   */
  onResume(): Observable<void> {
    const app = this.isNative() ? this.bridge()?.Plugins?.App : undefined;
    if (!app) return EMPTY;
    return new Observable<void>(subscriber => {
      let handle: { remove(): Promise<void> } | undefined;
      let closed = false;
      void Promise.resolve(
        app.addListener('appStateChange', state => {
          if (state.isActive) subscriber.next();
        }),
      ).then(h => {
        handle = h;
        if (closed) void h.remove();
      });
      return () => {
        closed = true;
        void handle?.remove();
      };
    });
  }

  /** Dials `phone` (the phone's dialer, or the computer's calling app). */
  openTel(phone: string): void {
    this.open(`tel:+${phoneDigits(phone)}`);
  }

  /** Opens a WhatsApp chat with `phone`. */
  openWhatsApp(phone: string, text?: string): void {
    this.open(whatsAppLink(phone, text));
  }

  /** Opens a link outside the app. */
  protected open(url: string): void {
    window.open(url, '_blank', 'noopener');
  }
}
