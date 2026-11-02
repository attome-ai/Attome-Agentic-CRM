import { afterEach, describe, expect, it, vi } from 'vitest';

import { NativeService, phoneDigits, whatsAppLink } from './native.service';

const g = globalThis as unknown as { Capacitor?: unknown };

afterEach(() => {
  delete g.Capacitor;
  vi.restoreAllMocks();
});

describe('NativeService (B17-T2)', () => {
  it('isNative false in jsdom', () => {
    expect(new NativeService().isNative()).toBe(false);
  });

  it('isNative true inside the shell', () => {
    g.Capacitor = { isNativePlatform: () => true, Plugins: {} };
    expect(new NativeService().isNative()).toBe(true);
  });

  it('takePhoto falls back to file input', async () => {
    const created: HTMLInputElement[] = [];
    const real = document.createElement.bind(document);
    vi.spyOn(document, 'createElement').mockImplementation(((tag: string) => {
      const element = real(tag);
      if (tag === 'input') created.push(element as HTMLInputElement);
      return element;
    }) as typeof document.createElement);
    const photo = new NativeService().takePhoto();
    const input = created[0];
    expect(input.type).toBe('file');
    expect(input.accept).toBe('image/*');
    const file = new File(['x'], 'photo.jpg', { type: 'image/jpeg' });
    Object.defineProperty(input, 'files', { value: [file] });
    input.dispatchEvent(new Event('change'));
    expect(await photo).toEqual({ file });
  });

  it('takePhoto uses the native camera inside the shell', async () => {
    const getPhoto = vi.fn(async () => ({ dataUrl: 'data:image/jpeg;base64,AA' }));
    g.Capacitor = { isNativePlatform: () => true, Plugins: { Camera: { getPhoto } } };
    expect(await new NativeService().takePhoto()).toEqual({ dataUrl: 'data:image/jpeg;base64,AA' });
    expect(getPhoto).toHaveBeenCalledOnce();
  });

  it('openWhatsApp builds wa.me link with digits only', () => {
    const service = new NativeService();
    const opened: string[] = [];
    vi.spyOn(window, 'open').mockImplementation((url?: string | URL) => {
      opened.push(String(url));
      return null;
    });
    service.openWhatsApp('+966 (50) 123-4567', 'مرحبا');
    expect(opened[0]).toBe(`https://wa.me/966501234567?text=${encodeURIComponent('مرحبا')}`);
    expect(phoneDigits('+20 10 1234 5678')).toBe('201012345678');
    expect(whatsAppLink('+971-50-000')).toBe('https://wa.me/97150000');
  });
});
