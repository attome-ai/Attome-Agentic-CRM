import { afterEach, describe, expect, it, vi } from 'vitest';
import { firstValueFrom } from 'rxjs';

import { ScanService, fromZxingFormat } from './scan.service';

/** A service whose zxing import is a stub. */
class StubbedScan extends ScanService {
  readonly readBarcodes = vi.fn(async () => [
    { format: 'EAN-13', text: '6281000000017', isValid: true },
    { format: 'Aztec', text: 'ignored', isValid: true },
  ]);
  readonly loads = vi.fn();
  protected override loadZxing() {
    this.loads();
    return Promise.resolve({ readBarcodes: this.readBarcodes } as never);
  }
}

const g = globalThis as unknown as { BarcodeDetector?: unknown; window: Record<string, unknown> };

afterEach(() => {
  delete g.BarcodeDetector;
  delete (g.window as { BarcodeDetector?: unknown }).BarcodeDetector;
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe('ScanService (B16-T1)', () => {
  it('uses BarcodeDetector when present', async () => {
    const detect = vi.fn(async () => [
      { format: 'qr_code', rawValue: 'https://example.com/a' },
      { format: 'aztec', rawValue: 'not ours' },
    ]);
    const formats: string[][] = [];
    class FakeDetector {
      constructor(o: { formats: string[] }) { formats.push(o.formats); }
      detect = detect;
    }
    g.BarcodeDetector = FakeDetector;
    (g.window as { BarcodeDetector?: unknown }).BarcodeDetector = FakeDetector;
    const svc = new StubbedScan();
    const results = await svc.decodeFrame({} as ImageBitmapSource);
    expect(results).toEqual([{ format: 'qr_code', rawValue: 'https://example.com/a' }]);
    expect(formats[0]).toContain('ean_13');
    expect(svc.loads).not.toHaveBeenCalled();
  });

  it('falls back to zxing when BarcodeDetector is missing', async () => {
    // jsdom has no ImageData; a frame of that class is what the reader takes as is.
    class FakeImageData { constructor(readonly width: number, readonly height: number) {} }
    vi.stubGlobal('ImageData', FakeImageData);
    const svc = new StubbedScan();
    const frame = new FakeImageData(2, 2) as unknown as ImageData;
    const results = await svc.decodeFrame(frame);
    expect(svc.loads).toHaveBeenCalledTimes(1);
    expect(svc.readBarcodes).toHaveBeenCalledWith(frame, expect.objectContaining({ formats: expect.arrayContaining(['QRCode', 'EAN-13']) }));
    expect(results).toEqual([{ format: 'ean_13', rawValue: '6281000000017' }]);
    // The reader loads once.
    await svc.decodeFrame(frame);
    expect(svc.loads).toHaveBeenCalledTimes(1);
  });

  it('stop releases tracks', async () => {
    vi.useFakeTimers();
    const tracks = [{ stop: vi.fn() }, { stop: vi.fn() }];
    const stream = { getTracks: () => tracks } as unknown as MediaStream;
    Object.defineProperty(globalThis.navigator, 'mediaDevices', {
      configurable: true,
      value: { getUserMedia: vi.fn(async () => stream) },
    });
    const svc = new StubbedScan();
    const video = { readyState: 4, videoWidth: 2, videoHeight: 2, play: vi.fn(), srcObject: null } as unknown as HTMLVideoElement;
    vi.spyOn(svc, 'decodeFrame').mockResolvedValue([{ format: 'code_128', rawValue: 'A-1' }]);
    const first = firstValueFrom(svc.startCamera(video, { continuous: false }));
    await vi.advanceTimersByTimeAsync(300);
    await expect(first).resolves.toEqual({ format: 'code_128', rawValue: 'A-1' });
    expect(navigator.mediaDevices.getUserMedia).toHaveBeenCalledWith({ video: { facingMode: 'environment' } });
    expect(video.srcObject).toBe(stream);
    // Completing after the first code tore the subscription down, releasing the camera.
    expect(tracks.every(t => t.stop.mock.calls.length === 1)).toBe(true);
    svc.stop();
    expect(tracks[0].stop).toHaveBeenCalledTimes(1);
  });

  it('maps zxing format names', () => {
    expect(fromZxingFormat('EAN-13')).toBe('ean_13');
    expect(fromZxingFormat('QRCode')).toBe('qr_code');
    expect(fromZxingFormat('UPCA')).toBe('upc_a');
    expect(fromZxingFormat('Aztec')).toBeNull();
  });
});
