import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

/** The codes the scanner reads, in the W3C Barcode Detection API's names. */
export const SCAN_FORMATS = [
  'ean_13', 'ean_8', 'upc_a', 'upc_e', 'code_128', 'code_39', 'qr_code', 'data_matrix', 'pdf417',
] as const;
export type ScanFormat = typeof SCAN_FORMATS[number];

export interface ScanResult {
  format: ScanFormat;
  rawValue: string;
}

/** zxing-wasm's format names for ours. */
const ZXING: Record<ScanFormat, string> = {
  ean_13: 'EAN-13', ean_8: 'EAN-8', upc_a: 'UPC-A', upc_e: 'UPC-E', code_128: 'Code128',
  code_39: 'Code39', qr_code: 'QRCode', data_matrix: 'DataMatrix', pdf417: 'PDF417',
};

/** Our format for a zxing-wasm format name (`EAN-13` or `EAN13`), or `null`. Pure. */
export function fromZxingFormat(name: string): ScanFormat | null {
  const key = name.replace(/[-_\s]/g, '').toLowerCase();
  for (const f of SCAN_FORMATS) {
    if (ZXING[f].replace(/[-_\s]/g, '').toLowerCase() === key) return f;
  }
  return null;
}

/** The part of the browser's BarcodeDetector the service uses. */
interface Detector {
  detect(source: ImageBitmapSource): Promise<{ format: string; rawValue: string }[]>;
}
type DetectorConstructor = new (options: { formats: string[] }) => Detector;

/** The part of zxing-wasm's reader the service uses. */
interface ZxingReader {
  readBarcodes(input: ImageData, options: { formats: string[]; tryHarder?: boolean }): Promise<
    { format: string; text: string; isValid?: boolean }[]
  >;
}

/** How often the camera is read, in milliseconds. */
const FRAME_MS = 250;

/**
 * B16-T1: decodes codes from a frame or from the device camera. It uses the
 * browser's `BarcodeDetector` when the browser has one, and otherwise
 * loads `zxing-wasm`'s reader on first use (a dynamic import, so the
 * WebAssembly decoder is never in the main bundle). `startCamera` opens the
 * rear camera, reads a frame every 250 ms and emits each code found;
 * without `continuous` it completes after the first. `stop` releases every
 * camera track, as does unsubscribing.
 */
@Injectable({ providedIn: 'root' })
export class ScanService {
  private detector: Detector | null = null;
  private reader: Promise<ZxingReader> | null = null;
  private stream: MediaStream | null = null;
  private timer: ReturnType<typeof setInterval> | null = null;

  /** Overridable for tests: the dynamic import of the zxing reader. */
  protected loadZxing(): Promise<ZxingReader> {
    return import('zxing-wasm/reader') as unknown as Promise<ZxingReader>;
  }

  /** Every code in one frame. */
  async decodeFrame(source: ImageBitmapSource): Promise<ScanResult[]> {
    const Native = (globalThis as unknown as { BarcodeDetector?: DetectorConstructor }).BarcodeDetector;
    if (typeof window !== 'undefined' && 'BarcodeDetector' in window && Native) {
      this.detector ??= new Native({ formats: [...SCAN_FORMATS] });
      const found = await this.detector.detect(source);
      return found
        .filter(f => (SCAN_FORMATS as readonly string[]).includes(f.format))
        .map(f => ({ format: f.format as ScanFormat, rawValue: f.rawValue }));
    }
    this.reader ??= this.loadZxing();
    const reader = await this.reader;
    const image = toImageData(source);
    if (!image) return [];
    const found = await reader.readBarcodes(image, { formats: SCAN_FORMATS.map(f => ZXING[f]), tryHarder: true });
    const out: ScanResult[] = [];
    for (const r of found) {
      const format = fromZxingFormat(r.format);
      if (format && r.isValid !== false && r.text) out.push({ format, rawValue: r.text });
    }
    return out;
  }

  /** Reads the rear camera into `video` and emits the codes it sees. */
  startCamera(video: HTMLVideoElement, opts: { continuous: boolean }): Observable<ScanResult> {
    return new Observable<ScanResult>(subscriber => {
      let busy = false;
      let done = false;
      navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } }).then(stream => {
        if (done) {
          stream.getTracks().forEach(t => t.stop());
          return;
        }
        this.stream = stream;
        video.srcObject = stream;
        void video.play?.();
        this.timer = setInterval(() => {
          if (busy || video.readyState < 2) return;
          busy = true;
          this.decodeFrame(video).then(results => {
            busy = false;
            for (const r of results) {
              if (done) return;
              subscriber.next(r);
              if (!opts.continuous) {
                done = true;
                subscriber.complete();
                return;
              }
            }
          }, error => {
            busy = false;
            subscriber.error(error);
          });
        }, FRAME_MS);
      }, error => subscriber.error(error));
      return () => {
        done = true;
        this.stop();
      };
    });
  }

  /** Releases the camera. */
  stop(): void {
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.stream?.getTracks().forEach(t => t.stop());
    this.stream = null;
  }
}

/** A frame as ImageData, for the zxing reader: drawn onto a canvas when needed. */
function toImageData(source: ImageBitmapSource): ImageData | null {
  if (typeof ImageData !== 'undefined' && source instanceof ImageData) return source;
  const s = source as { videoWidth?: number; videoHeight?: number; width?: number; height?: number };
  const width = s.videoWidth || s.width || 0;
  const height = s.videoHeight || s.height || 0;
  if (!width || !height || typeof document === 'undefined') return null;
  const canvas = document.createElement('canvas');
  canvas.width = Number(width);
  canvas.height = Number(height);
  const ctx = canvas.getContext('2d');
  if (!ctx) return null;
  ctx.drawImage(source as CanvasImageSource, 0, 0, canvas.width, canvas.height);
  return ctx.getImageData(0, 0, canvas.width, canvas.height);
}
