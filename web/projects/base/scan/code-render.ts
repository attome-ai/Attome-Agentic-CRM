/** The codes the app draws. */
export type CodeKind = 'qr' | 'code128' | 'ean13' | 'datamatrix';

/** bwip-js names for ours. */
const BCID: Record<CodeKind, string> = { qr: 'qrcode', code128: 'code128', ean13: 'ean13', datamatrix: 'datamatrix' };

/** The part of bwip-js the renderer uses. */
interface Bwip {
  drawingSVG(): unknown;
  qrcode(opts: object, drawing: unknown): string;
  code128(opts: object, drawing: unknown): string;
  ean13(opts: object, drawing: unknown): string;
  datamatrix(opts: object, drawing: unknown): string;
}

let loading: Promise<Bwip> | null = null;

/**
 * B16-T11: draws `text` as a QR code, Code 128, EAN-13 or Data Matrix and
 * returns the SVG markup. bwip-js is imported on first use, so it lives in a
 * lazy chunk, and only these four symbologies are referenced. Throws for
 * text the symbology cannot hold (an EAN-13 needs 12 or 13 digits).
 */
export async function renderCode(kind: CodeKind, text: string): Promise<string> {
  loading ??= import('bwip-js/browser') as unknown as Promise<Bwip>;
  const bwip = await loading;
  const linear = kind === 'code128' || kind === 'ean13';
  const opts = { bcid: BCID[kind], text, scale: 3, ...(linear ? { includetext: true, textxalign: 'center', height: 12 } : {}) };
  const draw = { qr: bwip.qrcode, code128: bwip.code128, ean13: bwip.ean13, datamatrix: bwip.datamatrix }[kind];
  return draw(opts, bwip.drawingSVG());
}
