/*
 * @attome/base/scan — decoding barcodes and QR codes from the device camera
 * (B16-T1): the browser's BarcodeDetector where it exists, else zxing-wasm,
 * loaded only when first needed; and drawing QR codes and barcodes as SVG.
 */
export { SCAN_FORMATS, ScanService, fromZxingFormat } from './scan.service';
export type { ScanFormat, ScanResult } from './scan.service';
// B16-T11 — drawing codes, with bwip-js loaded on first use.
export { renderCode } from './code-render';
export type { CodeKind } from './code-render';
