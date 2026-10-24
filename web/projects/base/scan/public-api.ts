/*
 * @attome/base/scan — decoding barcodes and QR codes from the device camera
 * (B16-T1): the browser's BarcodeDetector where it exists, else zxing-wasm,
 * loaded only when first needed.
 */
export { SCAN_FORMATS, ScanService, fromZxingFormat } from './scan.service';
export type { ScanFormat, ScanResult } from './scan.service';
