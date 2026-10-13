// jsdom 27 implements neither `File.prototype.arrayBuffer()` nor
// `Blob.prototype.arrayBuffer()` — confirmed live here: both throw "is not a
// function", which broke every real-file-read path (field-input.component's
// upload checksum) the moment its spec actually ran for the first time. All
// real browsers implement both (File inherits Blob's), so this is a
// test-environment gap, not a product bug. jsdom's `FileReader` does work,
// so it's the polyfill's read path.
function arrayBufferViaFileReader(this: Blob): Promise<ArrayBuffer> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result as ArrayBuffer);
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(this);
  });
}

if (typeof Blob !== 'undefined' && typeof Blob.prototype.arrayBuffer !== 'function') {
  Blob.prototype.arrayBuffer = arrayBufferViaFileReader;
}
if (typeof File !== 'undefined' && typeof File.prototype.arrayBuffer !== 'function') {
  File.prototype.arrayBuffer = arrayBufferViaFileReader;
}
