# Printing labels

A document template can draw codes for a record's fields and print one label per record into a single PDF
(B16-T12).

## Codes in a template

Name `qr_<field>` or `barcode_<field>` as an image source:

```html
<img src="{{ qr_asset_tag }}" alt=""> <img src="{{ barcode_asset_tag }}" alt="">
<p>{{ asset_tag }} · {{ name }}</p>
```

`qr_<field>` is a QR code and `barcode_<field>` a Code 128 barcode (printable ASCII, up to 48 characters)
of the field's value, drawn on the server as SVG, so the renderer needs no script. A field the reader
cannot see, or a value a barcode cannot carry, draws nothing.

## A sheet of labels

`POST /api/v1/docgen/templates/{id}/render-labels` with `{"record_ids": [...]}` (1 to 500, in order)
renders the template once per record, as the caller, into one PDF: each record is a
`<section class="label">`, so the template's stylesheet sets the label size and page breaks (for example
`.label { break-inside: avoid; }`). A record the caller cannot see is left out. The answer names the render;
`GET /api/v1/docgen/renders/{id}` shows it and its file when done.
