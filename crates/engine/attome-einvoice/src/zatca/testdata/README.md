# ZATCA sample invoices

`simplified_invoice_signed.xml` and `standard_invoice_signed.xml` are the signed sample outputs of
[Saleh7/php-zatca-xml](https://github.com/Saleh7/php-zatca-xml) (`examples/*/output/`, MIT
License, Copyright (c) 2023 ~/Saleh), a library built to match ZATCA's Java SDK. Their
`invoiceSignedData` digest is the invoice hash, which `zatca::hash` must reproduce. Keep them
unchanged: any edit changes the hash.
