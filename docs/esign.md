# E-signature and the PDF seal

An envelope carries up to ten documents and up to twenty signers, each with a
role and a signing order. The owner sends it (`POST /api/v1/esign/envelopes`,
then `…/{id}/send`); each signer gets a personal link, reads the envelope,
asks for a six-digit code by email and signs with the code and their typed
name, or declines. Every step is an event chained by hash, so a changed or
removed event shows. When the last signer signs, the envelope is completed and
keeps its completion certificate: the documents with their SHA-256 as sent,
each signer with when, from which address and how they were checked, the
events, and the chain's last hash.

## The seal

When the deployment has a signing certificate, each PDF of a completed
envelope also gets a sealed copy: the same file with a PAdES signature
(`ETSI.CAdES.detached`) made with the deployment's certificate. The seal
covers the whole file, so any later change to the copy shows in a PDF reader
or validator as a broken signature. The original file is kept as it was
signed; the sealed copy carries it unchanged as its first revision, and the
certificate's hashes still name the original.

The seal says the deployment holds the document as everyone signed it, under
the reason "Signed by everyone (title); certificate (hash)". It is the
platform's seal, not each signer's own signature: the signers' identity
evidence is the completion certificate.

Set both files in the configuration (`esign` section):

| Key | What |
|---|---|
| `esign.seal_certificate_file` | The PEM certificate chain, the signing certificate first. RSA (2048 bits or more) or P-256. |
| `esign.seal_key_file` | The signing certificate's private key, PEM: PKCS #8 (`BEGIN PRIVATE KEY`), or PKCS #1 for RSA. Readable by the server only. |

Leave both empty (the default) and envelopes are not sealed. Use a
certificate your recipients' readers trust (a document-signing certificate
from a trusted CA, or one from your organisation's CA that they import);
a self-signed certificate validates as intact but "unknown signer".

The seal is made by a job after the envelope completes, off the request.
A document that is not a PDF, is encrypted, or cannot be read keeps the
reason and is not sealed; the envelope view lists each document's seal
(`seals`: the sealed copy's SHA-256 and time, or the reason). If the key was
missing or wrong when the envelope completed, fix it and queue the seal again
with `POST /api/v1/esign/envelopes/{id}/seal`; documents already sealed are
left as they are.

The owner (or an administrator) downloads a sealed copy at
`GET /api/v1/esign/envelopes/{id}/documents/{document_id}/sealed`.

### What it was checked with

The seal was checked with pyHanko 0.38 in strict mode and qpdf (through
pikepdf) on PDFs from Chrome and wkhtmltopdf, each also rewritten with object
streams and linearised: every signature intact and valid, covering the entire
file, and a second seal on a sealed file accepted as an allowed form-filling
change over the first. No timestamp is added (RFC 3161), so the signing time
is the server's clock as written in the signature.
