# Trust centre

This page lists the certifications and audit reports that cover Attome, what each one covers, and who
is responsible for each security control under each way of running Attome. The
[responsibility matrix](responsibilities.md) has the control-by-control detail.

## Certifications and reports

| Certification or report | Covers | Status |
|---|---|---|
| SOC 2 Type I (Security) | Attome managed hosting: the deployments Attome runs for customers, the release pipeline and the people who operate them | In preparation. The scope and the evidence map are drafted; no report has been issued yet. |
| SOC 2 Type II (Security; Availability and Confidentiality to be decided) | The same scope, over an evidence period of at least six months | Planned after the Type I. |

No other certificate is held today. This page names a certificate only once it is issued, with its
scope, the issuing body and the period it covers. A customer under NDA can ask their Attome contact
for the current report as soon as one exists.

### What a certificate does and does not cover

A certificate or report covers **Attome managed hosting** only: the service Attome itself runs. It
does not cover:

- **Self-hosted deployments.** The customer runs the servers, the database and the network; their
  own auditors cover that operation. The product features that support their controls (audit chain,
  access reviews, backups, encryption settings) are the same in every deployment.
- **Partner-hosted deployments.** A hosting partner runs the service under its own name and its own
  certifications. Attome's report covers the software release pipeline the partner receives, not the
  partner's operation.

## How Attome can be run

| Profile | Who runs the servers | Who operates the deployment | Whose certificate applies |
|---|---|---|---|
| **Self-hosted** | The customer, on their own machines or cloud | The customer | The customer's own |
| **Partner-hosted** | A hosting partner | The partner, for its customer | The partner's own |
| **Managed** | Attome | Attome, for the customer | Attome's (once issued) |

Every profile gives each customer its own deployment and its own database: no customer's data is
stored with another's. A managed customer inherits the controls Attome operates (marked **Attome** in
the matrix) and keeps the ones only they can operate, such as deciding who gets access and
reviewing it.

## Product security features every profile has

These are part of the software, so they are the same whoever runs it:

- Sign-in with passwords, multi-factor authentication, single sign-on over OpenID Connect (a SAML-only
  identity provider connects through a broker, see [identity brokers](../../identity-brokers.md)) and API keys;
  sessions can be revoked.
- Role-based access at entity, record and field level, with access reviews.
- A tamper-evident audit trail: security, access, configuration and data changes are recorded, and
  the record chain can be verified.
- TLS for every connection the server makes and accepts; secrets kept out of configuration files.
- Backups with restore drills, and file backups checked by SHA-256.
- Releases built and checked by the release gate: dependency licence and advisory checks, a software
  bill of materials, and signed release reports.

## Related

- [Responsibility matrix](responsibilities.md)
- [Install](../install.md): running Attome yourself
- [Partner programme](../partners/README.md): hosting partners
