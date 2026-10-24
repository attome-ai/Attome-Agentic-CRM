# Responsibility matrix

Who operates each security control, for each way of running Attome. **Customer**, **Partner** and
**Attome** name the party that operates the control; "shared" means each party does the part named.
The profiles are described on the [trust centre](README.md#how-attome-can-be-run) page.

The product supplies the features behind most controls in every profile (the last column). Using
them, and proving they are used, belongs to whoever operates the deployment.

## Infrastructure

| Control | Self-hosted | Partner-hosted | Managed | What the product gives |
|---|---|---|---|---|
| Physical security of servers and data centre | Customer | Partner | Attome (through its cloud provider) | — |
| Network, firewall and TLS edge | Customer | Partner | Attome | the TLS edge configuration, or the built-in TLS listener |
| Operating system patching | Customer | Partner | Attome | — |
| Database, cache and object store operation | Customer | Partner | Attome | health and readiness checks, pool and queue metrics |
| Encryption in transit | Customer | Partner | Attome | TLS to and from every service |
| Encryption of disks and backups at rest | Customer | Partner | Attome | encrypted audit values; at-rest encryption is the database's and the store's |
| Backups and restore drills | Customer | Partner | Attome | backup and restore commands, drill reports, SHA-256 file manifests |
| Capacity, monitoring and alerting | Customer | Partner | Attome | metrics, built-in alerts and runbooks |
| Incident response for the hosting | Customer | Partner | Attome | security events and the audit trail as evidence |

## The application

| Control | Self-hosted | Partner-hosted | Managed | What the product gives |
|---|---|---|---|---|
| Upgrading to new releases | Customer | Partner | Attome | the upgrade guide and the preflight checks |
| Secure development and release | Attome | Attome | Attome | the release gate: tests, dependency and licence checks, SBOM, signed reports |
| Vulnerability fixes in Attome's code | Attome | Attome | Attome | fixes shipped in releases |
| Applying a security release | Customer | Partner | Attome | — |
| Configuration of security settings (password rules, multi-factor authentication) | Customer | Shared: partner sets the defaults, customer decides | Shared: Attome sets the defaults, customer decides | the security settings and their audit |
| Secrets for the deployment (keys, database passwords) | Customer | Partner | Attome | secrets read from the environment, never from committed files |
| Audit trail retention and chain verification | Customer | Partner | Attome | the audit chainer and the chain verifier |

## People and data

| Control | Self-hosted | Partner-hosted | Managed | What the product gives |
|---|---|---|---|---|
| Who gets an account, and with which roles | Customer | Customer | Customer | users, roles, teams, record and field access |
| Access reviews | Customer | Customer | Customer | the access review job and its reports |
| Removing leavers | Customer | Customer | Customer | deactivation, session revocation, SCIM from an identity provider |
| Single sign-on and the identity provider | Customer | Customer | Customer | OpenID Connect sign-in |
| Classifying data and choosing what is sensitive | Customer | Customer | Customer | sensitive fields with field-level grants |
| Data the customer loads, and its lawful basis | Customer | Customer | Customer | consent and retention features |
| Requests from data subjects | Customer | Customer, with partner support | Customer, with Attome support | export, erasure and the audit of both |
| Access by the operator's staff to customer data | — | Partner: only under the customer's agreement | Attome: only under the customer's agreement, recorded | every staff sign-in recorded in the audit trail |
| Exporting data and leaving | Customer | Customer, partner hands over | Customer, Attome hands over | record export through the API and views |

## Reading the matrix for a managed customer

A managed customer inherits every control marked **Attome**: Attome operates it and its report
(once issued, see the [trust centre](README.md#certifications-and-reports)) covers it. The controls
marked **Customer** are the customer's in every profile; the customer's own auditors look at those,
using the product's reports as evidence.
