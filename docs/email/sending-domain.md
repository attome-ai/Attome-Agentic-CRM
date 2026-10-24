# The sending domain: SPF, DKIM and DMARC

Mail from `noreply@example.com` is delivered, rather than filed as spam or
refused, when `example.com` publishes three DNS records that say who may
send for it. Add them at the company that hosts the domain's DNS. Attome
does not check them for you yet (roadmap Z8-T4), so check them by hand with
the commands below.

## SPF: who may send

One TXT record on the domain itself lists every service allowed to send as
it. There must be exactly one; when you add a service, extend the record
rather than adding a second.

| Provider | What SPF needs |
|---|---|
| Amazon SES | nothing on the domain by default (SES uses its own MAIL FROM); with a custom MAIL FROM subdomain, `include:amazonses.com` on that subdomain |
| SendGrid | nothing by hand: the return-path CNAME from domain authentication covers it |
| Your own relay or office mail | what that service documents, e.g. `include:spf.protection.outlook.com` |

```
example.com.  TXT  "v=spf1 include:spf.protection.outlook.com ~all"
```

## DKIM: a signature receivers can check

The provider signs each message and publishes the public key in DNS. SES and
SendGrid give you CNAME records to add (SES three, SendGrid two DKIM records
plus a return path); copy them exactly. An SMTP mail service gives its own
DKIM record or CNAME.

## DMARC: what receivers should do on a failure

One TXT record at `_dmarc`. Start by only collecting reports, then tighten
once the reports show your mail passing:

```
_dmarc.example.com.  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@example.com"
```

Move `p=none` to `p=quarantine` and then `p=reject` over a few weeks.

## Check the records

DNS changes can take up to a day to be seen everywhere.

Windows (PowerShell):

```powershell
Resolve-DnsName -Type TXT example.com          # SPF
Resolve-DnsName -Type TXT _dmarc.example.com   # DMARC
Resolve-DnsName -Type CNAME <selector>._domainkey.example.com   # DKIM
```

Linux and macOS:

```sh
dig +short TXT example.com
dig +short TXT _dmarc.example.com
dig +short CNAME <selector>._domainkey.example.com
```

Then send a message to an outside mailbox (Gmail shows *Show original*,
Outlook *View message source*) and look for `spf=pass`, `dkim=pass` and
`dmarc=pass` in the `Authentication-Results` header.

## Before going live

Set `email.test_mode_catch_all` on development and copied deployments: every
message then goes to that one address instead of its recipients, so a
deployment restored from production never mails a real customer.
