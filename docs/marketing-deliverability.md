# Marketing email deliverability

How marketing email lands: the dashboard, the check before a send, the alerts, the sunset policy,
blocklists, sender reputation and DMARC reports. Everything here belongs to the marketing pack and is
set on one record, the **deliverability policy** (`marketing_deliverability_policy`), which you change
like any record (it is audited). Setting up the sending domain itself (SPF, DKIM, DMARC records) is in
[The sending domain](email/sending-domain.md).

## What is on, what is off

| Part | Default | Switch it on |
|---|---|---|
| Dashboard, per-send figures, pre-send check | on | nothing to do |
| Bounce and complaint alerts | on | thresholds on the policy |
| Sunset policy | off | `sunset_enabled`, plus a re-engagement design and purpose |
| Blocklist checks | off | `blocklist_enabled`, and the lists you may query in `marketing.blocklist_zones` |
| Google Postmaster reputation | off | `postmaster_enabled`, and a Postmaster integration |
| Microsoft SNDS reputation | off | `snds_enabled`, and an SNDS integration |
| DMARC reports | upload only | see below |

## The dashboard

`GET /api/v1/marketing/deliverability/overview` gives the figures the deliverability screen shows: delivery,
bounce, complaint, open and click rates per mailbox provider and day, totals per send, recent alerts,
blocklist status and the share of mail passing DMARC. `GET .../deliverability/daily` lists the daily
figures a page at a time (by sending domain, provider and dates) and
`GET .../deliverability/sends/{send_id}` one send's totals per provider.

## The check before a send

`POST /api/v1/marketing/precheck` scores one rendered email and its audience from 0 to 100 and lists what
lowers the score: spam wording (English and Arabic), mostly images, links to blocklisted domains, no
unsubscribe link, no plain-text part, a message over 100 KB, an audience mostly never mailed before, and
more than 5% invalid addresses. It sends and stores nothing; the send screen shows the findings.

`POST /api/v1/marketing/address-check` checks addresses before you add them (at most 60 checks a minute
per person).

## Alerts

Every day the previous day is checked, and the people in the policy's `marketing_owner_role` and the
administrators are told, in English and Arabic, when:

- the bounce rate for a sending domain and provider passes `bounce_warn_percent` (default 2%) or the
  complaint rate passes `complaint_warn_percent` (default 0.3%), once enough mail was sent to judge;
- a sending domain or IP newly appears on a blocklist;
- the share of mail failing DMARC at least doubles from one day to the next;
- a reputation source reports a drop (Postmaster high, medium, low, bad; SNDS green, yellow, red).

Each alert is raised once per subject, kind and day.

## Sunset

With `sunset_enabled` on, every night people who have not engaged with marketing (opened, clicked or sent
a form) for `sunset_months` months get **one** re-engagement email: the policy's re-engagement design,
sent for its re-engagement purpose to those who consent. Anyone who has still not engaged some days later
is sunset and left out of every campaign. Engaging again at any time brings a person back.

## Blocklists

No blocklist is queried by default, because each list's terms decide who may query it (the commercial
lists need a subscription). Name the lists you are entitled to in the setting `marketing.blocklist_zones`
(for example your Spamhaus DQS zone) and the sending IPs in `marketing.blocklist_ips`, then turn on
`blocklist_enabled`. Every day each sending domain from the last 30 days and each IP is looked up once.

## Reputation

Turn on `postmaster_enabled` (Google Postmaster Tools, per sending domain) or `snds_enabled` (Microsoft
SNDS, per sending IP) after adding the matching integration with its credentials. One reading per day is
kept in the deployment.

## DMARC reports

1. Publish a DMARC record for the sending domain whose `rua` address is a mailbox you can read, as
   [The sending domain](email/sending-domain.md) shows: start with `p=none`.
2. Receivers send aggregate reports there, usually daily, as XML, gzip or ZIP attachments.
3. Upload each report file to `POST /api/v1/marketing/deliverability/dmarc/upload` (the file as the body,
   at most 20 MB; administrators only). A report uploaded twice is stored once.
4. Read the results per sending source at `GET /api/v1/marketing/deliverability/dmarc`; the dashboard shows
   the pass share, and a jump in failures raises an alert.

Reading reports straight from the mailbox is not built yet, and the policy's `dmarc_enabled` switch has
no effect until it is.
