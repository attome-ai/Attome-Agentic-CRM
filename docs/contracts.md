# Contracts

Contract management is the `contract-management` pack (`packs/contract-management/changesets/`)
on top of the contract engine (`crates/engine/attome-contract`, module `contract`). The pack
defines the records; the engine adds drafting, comparison, the playbook check, negotiation,
signature, imports and the background jobs. This guide starts with the smallest useful setup and
adds one part at a time.

## The smallest setup: a repository with renewal reminders

Install the pack with its dependencies (`crm`, `sales`, `finance`, `regions`, `vendor-supplier`,
then `contract-management`) and turn on the `contract` module. You then have:

- **Contracts** with a type, counterparty (free text, or an account or vendor), owner, value and
  currency, start and end dates, notice period, automatic renewal and renewal term, and a
  confidential flag.
- **Clauses** (`contract_clause`, bilingual rich text, from the clause library `clause`),
  **obligations** (owner, who owes it, due date, recurrence, evidence) and **amendments** (terms
  that take effect on a date; the contract's current terms are recomputed from them).
- **Roles**: Contract Requester (their own requests, no values or terms), Contract Viewer (reads,
  no values or terms, no confidential contract), Contract Manager (everything but confidential
  contracts) and Legal (everything, plus contract types and playbook rules).

Renewal reminders need nothing else. The nightly `ContractKeyDates` job keeps each approved or
active contract's `notice_deadline` (end date less the notice period), opens one task "Renew,
renegotiate or terminate" for the owner 30 days before the deadline, reminds obligation owners 7
days before a due date, escalates overdue obligations to the contract's owner, rolls recurring
obligations forward and applies amendments that took effect. Both lead times are fixed in this
version.

Contracts also come from the business: an accepted quote or a confirmed order drafts a sales
contract, and a service request under a contract type's intake offering drafts one of that type
(`ContractLinkSweep`, every 15 minutes). Free-text counterparties get a proposed account for a
person to confirm (`POST /api/v1/contract/counterparty-match/run`,
`POST /api/v1/contract/counterparty-proposals/{id}/decide`).

Ended contracts are proposed for review by a retention rule that boot adds once; change its
period or action at `/api/v1/admin/retention/rules`. A contract under a legal hold is never
proposed and cannot be deleted.

Views: My Contracts, Expiring by Notice Deadline, Obligation: Due and Deviations to Review.
Reports: Expiring in 90 Days, Value Under Management, Obligation On-Time %, Cycle Time by Stage
(drafting, negotiation and signature, from the contract's versions) and Playbook Deviation Count.

## Drafting

Give a contract type a document template (`draft_template_ref`, a K3 template). Then
`POST /api/v1/contract/contracts/{id}/draft` adds the contract's next version and renders the
template against the contract and its clauses in the background; the document is attached to the
version's `file`. The template sees only what the requester may read.

`POST /api/v1/contract/contracts/{id}/compare` with two versions compares them in the background
(`contract_compare` job): section by section, a word-level diff, and the sections that match a
library clause but are like neither its standard text nor its fallbacks. The comparison screen is
`contract/compare/:id` in the web app.

Old contracts come in through their files: create a `contract_import` with the file, then
`POST /api/v1/contract/imports/{id}/propose` proposes the fields (English or Arabic) with a
confidence each, and `POST /api/v1/contract/imports/{id}/accept` creates the contract and its
obligations from what a person reviewed. Nothing is saved before a person accepts.

## The playbook

Legal writes `contract_playbook_rule` records: a condition in the rule language, optionally for
one clause key, and a severity (`info`, `needs_legal` or `block`). Every save of a contract or one
of its clauses is checked: deviations are kept in the contract's `playbook_deviations`, and a
`block` rule refuses the save. A `needs_legal` deviation adds Legal to the approval.

## Approval

Submitting a draft (`POST /api/v1/contract/{id}/transition` to `approved`) holds it in `review`
under the pack's approval plan: a contract manager approves; Legal too when the playbook marked a
deviation that needs legal; Legal again above a value of 1,000,000. Approvers decide at
`POST /api/v1/approvals/{id}/decide`; a rejection returns the contract to draft. Submit, approve,
activate and terminate each need their privilege (`contract.submit`, `contract.approve`,
`contract.activate`, `contract.terminate`).

## Negotiation

`POST /api/v1/contract/contracts/{id}/share-for-review` emails the counterparty a link for the
next round and closes the round before. Through the link (`GET` and `POST
/api/v1/contract/review/{token}`, no account needed) the counterparty reads the current version,
comments, and sends back a PDF or Word version of at most 7 MB, which ends the round. Once the
virus scan passes, the `ContractReviewSweep` job (every five minutes) sets the file on a new
version (source `counterparty_upload`) and queues its comparison with the version before. Each
round is a note on the contract's timeline; the link shows nothing of other contracts and no
internal note.

## Signature

`POST /api/v1/contract/contracts/{id}/send-for-signature` sends an approved contract's latest
version to its signers, in order, through an electronic signature envelope (email codes). When
everyone has signed, the `ContractSignatureSweep` job (every five minutes) adds a `signed`
version and makes the contract active as the person who sent it; a declined or voided envelope
leaves it approved. The envelope keeps the completion certificate. National identity signing
(Nafath, UAE Pass) is not available yet.

## Agents

Read-only actions, each limited to what the person behind the agent may read:
`contract.summarise` (terms, clause titles, open obligations), `contract.review_against_playbook`
(deviations with the library's fallback clauses) and `contract.answer` (an answer from clause
text with citations, declined when the clauses do not answer the question; needs a model for the
`contract.answer` task). No action approves, signs or edits a contract.

## Settings

| Setting | Default | What it does |
|---|---|---|
| `contract.review_link_days` | 14 | Days a counterparty review link stays valid (1 to 90). |

## Jobs

| Job | When | What |
|---|---|---|
| `ContractKeyDates` | nightly | Notice deadlines, renewal tasks, obligation reminders and escalations, amendments. |
| `ContractLinkSweep` | every 15 minutes | Drafts contracts from accepted quotes, confirmed orders and intake requests. |
| `ContractReviewSweep` | every 5 minutes | Sets scanned counterparty versions and queues their comparisons. |
| `ContractSignatureSweep` | every 5 minutes | Activates contracts whose envelopes completed. |
| `contract_compare` | on request | Compares two versions. |
| `ContractCounterpartyMatch` | on request | Proposes accounts for free-text counterparties. |
