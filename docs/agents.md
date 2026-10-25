# Agents

How agents are defined, what they may do, and how they are held to it. Decisions: V2-D486, V2-D487.

## Defining an agent

An agent is an `agent` metadata object (`crates/engine/attome-model/src/kinds/agent.rs`), edited like
any other kind: as a draft through `POST /api/v1/admin/model/agent/{id}/commands`, published through
`.../publish`, or in the designer at `/model/agents`.

```json
{ "role": "Support triage",
  "instructions": "Read new cases and propose the queue and priority.",
  "tools": ["record.get", "record.schema", "record.update"],
  "identity": { "run_as": "caller" },
  "limits": { "max_steps": 20, "max_tool_calls": 40, "max_tokens": 60000,
              "daily": { "record_changes": 200, "deletes": 0 } },
  "triggers": [{ "kind": "record_change", "entity": "<entity id>" }],
  "channels": ["chat"],
  "persona": { "language": "ar", "temperature": 0.2 } }
```

To run sessions from the agent itself, give it `"policy": "<ai_agent_policy id>"` (its organisation
ceiling) and `"persona": { "model": "<ai_model id>" }`, publish it, and start one with
`POST /api/v1/model/agents/{agent}/sessions` (`{ "risk_ceiling": "reversible" }`).

Saving checks the tools exist, the limits are within the platform ceilings and each trigger's entity
exists at publish.

## What an agent may do

Effective authority is a conjunction, and nothing in a definition widens it: the person's own
privileges, the session's ceiling and allow-list, the organisation's agent policy, and the agent's
own tools. A session started with `agent` (`POST /api/v1/agents/{id}/sessions`) takes the published
agent's tools as one more allow-list and its `limits.daily` as per-day caps.

- **Writes need a person, unless an administrator says otherwise.** With no autonomy level set,
  every write action stops at confirmation for an agent and consequential ones need a second
  person's approval.
- **Autonomy levels (AH8, V2-D693).** Per agent and per action, an administrator sets how much the
  agent may do alone: `suggest` (a person does it), `ask_first`, `act_on_review` (it is staged
  with the session's other staged actions until the person applies or discards them, V2-D702),
  `act_with_undo` (it waits in an undo window, then runs), `act_and_report` (it runs and tells the
  person) or `automatic`.
  `GET /api/v1/admin/ai/agents/{agent}/autonomy` lists every action with its level;
  `PUT .../autonomy/{action_id}` (`{ "level": "act_with_undo", "undo_seconds": 300,
  "daily_limit": 50 }`, with optional `money_cap_minor` and `currency`, `owned_records_only`,
  `hours_start`/`hours_end`/`time_zone`) sets one and `DELETE` returns it to the built-in rule
  (screen: the agent form's Autonomy tab). Going over a limit asks first. Untrusted text the agent
  read (an inbound email, a document) always lowers the level by one, and `memory.remember` takes no
  level at all.
- **Review a batch.** At `act_on_review` a call answers `awaiting_review`: nothing ran, and the
  agent cannot build on the result. The person applies the staged actions with
  `POST /api/v1/ai/deferred-actions/apply` (`{ "agent_session_id": "…" }` for the whole session, or
  `{ "ids": [...] }`, optionally `"undo_window_seconds"`) or drops them with `.../discard` (screen:
  the review section of `/ai/pending-actions`). Applied actions run in the order they were staged,
  each re-checked like an approved one; each ends with its own result.
- **Trial before going live (AH6).** A definition in status `testing` starts sessions on its real
  triggers, but every write or outside call it is allowed to make is recorded in
  `ai_trial_decision` instead of run (the agent is told it was recorded); reads run for real, and
  the public web chat refuses a testing agent. Hourly, each decision older than a day is compared
  with what a person did to the same record in that day (`same`, `different` or `none`, from the
  audit trail). `GET /api/v1/admin/ai/agents/{agent}/trial-report` shows the agreement, per action
  and with the steps a person did differently; `POST .../go-live` (`{ "row_version": 3,
  "min_agreement": 0.9 }`) sets the definition `active`, refused below the threshold or with fewer
  than 30 compared steps (screen: the agent form's Trial tab).
- **Earned autonomy (AH8-T9).** When an action's trial agreement over the last 28 days reaches 98%
  over at least 200 compared steps, the hourly job proposes raising its level by one step; a
  consequential action is never proposed past `act_on_review`. An administrator accepts or rejects
  it (`GET .../autonomy/proposals`, `POST /api/v1/admin/ai/autonomy/proposals/{id}/accept|reject`;
  screen: the Autonomy tab). A proposal expires after 14 days, and one whose level changed since is
  refused.
- **Daily summary (AH8-T8).** Once a day each person gets one in-app note counting what their
  agents ran on their own at `automatic`; `act_and_report` steps were reported as they ran.
- **The undo window.** Any write can be held before it runs, including one that cannot be undone
  afterwards (an email, a payment, a call to another system): an agent at `act_with_undo`, an agent
  that passes `_undo_window_seconds` in a tool call, or a person through
  `POST /api/v1/actions/{id}/invoke` with `undo_window_seconds`. The call answers `scheduled` with
  `run_at`; the person cancels it until then with `POST /api/v1/ai/deferred-actions/{id}/cancel`
  (screen: `/ai/pending-actions`). Just before it runs it is checked again like an approved action,
  and an agent's is put through the gate with today's level, so a level lowered during the window
  asks for approval instead.
- **Per-write approval (off by default).** `POST /api/v1/admin/ai/write-policies`
  (`{ "action_id": "record.update", "entity": "invoice" }`) makes that agent write wait for a second
  person after it is confirmed; `DELETE .../{id}` turns it off.
- **Daily limits** count an agent's steps by class (record changes, deletes, messages, outside
  calls) across all its sessions; at the cap the step is refused.
  `GET /api/v1/admin/ai/agents/{agent}/usage` shows today's use.
- **Switches.** `PUT /api/v1/admin/ai/switches/{kind}/{key}` turns an agent, model, provider, tool or
  channel off at once (screen: `/ai/switches`). Turning it back on takes a different administrator.

## Tools agents get

- Records: `record.get`, `search.records`, `query.execute`, `record.schema` (an entity's typed input),
  `record.validate` (a dry run of a create), `record.create|update|delete|restore`, `record.deleted`
  (the deleted records you may see, to restore), `record.assign`,
  `record.transitions` and `record.transition` (move a stage or status through the state model; a
  move that needs approval goes to its pending state and asks for it).
- Many records: `record.bulk.preview` (count, a sample of what changes, problems), then
  `record.bulk.update|delete` (up to 500, run by the bulk engine, approved by a second person) and
  `record.bulk.status` (each record's result). A replayed call never applies twice.
- Questions: `query.plan` turns a question into a checked query (entity, filters, order, limit) and
  returns the issues to fix, or a description for the person and the `query.execute` arguments that
  run it. The model never writes SQL.
- AI attributes: an attribute whose options carry `"ai": { "prompt": "Summarise {{description}}..." }`
  is filled by `record.ai_field` as a suggestion a person accepts or rejects.
- Communication: `email.draft` files a draft for a person to send; `email.send` sends now, or after
  an undo window. It is consequential: an agent's send needs approval unless its level allows more. `text.translate`
  translates text keeping names, numbers and the deployment's terms (`inference.translation.glossary`).
- Building: `model.<kind>.describe|list|edit` for every metadata kind, found over MCP with
  `tools.search`; edits are drafts a person confirms.
- Outages: `system.status` lists the services (object storage, email, the job queues) and which are
  down. A call refused because one is down names it under `degraded` with `retryable`: `true` for a
  short outage, `false` once it has lasted five minutes, so the agent stops and tells the person.
- Follow-ups: `followup.remind_owner` (an in-app reminder to the owner of a stalled record, marking
  the follow-up item reminded) and `followup.send_message` (the drafted message by email or as an
  internal message, marking the item sent; consequential, so a person approves an agent's call).
  Both act only on the caller's own open items and under the rule's `daily_cap`, counted per rule
  since midnight UTC.
- Competitors: `sales.competitors.on_deal` (the competitors on a deal with their battle card),
  `sales.battlecard.get` (a competitor's card and its knowledge article),
  `sales.winloss.draft_review` (a deal's win-loss review drafted from the deal and its notes, emails
  and call findings) and `sales.battlecard.draft_update` (a card update drafted from the last 20 loss
  reviews). All read as the person; the drafts are never saved or published.
- Billing: `billing.find_invoices` (invoices the person may read, by account, status, payment status
  or number), `billing.account_balance` (what an account owes per currency), `billing.explain_tax`
  (a line's VAT facts and the tax engine's decision, in Arabic and English) and the draft-only
  `billing.draft_invoice` and `billing.draft_credit_note`, which an agent's call files only after a
  person confirms. Issuing, cancelling, issuing a credit note and writing off stay with people.
- Subscriptions (reads only): `billing.subscription.read` (a subscription as of a date, each line's
  quantity and price that day), `billing.usage.read` (metered usage per line and metric between two
  dates), `billing.amendment.draft` (what an amendment would do, with its proration) and
  `billing.renewal.draft` (the next term's dates and lines). The drafts change nothing: amending,
  cancelling, renewing and changing a price stay with people.
- Deliverability (reads only, marketing): `deliverability.explain` compares a date range of the daily
  deliverability rollup with the range before it and lists the biggest changes in delivery, bounce,
  open and complaint rates by mailbox provider and send; `deliverability.propose_segment` drafts a
  segment of people engaged recently and not sunset, saving nothing. Neither lifts a suppression or
  changes DNS or the policy.
- Org charts (sales; no manager is set): `sales.orgchart.read` reads an account's chart,
  `sales.committee.read` a deal's buying committee (influence and attitude only through the Deal
  Attitude profile) and `sales.coverage.gaps` just its gaps; `sales.orgchart.propose` queues
  proposals for an account's unplaced people, from their titles and departments, written as open
  drafts a person accepts or rejects (confirmed first).
- Dialer (sales; nothing dials): `sales.call_list.build` creates a draft call list from a description
  (and a saved view) for a person to fill and activate; `sales.call_list.order` reorders a list's
  waiting members by points score or deal risk, saying which data is missing rather than guessing;
  both are confirmed first. `sales.call.draft_notes` drafts notes for a call attempt from its
  recording's transcript (summary and next steps, extracted locally) and saves nothing.
- Service levels (administrators): `ops.slo_health` lists each SLO class with its status and the share
  of its 30-day error budget left, from the server's own metrics store.
- Database cluster (with the ops module): `ops.cluster_status` (`ops.read`) reads the members, lag,
  synchronous standby and last failover; `ops.propose_switchover` (`ops.cluster.switchover`) only
  creates the switchover approval request. A second person in the Operations role approves it, never
  an agent, and only then does the server ask Patroni to move the leader.
- Recovery drills (with the ops module, `ops.read`, reads only): `ops.drill_freshness` says whether each
  drill kind is fresh, stale, failed or never run, with the checks the last run failed;
  `ops.drill_evidence` reads one drill's numbers and check results. No tool uploads or changes evidence.
- Upgrades (with the ops module, `ops.read`, read only): `ops.upgrade_status` reads the latest upgrade, its
  check report and how it ended; starting or rolling back an upgrade stays with people.
- Secrets (administrators, reads only): `secrets.list` names every configured secret with the
  features that use it, whether it is set and how many days its active key has been in use. It never
  returns a value or a key id, and there is no tool that writes or rotates a secret.
- Tables (administrators, reads only): `table.health` reads an entity table's size, dead rows,
  unused indexes and unindexed lookups; `table.index_proposals` lists the indexes slow statements
  suggest; `table.change_plan` previews how structure changes would run, with estimates. None
  applies anything: an agent proposes, and a builder makes the change.

## Delegating to a specialist

An agent object may declare a typed contract other agents hand it work through:

```json
"handoff": {
  "input":  { "type": "object", "required": ["account_id"], "properties": { "account_id": { "type": "string" } } },
  "output": { "type": "object", "required": ["risk"], "properties": { "risk": { "enum": ["low", "medium", "high"] } } }
}
```

A supervisor calls `agent.delegate` with the specialist's id and an input that matches. The
specialist runs in a child session of the supervisor's (one run tree: `parent_session_ref`), with
only its read tools and at most ten steps, and its answer comes back as a JSON object checked against
the output contract. Specialists never write and never delegate again; the supervisor composes the
answers and proposes any change through its own gate.

## Running

- From a trusted partner: `GET /api/v1/a2a/agents` lists the agents with a handoff contract;
  `POST /api/v1/a2a/agents/{agent}/tasks` with `{ "input": ... }` runs one read-only task.

- Over MCP: `initialize` with `"params": { "agent": "<agent object id>" }` runs the connection as
  that agent (its tools and daily limits, under the connecting person's own privileges).

- In chat: `POST /api/v1/ai/conversations/{id}/messages`. Start the conversation with
  `"mode": "develop"` to build (metadata drafts only) or `"run"` to act on records.
- In the background: `POST /api/v1/ai/conversations/{id}/runs` returns at once; follow
  `GET /api/v1/ai/conversations/{id}/stream`.
- What a session did: `GET /api/v1/admin/agents/sessions/{id}/trace` (the Steps button on the agent
  sessions screen).

## Follow-up agent

Finds records that went quiet and follows them up for their owner. Nothing happens until an
administrator adds a rule (an `ai_followup_rule` record, under AI in the admin area); there is
none by default.

- **What a rule finds** (`reason`, on the rule's `target_entity`, after `idle_days`):
  `stalled_deal` is an open record (a `stage` other than `closed_won`/`closed_lost`, or
  `is_closed` false) untouched for `idle_days` (its `last_activity_at`, else its last change);
  `overdue_task` is an open record past its `due_at` or `due_date`; `unanswered_customer` is a
  conversation whose newest message is inbound, older than `idle_days`, with no reply after it.
  Each record is recorded at most once a week (`ai_followup_item`).
- **When:** every hour. `POST /api/v1/admin/ai/follow-up-rules/{id}/run` runs one rule now.
- **What it does** (`mode`): `remind_owner` sends the owner an in-app reminder.
  `draft_message` has the `followup_agent` draft a message, filed as an email draft on the record,
  and reminds the owner. `send_message` has it draft the message and send it with
  `followup.send_message`, which always waits for a person's approval; there is no auto-send.
  The agent ships as a draft: until an administrator activates `followup_agent`, both modes only
  remind the owner. The agent acts as the record's owner and its drafts and reminders wait for
  the owner's confirmation in that conversation.
- **Daily cap:** `daily_cap` limits the items of a rule reminded or sent per day (UTC); past it the
  rest wait for the next run.
- **Switched off:** while AI chat is switched off (`/ai/switches`), nothing runs and items stay open.
- **Owners** see their open follow-ups at `/ai/follow-ups` (`GET /api/v1/ai/follow-ups`) and dismiss
  them (`POST /api/v1/ai/follow-ups/{id}/dismiss`, `If-Match`).

## Hand-offs between agents and people

A ticket can move between an agent and people with a reason attached, so neither side starts cold.

- **The ledger.** Each hand-off (`service_handoff`) records who handed the ticket (an agent or a
  person) to whom (a person, a queue or an agent), a summary, the reasoning and its status:
  `pending`, `accepted`, `returned` or `cancelled`. A ticket has at most one hand-off waiting. Every
  step is written to the ticket's timeline with the summary, reasoning or note.
- **An agent hands off** with `handoff.to_person` (`ticket_id`, `to_kind`, `to_ref`, `summary`,
  `reasoning`). The reasoning is required, and the ticket and the person or queue must be ones the
  agent's owner can see. To a person the ticket is assigned to them at once; to a queue it moves there
  unassigned for the queue to hand out. Web chat keeps `bot.handoff`, which opens a work request.
- **A person hands off** from the ticket (`POST /api/v1/service/tickets/{id}/handoff`) the same way.
- **Accepting.** Only the person it was handed to, or an active member of the queue, accepts it
  (`POST /api/v1/service/handoffs/{id}/accept`, `If-Match`); the ticket is then theirs. My hand-offs
  (`/service/handoffs`, `GET /api/v1/service/handoffs`) lists what waits for me and my queues; the
  ticket's card shows its newest hand-off.
- **Handing back.** The ticket's assignee hands an agent's hand-off back with a note
  (`POST /api/v1/service/handoffs/{id}/return`, `If-Match`). If the agent's session is still live, the
  note becomes its next turn. Otherwise a new session of the same agent starts for the person who handed
  it back, and its first turn carries the ticket, the original summary and reasoning, and the note. A
  revoked or paused session is never resumed.
- **What it does not do.** Queues, membership and claiming stay with the queue engine (V7, G4), and live
  routing stays with J10; hand-offs only add the hand-off, the hand-back and their record. Each agent
  hand-off counts in the agent's hand-off rate (Agent performance).

## Agent performance

`/ai/agents/performance` (administrators; `GET /api/v1/admin/ai/agents/performance?from&to`) shows how
each agent did over a date range. The figures come from a nightly rollup (`ai_agent_daily_stat`).
Shortly after 02:00 UTC each night it computes the day before from the outcome ledger, the agent's
messages and the model prices, and it can be rebuilt for a range
(`POST /api/v1/admin/ai/agents/performance/backfill`, up to 400 days). A rerun gives the same figures.

- **Tasks done:** the agent's recorded tasks (`agent_task` outcomes: reminders, drafts, messages,
  promises, notes confirmed into tasks, hand-offs) on that day.
- **Resolution:** resolved ÷ done, where a task is resolved when its measured outcome says it succeeded.
- **Accuracy:** the summed effectiveness of the measured tasks ÷ the tasks measured.
- **Hand-off rate:** hand-offs ÷ tasks done.
- **Time saved:** an **estimate**. Each task counts a fixed time for its kind of work (follow-up 2 min,
  collections 3 min, meeting 15 min, hand-off 5 min), not a measurement.
- **Tokens and cost:** the tokens of the agent's sessions, priced from `inference.spend.prices`, else
  the approved model catalogue (`ai_model` input and output cost per token). Cost is in the price list's
  own currency. When any tokens had no price, the screen says "no price set" instead of showing a cost.
- **The runs behind a number:** choose an agent to see its days; every number of a day opens the
  outcome rows or sessions behind it (`GET /api/v1/admin/ai/agents/{id}/runs?day&metric`), with ids,
  times and tokens only, never message text or record values.
- **Asking an agent:** the read-only `agent.performance` action gives administrators the same figures
  through the operations agent or MCP.

## Work done by agents

`/ai/agents/work-share` (administrators; `GET /api/v1/admin/ai/work-share?from&to`, the last 30 days by
default) shows, for each process, how many tasks agents and people completed, the hand-offs between them,
and the agents' share (agents ÷ (agents + people)), with a bar per day.

- **A process is a work measure.** Each `ai_work_measure` record names an entity, an attribute and the
  values that mean a task of the process is done, comma-separated (`service.ticket_resolved`:
  `service_ticket`, `status`, `resolved,closed`). Add one through the generic entity API
  (`POST /api/v1/ai_work_measure`) and set `is_active` to false to stop counting it. Values are trimmed
  and compared exactly, case included.
- **Counting.** Every minute a change-feed consumer (`attome-ai/work_share`) counts each create or update
  that sets a measure's attribute to one of its values. It attributes the completion by the change event's
  initiator: an agent acting for a person counts as the agent's, anything else as the person's. Counts and
  the consumer's cursor move together, so each event is counted exactly once. Results are kept per
  process and UTC day in `ai_work_share_daily`.
- **Only completions after this release are attributed.** Change events written before events carried
  their initiator count as a person's.
- **Hand-offs** are the day's ticket hand-offs (`service_handoff`), shown for measures on `service_ticket`.
- **The records behind a number:** every count of a day opens the change events behind it
  (`GET /api/v1/admin/ai/work-share/{process_key}/events?day&by=agent|person`), each linked to its
  record, while the change feed still keeps them.
- **Rebuilding.** `POST /api/v1/admin/ai/work-share/rebuild` (`{ "from", "to" }`, up to a year) clears the
  range and counts it again from the change events still kept. The table is derived and can always be
  rebuilt; days older than the feed's retention cannot.

## Collections and renewals

Collections reuse the follow-up ledger. Nothing happens until an administrator adds an
`ai_collection_rule` (under AI in the admin area); there is none by default.

- **Rule kinds** (`kind`, with `offset_days`): `invoice_due` finds unpaid invoices (`issued`,
  `sent` or `overdue` with something still open) due `offset_days` from today; `invoice_overdue`
  finds those due `offset_days` ago; `renewal_due` finds active or trial subscriptions ending within
  `offset_days`. A record is recorded at most once a day, and not at all once it has had
  `max_reminders` reminders under the rule. An invoice with an open payment promise for today or later
  is skipped, unless a person rejected that promise.
- **When:** the hourly follow-up scan finds collections from 08:00 in the deployment's time zone
  (`core.time_zone`), with that local date as the day.
- **Sending.** For an active rule with reminders left, the run sends each reminder as the record's
  owner (`collections.send_reminder`). An agent calling `collections.send_reminder` itself always
  waits for a person's approval. The message is the rule's English or Arabic template
  (`template_text_en`, `template_text_ar`), or a built-in one, in the customer's language (the
  contact's `preferred_language`, then the invoice's `language`, then the deployment's). Its values
  are `{invoice_number}`, `{amount}`, `{currency}`, `{due_date}`, `{customer_name}`,
  `{subscription_name}` and `{end_date}`, always taken from the invoice or subscription, never written
  by the model. The rule's `channel` must be `email` today: `whatsapp` and `sms` rules are refused,
  and the owner is reminded instead, as when the customer has no email or asked not to be emailed.
- **Promises.** Every five minutes new inbound replies on those invoices are read for a promise to pay
  (amount and date, Arabic or English). A promise found is recorded as an `ai_payment_promise`
  waiting for review. On the invoice's Collections panel staff confirm or reject it
  (`POST /api/v1/ai/collections/promises/{id}/confirm`, `.../reject`) and later mark it kept or
  broken (`.../status`), each with `If-Match` and update access to the invoice. The panel lists the
  promises and reminders (`GET /api/v1/ai/collections/invoices/{id}/promises`, `.../reminders`).
- **Switched off:** while AI chat is switched off, nothing is sent or read.

## Lead qualifier

The `lead_qualifier` agent ships as a draft with its Lead Qualifier policy; an administrator
activates it and gives it a model. It reads the lead, looks for what Attome already knows about the
company (`search.records`), asks the questions that decide fit (need, budget, timing, who decides)
in the lead's language, records the answers on the lead (`record.update`), offers a meeting and hands
a qualified lead to its owner (`record.assign`).

- **Reaching the lead.** Only two actions contact the lead, and both are Consequential, so each
  call waits for a person's approval: `lead.send_message` emails the lead (a `communication` on the
  lead), and `lead.book_meeting` books a meeting on a booking page (`page` is its slug, `start` one
  of its offered times). The booking goes to a free team member round robin, and the lead gets the
  confirmation with the reschedule and cancel link.
- **Consent.** Both refuse unless the lead holds a grant in force for the `sales_outreach` consent
  purpose on email (or `any`) in the consent ledger. No grant, a withdrawal or an account opt-out
  refuses; nothing is sent. Record the grant from the lead's form or by hand.
- **Limits.** The policy caps a session at 40 tool calls, 30 minutes and 60,000 tokens, and the
  agent at 100 writes a day; each contact action also stops after 10 a minute and 100 a day in one
  session. Each completed action records an `agent_task` outcome under rule `ai.lead`.
- **Not yet:** WhatsApp (the compose writer sends email only) and company enrichment (L9).

## Inbox to record

The `inbox_to_record` agent ships as a draft with its Inbox to Record policy; an administrator
activates it and gives it a model. Inbound mail is first routed by the mailbox's rule (a case, a lead
or the sender's contact). The agent then works on one inbound email at a time:

- **Intent.** It classifies the email (`record.classify`): a new enquiry is a lead, a problem is a
  case, a purchase order is an order; anything else stays where the routing put it.
- **Fields.** It reads attachments with `document.extract` and fills only values the email or its
  attachments state. It looks for the existing record first (`search.records`, `duplicates.check`)
  and updates it rather than make a second one.
- **Filing.** `inbox.file_message` places the email on every record it created or updated. The
  email stays where it was too, and shows with its attachments on each record's timeline. Only
  inbound email is filed, and only on a record the caller may update; filing twice is a no-op.
- **Acknowledgement.** It answers the sender with `email.send`, in the sender's language, naming
  the record's reference. `email.send` is Consequential, so it waits for approval, or for its undo
  window at the `act_with_undo` autonomy level.
- **Limits.** The policy caps a session at 30 tool calls, 15 minutes and 40,000 tokens, and the
  agent at 500 writes a day. Each filing records an `agent_task` outcome under rule `ai.inbox`.

## Operations agent

`ops.report` (administrators only; reads, changes nothing) answers "how is this deployment doing":

- the nodes seen in the last day, the version each runs, and whether each reported in the last
  three minutes;
- the services this node depends on, as `system.status` reads them, and whether writes are paused;
- the backups in `backup.dir`: how many, their size, the newest archive's time, and the last restore
  drill and whether it passed;
- the database's size and each SLO class's status.

It also lists the routine actions these call for, urgent ones first, each naming its fix: no backup
in 26 hours or none at all (`attome backup now`), backups switched off (`backup.enabled`), no
passing restore drill in 35 days (`attome backup drill`), a service down, writes paused, a node
that stopped reporting, nodes on different versions, and an SLO class over its error budget.

Every Monday from 06:00 UTC the report and its proposals go to every administrator as the weekly
operations digest, in the app and by email (job `ai_ops_weekly_digest`, checked hourly, sent once a
week). The `ops_agent` ships as a draft with its Operations policy: it may call `ops.report`,
`ops.slo_health`, `system.status` and `table.health`, all reads, so a person runs whatever it
proposes. Certificates and free disk space are not reported: the server holds no certificate
while TLS ends at the proxy, and free space needs a platform call it does not make.

## Meeting briefs and notes

A meeting is an `activity` whose `activity_type` is `meeting`. It is about a record through
`entity_name` and `record_id`, and it starts at its `due_at`.

- **Briefs before a meeting.** Every 15 minutes the `ai_meeting_brief_scan` job finds meetings
  starting 60 to 75 minutes ahead that are not cancelled and have no brief. For each it runs
  `meeting.brief` as the meeting's owner, through the gate, so the AI switch, the licence, the
  owner's grants and their budget apply. The brief covers the meeting; its account (the record it
  is about, or that record's lookup to `account`); up to 10 open deals and 10 open cases on the
  account; the 5 latest activities; and up to 10 open tasks. It is written in the meeting's
  language, else the owner's locale (`core.locale`).
- **Briefs respect record access.** Every record is read as the meeting's owner and, when someone
  else asks, as that person too. A record either cannot read is left out, and only the fields both
  may see are used. Records whose subject restricted processing are left out. The brief is the
  meeting's one `ai_meeting_brief` row, owned by the meeting owner; it is refreshed when made again,
  and marked `failed` with no text when generation fails. The owner gets an in-app notice.
  People turn unasked briefs off with the `ai.meeting_briefs` setting (their own, or the
  deployment's); it is on by default.
- **Reading and remaking a brief.** `GET /api/v1/ai/meetings/{id}/brief` returns it to anyone who
  may read the meeting. `POST /api/v1/ai/meetings/{id}/brief/regenerate` makes it again now, as
  the caller.
- **Notes from a recording.** `POST /api/v1/ai/meetings/{id}/notes` with `{ "transcript_ref":
  "<recording document id>" }` queues `meeting.notes` (202). The transcript is the recording's
  transcript (`GET /api/v1/documents/{id}/transcript`), read under the document's own access. A long
  transcript is summarised in parts and the parts merged. The notes hold a summary, decisions,
  action items with any owner or date the meeting named, and proposed record updates. Each proposed
  update names the record, the field, the new value and the transcript words behind it. An update
  is kept only for the meeting's record or its account, a real field, words that are in the
  transcript, and a record the caller may change. Nothing is applied: the notes are an
  `ai_meeting_notes` row in `draft`, written in the transcript's language.
- **Confirming notes.** `POST /api/v1/ai/meetings/{id}/notes/confirm` with `If-Match` (the notes'
  `row_version`) and the chosen `action_item_indexes` and `record_update_indexes` confirms the
  notes once. Each chosen action item becomes an open task on the meeting. Each chosen record update
  is only proposed: it goes through `record.update_field`, so the field allow-list, the write
  approval policy and the daily cap decide whether it applies, waits for a person's approval or is
  refused. Confirmed notes are never rewritten.

## Safety around the model

- Untrusted text (records, documents, tool results) is cleaned of hidden characters and hidden HTML
  before the model sees it, and wrapped as data.
- Untrusted text that reads like instructions ("ignore previous instructions", «تجاهل التعليمات»,
  role markers, tool-call or exfiltration requests) is marked with a warning naming the signals; it
  stays visible as data, so a summary still contains its record.
- An answer never carries record data to another host: outside images and data-carrying links are
  removed before it is stored.
- Prompt overrides (`prompt_override` kind) change editable sections only; the locked safety text
  stays as shipped, and text that tells the model to ignore its rules or looks like a secret is
  refused.
- Eval suites (`eval_suite` kind) hold test cases per agent; a failed safety case fails the suite.
- A fine-tuned or adapter model is pinned on its AI Model row: `pinned_version`, `base_model`, the
  eval suite that judges it (`drift_suite_ref`), its expected score (`drift_baseline`) and how far it
  may fall (`drift_tolerance`, default 0.05). Each night the suite re-runs, as the administrator who
  last ran it by hand, and administrators are alerted when the score drifts below the baseline.
- Masked personal values come back in an answer only for a viewer who may read the field they came
  from; anyone else sees the token, and a forbidden value the answer repeats verbatim is replaced.
