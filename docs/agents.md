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

- **Writes need a person.** Every write action stops at confirmation for an agent; consequential
  ones need a second person's approval.
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
- Communication: `email.draft` files a draft; sending stays a person's step. `text.translate`
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
- Service levels (administrators): `ops.slo_health` lists each SLO class with its status and the share
  of its 30-day error budget left, from the server's own metrics store.

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
