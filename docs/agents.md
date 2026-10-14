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
- **Daily limits** count an agent's steps by class (record changes, deletes, messages, outside
  calls) across all its sessions; at the cap the step is refused.
  `GET /api/v1/admin/ai/agents/{agent}/usage` shows today's use.
- **Switches.** `PUT /api/v1/admin/ai/switches/{kind}/{key}` turns an agent, model, provider, tool or
  channel off at once (screen: `/ai/switches`). Turning it back on takes a different administrator.

## Tools agents get

- Records: `record.get`, `search.records`, `query.execute`, `record.schema` (an entity's typed input),
  `record.validate` (a dry run of a create), `record.create|update|delete|restore`, `record.assign`,
  `record.transitions` and `record.transition` (move a stage or status through the state model; a
  move that needs approval goes to its pending state and asks for it).
- Many records: `record.bulk.preview` (count, a sample of what changes, problems), then
  `record.bulk.update|delete` (up to 500, run by the bulk engine, approved by a second person) and
  `record.bulk.status` (each record's result). A replayed call never applies twice.
- Questions: `query.plan` turns a question into a checked query (entity, filters, order, limit) and
  returns the issues to fix, or a description for the person and the `query.execute` arguments that
  run it. The model never writes SQL.
- Communication: `email.draft` files a draft; sending stays a person's step. `text.translate`
  translates text keeping names, numbers and the deployment's terms (`inference.translation.glossary`).
- Building: `model.<kind>.describe|list|edit` for every metadata kind, found over MCP with
  `tools.search`; edits are drafts a person confirms.

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

- In chat: `POST /api/v1/ai/conversations/{id}/messages`.
- In the background: `POST /api/v1/ai/conversations/{id}/runs` returns at once; follow
  `GET /api/v1/ai/conversations/{id}/stream`.
- What a session did: `GET /api/v1/admin/agents/sessions/{id}/trace` (the Steps button on the agent
  sessions screen).

## Safety around the model

- Untrusted text (records, documents, tool results) is cleaned of hidden characters and hidden HTML
  before the model sees it, and wrapped as data.
- An answer never carries record data to another host: outside images and data-carrying links are
  removed before it is stored.
- Prompt overrides (`prompt_override` kind) change editable sections only; the locked safety text
  stays as shipped, and text that tells the model to ignore its rules or looks like a secret is
  refused.
- Eval suites (`eval_suite` kind) hold test cases per agent; a failed safety case fails the suite.
