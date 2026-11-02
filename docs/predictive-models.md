# Predictive models from a definition

A model predicts a yes/no attribute of any entity from its other attributes
(O1-T3). Create it through the admin API with a definition:

```http
POST /api/v1/admin/predict/models
{
  "name": "Lead conversion",
  "definition": {
    "entity": "lead",
    "target": "lead_status",
    "positive": ["converted"],
    "negative": ["disqualified"],
    "algorithm": "logistic_regression",
    "features": [
      { "attribute": "source" }, { "attribute": "seniority" },
      { "attribute": "authority" }, { "attribute": "timeline" },
      { "attribute": "budget" }, { "attribute": "country_code" }
    ],
    "min_rows": 500
  }
}
```

That is the lead conversion model of D18-T2
(`attome_predict::generic::lead_conversion`). The definition is checked
against the metadata (422 with every problem) and stored with the model; its
target reads `def:<target>`.

| Field | Meaning |
|---|---|
| `target` | A yes/no attribute, or a choice with `positive` and `negative` values. With values, a row with any other value is open: it is not trained on and it is the row that is scored. |
| `features` | `{ "attribute" }`, `{ "path": "account.industry" }`, `{ "time", "part" }` (`day_of_week`, `month`, `hour`, `age_days`) or `{ "rollup": "<child entity>", "via": "<its lookup>", "func": "count|sum|avg|min|max", "field", "alias" }` (the children of each row, counted or summed, read as the model's creator). |
| `closed_when` | Optional `{ "attribute", "values" }`: the rows whose outcome is known (a ticket that is resolved or closed). Only they are trained on and only the others are scored, for a yes/no target that starts as no. |
| `score` | Optional: the target values whose rows are scored. Without it, the open rows (neither positive nor negative) are scored when there are yes and no values, else every row. |
| `min_rows` | Labelled rows needed before a model trains (default 200, never below 50). |
| `score_attribute` | Optional number attribute of the entity that receives the score from 0 to 100. |

**Training** (the training job, and `POST .../models/{id}/train`) reads the
rows as the model's creator, so field security applies. Numbers and yes/no
values are used as they are, text and choices as their 20 most common values.
A fifth of the rows is held out; the model goes `active` only when it beats
always guessing the commoner outcome, otherwise `failed_holdout` with the
reason in `metrics.error` (`insufficient labeled training data` until there is
enough history).

**Scoring** runs in the nightly scoring sweep: each row gets one `prediction`
per model version, read through `GET /api/v1/predictions?regarding=...`, with
`explanation.top_factors`: the three inputs that moved the score most.

**On change.** Every five minutes the job `predict_definition_rescore` reads
the record changes since its last run (the change feed) and rescores the
changed records of each active model on that entity; a record changed many
times in those minutes is scored once, and gets a new prediction only when
its score moved.

**Outcomes.** The outcome-fill sweep records each prediction's outcome in
`outcome` (kind `prediction`, effectiveness 1 when the prediction was right,
0 when wrong): for a choice target with yes and no values once the record
closes either way, for a yes/no target once the prediction's 30-day horizon
has passed.

## Templates

- **Lead conversion** (`attome_predict::generic::lead_conversion`, D18-T2): above.
- **Subscription churn** (`attome_predict::generic::subscription_churn`, O3-T1): on the billing pack's
  `subscription`, cancelled against active or paused; scores active, trial and paused subscriptions into
  `subscription.churn_risk` (0 to 100). Features: billing frequency, renewal mode, term, age, the number
  of lines and of charges, and the customer's size, payment terms and credit hold. The billing pack's
  **Renewal risk** view lists the scored subscriptions, highest risk first. Case volume, satisfaction,
  usage and engagement join as features once those records link to the subscription or the account
  through a lookup a rollup can follow.
- **SLA breach** (`attome_predict::generic::sla_breach`, O2-T1): on `service_ticket`, trained on resolved
  and closed tickets (`sla_breached` is final then) and scored on open ones, from priority, severity,
  urgency, impact, type, category, channel, escalation level and whether it is a major incident. Its
  metrics carry the fixed-feature ticket model's as `metrics.baseline`, to compare. A ticket scored at 0.7
  or above has its waiting queue items moved up one priority, so the router offers it sooner.

