//! The token budget, actually applied.
//!
//! ## The gap this closes
//!
//! `attome_inference::budget` has shipped since D-360 with priority classes,
//! two default budgets, an allow/reject policy that charges the estimate up
//! front, a `Meter`, and four Prometheus metric names. It had **no call sites
//! anywhere in the workspace** — verified 2026-09-10 by grepping every crate
//! for `budget::`; the only hits were `attome-rules`' unrelated parser budgets
//! and a doc comment in `attome-jobs` referring to the shape. Every generation
//! this platform performs went out unmetered and unbounded.
//!
//! M31's own plan describes the gap more narrowly ("`Priority` classes still
//! only meter `attome-search`'s reindex drain") — that overstates what shipped.
//! `attome-search` does not reference `budget` either. Nothing did.
//!
//! ## What this module is
//!
//! The three-line sandwich every generation call site now wears:
//!
//! ```text
//! let grant = budget_guard::admit(state, ctx, Priority::Chat, &request).await?;
//! let generated = client.generate(request).await?;
//! grant.settle(state, &generated.usage).await;
//! ```
//!
//! [`admit`] rejects with 429 before a token is spent; [`Grant::settle`]
//! reconciles the pre-flight estimate against what the model actually
//! reported, so a conservative estimate does not permanently overcharge a
//! caller's window.
//!
//! ## Two budgets, both enforced
//!
//! Per-session **and** per-caller, because `Budget::PER_CALLER_DEFAULT`'s own
//! doc comment names the hole: opening a second session is the obvious way
//! around a per-session budget, and it is not an attack — it is what a user
//! does when the first one stops working. A direct (non-agent) invocation has
//! no session, so only the per-caller budget applies to it.
//!
//! ## Deliberately not configurable yet — except for the public widget
//!
//! Both budgets are the shipped constants. A per-deployment override belongs
//! in the validated config schema (guidelines §8) and is a separate change
//! with its own defaults question; wiring the enforcement first means the
//! numbers can be argued about against real metered data instead of guesses.
//!
//! **The one exception is an anonymous channel session** (C9, D-558 §3), and
//! it changes the *key* as well as the limit. Every public web-chat visitor
//! runs as the one shared `integration_system` service principal, so the
//! per-caller key (`security.user_id`) would make every visitor draw on one
//! shared quota: one visitor could exhaust everyone's, and the daily limit
//! would bound the deployment rather than the visitor. For such a session
//! (`ActionContext::anonymous_channel`, derived from the session row) the
//! "caller" is the visitor's own anonymous session, and both limits come from
//! `webchat.session_token_cap` / `webchat.daily_token_cap`, each clamped to
//! the shipped default. A missing cap refuses the generation — fail closed,
//! never an inherited default — though boot validation already makes that
//! unreachable for an enabled widget. Same two windows, same Redis counters,
//! same `admit`/`settle`: no second budget.
//!
//! **A per-visitor cap alone does not bound spend**, because a visitor is an
//! anonymous session and a new one is a token away. So an anonymous channel
//! session also draws on one **deployment-wide** budget
//! ([`WEBCHAT_DEPLOYMENT_KEY`], `webchat.deployment_daily_token_cap`), checked
//! and charged with the other two: exhausting it refuses every anonymous
//! generation — including a brand-new session's — until its 24-hour window
//! moves on. It is clamped to `Budget::PER_CALLER_DEFAULT`, which is exactly
//! the bound the whole widget had before C9, when every visitor was metered
//! as the one service principal: C9 moved per-visitor fairness onto a new key
//! and kept the old aggregate ceiling as the backstop. Raising it is a code
//! change to that default, not a configuration value.
//!
//! ## Money budgets (N24-T1)
//!
//! `inference.spend` adds monthly money caps (a rolling [`SPEND_WINDOW`]) for
//! the deployment, each person, each agent and each feature, counted in
//! millionths of the price unit through the same `token_window` counters
//! under `attome-ai:spend:{scope}:{id}`. They apply only when the generation
//! model has a price. Near a cap (`degrade_at_percent`) a generation is
//! shortened to `degraded_max_output_tokens` before its estimate is taken;
//! at a cap it is refused with 429 before anything is spent. The money
//! windows are reserved before the token windows and refunded if the token
//! windows then refuse, so a refusal by either charges nothing. Same failure
//! stance as the token windows: a Redis error refuses.

use std::time::Duration;

use attome_cache::token_window;
use attome_config::{ModelPrice, SpendSection, WebchatSection};
use attome_core::EngineState;
use attome_inference::budget::{self, Budget, BudgetVerdict, Priority};
use attome_inference::{GenerationRequest, Usage};
use attome_types::AppError;
use uuid::Uuid;

use crate::context::ActionContext;

/// Characters per token, for the pre-flight prompt estimate.
///
/// Deliberately crude and deliberately **low**: 4 chars/token is the common
/// rough figure for English, and Arabic — which this platform serves natively
/// — tokenizes worse than that, not better. Rounding the divisor down would
/// under-estimate the prompt, and an under-estimate is the direction that lets
/// a caller slip past a budget. The reconciliation in [`Grant::settle`] fixes
/// the error either way once the model reports real numbers; the estimate only
/// has to be honest enough that the *first* oversized request is refused.
const CHARS_PER_TOKEN: u64 = 4;

/// Estimates what a request will cost, before sending it.
///
/// Prompt side from the **serialized request** — messages, replayed
/// `tool_calls` and `tool_call_id`s, and every tool definition — through
/// `GenerationRequest::wire_bytes_estimate`, the one `ChatRequest` shape the
/// transport sends (BIN-G2, ai-10-10 O16). Counting only `content` let a
/// request carrying twenty tool schemas reserve what a bare prompt does.
/// Completion side from the ceiling the request will actually run under,
/// never an optimistic guess — the budget exists to stop an unbounded
/// generation started by a caller sitting just under the limit, so the
/// estimate must assume the generation runs to its ceiling.
pub fn estimate_tokens(request: &GenerationRequest, deployment_ceiling: u32) -> u64 {
    // Mirrors `GenerationClient::generate`'s own clamp: a caller's ceiling
    // never raises the deployment's.
    let completion_ceiling = request
        .max_output_tokens
        .unwrap_or(deployment_ceiling)
        .min(deployment_ceiling);
    // The model id is the transport's, not known here; it is a few dozen
    // bytes of the envelope.
    let prompt_bytes = request.wire_bytes_estimate("", completion_ceiling) as u64;

    prompt_bytes.div_ceil(CHARS_PER_TOKEN) + u64::from(completion_ceiling)
}

/// The per-session budget for this invocation: the session policy's token
/// limit when it has one, never above `Budget::PER_SESSION_DEFAULT` (D-512
/// §1), over the default's window. A session with no policy term keeps the
/// default. `start_session` already refuses a policy limit above the default;
/// the `min` here keeps a stored value from widening it regardless.
pub(crate) fn session_budget(ctx: &ActionContext) -> Budget {
    let default = Budget::PER_SESSION_DEFAULT;
    match ctx.session_max_tokens.and_then(|t| u64::try_from(t).ok()) {
        Some(tokens) => Budget {
            tokens: tokens.min(default.tokens),
            window: default.window,
        },
        None => default,
    }
}

/// The per-session budget actually enforced: [`session_budget`], narrowed for
/// an anonymous channel session by `webchat.session_token_cap`. `None` when
/// such a session has no configured cap — the caller refuses rather than
/// inheriting a default the operator never chose.
fn effective_session_budget(ctx: &ActionContext, webchat: &WebchatSection) -> Option<Budget> {
    let budget = session_budget(ctx);
    if !ctx.anonymous_channel {
        return Some(budget);
    }
    webchat.session_token_cap.map(|cap| Budget {
        tokens: budget.tokens.min(cap),
        window: budget.window,
    })
}

/// Whose per-caller budget a generation draws on, and how large it is.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CallerBudget {
    key: String,
    budget: Budget,
    scope: &'static str,
}

/// The caller budget: the human (or service) principal's, or — for an
/// anonymous channel session — the visitor's own, keyed on the session and
/// sized by `webchat.daily_token_cap` clamped to the default. `None` when an
/// anonymous session has no session id or no configured cap (fail closed).
fn caller_budget(ctx: &ActionContext, webchat: &WebchatSection) -> Option<CallerBudget> {
    let default = Budget::PER_CALLER_DEFAULT;
    if !ctx.anonymous_channel {
        return Some(CallerBudget {
            key: caller_key(ctx),
            budget: default,
            scope: "caller",
        });
    }
    let session = ctx.agent_session_id?;
    let cap = webchat.daily_token_cap?;
    Some(CallerBudget {
        key: format!("attome-ai:budget:visitor:{session}"),
        budget: Budget {
            tokens: default.tokens.min(cap),
            window: default.window,
        },
        scope: "visitor",
    })
}

/// The one budget every anonymous channel session in this deployment draws on
/// (C9, D-558). Deployment-wide by construction: no session, visitor or
/// principal id is part of it, so a new anonymous session cannot reset it.
pub const WEBCHAT_DEPLOYMENT_KEY: &str = "attome-ai:budget:webchat:deployment";

/// The deployment-wide web-chat budget: `Some(None)` outside an anonymous
/// channel session (it does not apply), `Some(Some(_))` inside one, sized by
/// `webchat.deployment_daily_token_cap` clamped to `PER_CALLER_DEFAULT`, and
/// `None` when an anonymous session has no configured cap (fail closed).
fn deployment_budget(
    ctx: &ActionContext,
    webchat: &WebchatSection,
) -> Option<Option<CallerBudget>> {
    if !ctx.anonymous_channel {
        return Some(None);
    }
    let default = Budget::PER_CALLER_DEFAULT;
    let cap = webchat.deployment_daily_token_cap?;
    Some(Some(CallerBudget {
        key: WEBCHAT_DEPLOYMENT_KEY.to_owned(),
        budget: Budget {
            tokens: default.tokens.min(cap),
            window: default.window,
        },
        scope: "webchat_deployment",
    }))
}

fn session_key(ctx: &ActionContext) -> Option<String> {
    ctx.agent_session_id
        .map(|id| format!("attome-ai:budget:session:{id}"))
}

fn caller_key(ctx: &ActionContext) -> String {
    format!("attome-ai:budget:caller:{}", ctx.security.user_id)
}

/// An admitted generation, holding what it charged so it can be reconciled.
///
/// Not `Drop`-based: settling is an `async` Redis round-trip and a `Drop` impl
/// cannot await one. A dropped `Grant` therefore leaves the estimate charged,
/// which is the safe direction — an abandoned generation costs the caller its
/// estimate rather than nothing.
#[must_use = "a Grant must be settled after the generation, or the estimate stays charged"]
pub struct Grant {
    session_key: Option<String>,
    caller_key: String,
    caller_window: std::time::Duration,
    /// The deployment-wide web-chat key and its window, for an anonymous
    /// channel session only.
    deployment: Option<(String, std::time::Duration)>,
    estimated: u64,
    priority: Priority,
    /// The money reserved, when a money budget applies (N24-T1).
    spend: Option<SpendGrant>,
    /// Z9-T5: whose call this is, for its usage row.
    meter: Meter,
}

/// Z9-T5: who a model call is for, kept from admission to settlement.
#[derive(Debug, Clone)]
struct Meter {
    user_id: Uuid,
    agent_session_id: Option<Uuid>,
    feature: String,
    started: std::time::Instant,
}

/// Z9-T5: a call's cost in millionths of the price unit, when its model has
/// a configured price. Pure.
pub fn usage_cost(
    prices: &std::collections::BTreeMap<String, ModelPrice>,
    usage: &Usage,
) -> Option<u64> {
    prices.get(&usage.model_id).map(|price| {
        cost_micros(
            price,
            u64::from(usage.prompt_tokens),
            u64::from(usage.completion_tokens),
        )
    })
}

/// Z9-T5: writes the call's usage row. Best-effort, like the rest of
/// settling: a failed write is logged, never the caller's error.
async fn record_usage(state: &EngineState, meter: &Meter, usage: &Usage) {
    let cost = usage_cost(&state.base.config.inference.spend.prices, usage)
        .and_then(|c| i64::try_from(c).ok());
    let latency = i32::try_from(meter.started.elapsed().as_millis()).unwrap_or(i32::MAX);
    let written = sqlx::query(
        "INSERT INTO ai_usage_event \
             (user_id, agent_session_id, feature, model_id, prompt_tokens, completion_tokens, \
              cached_prompt_tokens, reported, cost_micros, latency_ms) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(meter.user_id)
    .bind(meter.agent_session_id)
    .bind(&meter.feature)
    .bind(&usage.model_id)
    .bind(i32::try_from(usage.prompt_tokens).unwrap_or(i32::MAX))
    .bind(i32::try_from(usage.completion_tokens).unwrap_or(i32::MAX))
    .bind(
        usage
            .cached_prompt_tokens
            .and_then(|t| i32::try_from(t).ok()),
    )
    .bind(usage.reported)
    .bind(cost)
    .bind(latency)
    .execute(&state.base.db)
    .await;
    if let Err(error) = written {
        tracing::warn!(%error, feature = %meter.feature, "model usage row not written");
    }
}

impl std::fmt::Debug for Grant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Grant").finish_non_exhaustive()
    }
}

/// Checks both budgets and charges the estimate.
///
/// Returns `Err(AppError::TooManyRequests { retry_after_secs: None })` when either budget is exhausted —
/// **a rejection, never a queue slot**, per `attome_inference::budget`'s module
/// doc: queueing would convert a cost problem into a latency problem and hide
/// it.
///
/// Fails closed on a Redis outage, because [`token_window::reserve_all`] does;
/// see [`token_window::read`]'s doc for why that is the right direction here.
pub async fn admit(
    state: &EngineState,
    ctx: &ActionContext,
    priority: Priority,
    feature: &str,
    request: &mut GenerationRequest,
) -> Result<Grant, AppError> {
    let redis = &state.base.redis_coordination;
    // N24-T1: the money windows come first, because near a cap they shorten
    // the request the token estimate is then taken from.
    let spend_plan = plan_spend(state, ctx, feature).await?;
    if let Some(plan) = &spend_plan {
        degrade_if_near(redis, &state.base.config.inference.spend, plan, request).await?;
    }
    let estimated = estimate_tokens(request, state.base.config.inference.max_output_tokens);

    let webchat = &state.base.config.webchat;
    let (Some(session_budget), Some(caller), Some(deployment)) = (
        effective_session_budget(ctx, webchat),
        caller_budget(ctx, webchat),
        deployment_budget(ctx, webchat),
    ) else {
        tracing::error!(
            agent_session_id = ?ctx.agent_session_id,
            "inference request refused — an anonymous channel session has no configured \
             webchat spend cap"
        );
        return Err(AppError::TooManyRequests {
            retry_after_secs: None,
        });
    };
    let session_key = session_key(ctx);

    // BCA-31 / ai-10-10 A0.1: ONE atomic check-and-reserve across every window,
    // instead of a read-then-charge per window. The old sequence let N
    // concurrent generations each read a below-limit `consumed` and then each
    // charge its estimate, overshooting by up to N x estimate (BCA-F2). The
    // script evicts, checks and charges all of them, or none.
    //
    // Order is narrowest first, so a refusal names the window a runaway loop
    // hits first: the session budget, then the caller's, then the
    // deployment-wide web-chat backstop.
    let mut windows: Vec<token_window::ReserveWindow<'_>> = Vec::with_capacity(3);
    let mut scopes: Vec<&'static str> = Vec::with_capacity(3);
    if let Some(key) = &session_key {
        windows.push(token_window::ReserveWindow {
            key,
            window: session_budget.window,
            limit: session_budget.tokens,
        });
        scopes.push("session");
    }
    windows.push(token_window::ReserveWindow {
        key: &caller.key,
        window: caller.budget.window,
        limit: caller.budget.tokens,
    });
    scopes.push(caller.scope);
    if let Some(deployment) = &deployment {
        windows.push(token_window::ReserveWindow {
            key: &deployment.key,
            window: deployment.budget.window,
            limit: deployment.budget.tokens,
        });
        scopes.push(deployment.scope);
    }

    let spend = match spend_plan {
        Some(plan) => Some(reserve_spend(redis, plan, estimated, priority).await?),
        None => None,
    };

    match reserve(redis, &windows, estimated).await? {
        Admission::Reserved => {}
        Admission::Refused {
            index,
            consumed,
            retry_after,
        } => {
            if let Some(spend) = &spend {
                spend.refund(redis).await;
            }
            let scope = scopes[index];
            metrics::counter!(
                budget::BUDGET_REJECTED_TOTAL,
                "scope" => scope,
                "priority" => priority_label(priority),
            )
            .increment(1);
            tracing::info!(
                scope,
                consumed,
                estimated,
                limit = windows[index].limit,
                retry_after_secs = retry_after.as_secs(),
                "inference request refused — token budget exhausted"
            );
            return Err(AppError::TooManyRequests {
                retry_after_secs: None,
            });
        }
    }

    Ok(Grant {
        session_key,
        caller_key: caller.key,
        caller_window: caller.budget.window,
        deployment: deployment.map(|d| (d.key, d.budget.window)),
        estimated,
        priority,
        spend,
        meter: Meter {
            user_id: ctx.security.user_id,
            agent_session_id: ctx.agent_session_id,
            feature: feature.to_owned(),
            started: std::time::Instant::now(),
        },
    })
}

/// The feature id chat and agent turns are budgeted under.
pub const AGENT_TURN_FEATURE: &str = "agent.turn";

/// The rolling month money budgets count over.
pub const SPEND_WINDOW: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// What a generation costs, in millionths of the price unit: a price is per
/// million tokens, so tokens times price is already in millionths.
pub fn cost_micros(price: &ModelPrice, prompt_tokens: u64, completion_tokens: u64) -> u64 {
    let micros = prompt_tokens as f64 * price.prompt_per_million
        + completion_tokens as f64 * price.completion_per_million;
    micros.ceil().max(0.0) as u64
}

/// A configured cap in millionths of the price unit.
fn cap_micros(cap: f64) -> u64 {
    (cap * 1_000_000.0).floor().max(0.0) as u64
}

/// One money window a generation draws on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendWindow {
    pub key: String,
    /// The cap, in millionths of the price unit.
    pub limit: u64,
    pub scope: &'static str,
}

/// The money windows a generation by `caller` (through `agent`, for
/// `feature`) draws on, narrowest first. `caller` is `None` for an
/// anonymous channel session, whose shared service principal is not a
/// person (the web-chat caps bound those).
pub fn spend_windows(
    spend: &SpendSection,
    caller: Option<uuid::Uuid>,
    agent: Option<uuid::Uuid>,
    feature: &str,
) -> Vec<SpendWindow> {
    let mut windows = Vec::new();
    if let Some(cap) = spend.feature_monthly.get(feature) {
        windows.push(SpendWindow {
            key: format!("attome-ai:spend:feature:{feature}"),
            limit: cap_micros(*cap),
            scope: "spend_feature",
        });
    }
    if let (Some(cap), Some(agent)) = (spend.agent_monthly, agent) {
        windows.push(SpendWindow {
            key: format!("attome-ai:spend:agent:{agent}"),
            limit: cap_micros(cap),
            scope: "spend_agent",
        });
    }
    if let (Some(cap), Some(caller)) = (spend.caller_monthly, caller) {
        windows.push(SpendWindow {
            key: format!("attome-ai:spend:caller:{caller}"),
            limit: cap_micros(cap),
            scope: "spend_caller",
        });
    }
    if let Some(cap) = spend.deployment_monthly {
        windows.push(SpendWindow {
            key: "attome-ai:spend:deployment".to_owned(),
            limit: cap_micros(cap),
            scope: "spend_deployment",
        });
    }
    windows
}

/// The generation model's price: `inference.spend.prices` when it names the
/// model, otherwise the approved, live `ai_model` catalogue entry's
/// `input_cost`/`output_cost` when they are priced per token
/// ([`price_from_catalogue`]). `None` when neither prices it.
pub async fn model_price(state: &EngineState) -> Result<Option<ModelPrice>, AppError> {
    let model = &state.base.config.inference.generation.model;
    if let Some(price) = state.base.config.inference.spend.prices.get(model) {
        return Ok(Some(*price));
    }
    if model.is_empty() {
        return Ok(None);
    }
    let rows: Vec<(Option<String>, Option<f64>, Option<f64>)> = sqlx::query_as(
        "SELECT cost_unit, input_cost::float8, output_cost::float8 FROM ai_model          WHERE provider_model_id = $1 AND approval_status = 'approved'            AND (is_active IS NULL OR is_active = true)          ORDER BY id LIMIT 5",
    )
    .bind(model)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .find_map(|(unit, input, output)| price_from_catalogue(unit.as_deref()?, input?, output?)))
}

/// A catalogue price as a price per million tokens; `None` for a unit that is
/// not per token or an amount that is not a finite, non-negative number.
pub fn price_from_catalogue(unit: &str, input: f64, output: f64) -> Option<ModelPrice> {
    let scale = match unit {
        "per_1m_tokens" => 1.0,
        "per_1k_tokens" => 1_000.0,
        _ => return None,
    };
    let valid = |v: f64| v.is_finite() && v >= 0.0;
    (valid(input) && valid(output)).then_some(ModelPrice {
        prompt_per_million: input * scale,
        completion_per_million: output * scale,
    })
}

/// Whether `consumed` has reached `percent` of `limit`.
pub fn near_cap(consumed: u64, limit: u64, percent: u8) -> bool {
    u128::from(consumed) * 100 >= u128::from(limit) * u128::from(percent)
}

/// The money side of one generation: its price and the windows it draws on.
#[derive(Debug)]
struct SpendPlan {
    price: ModelPrice,
    windows: Vec<SpendWindow>,
}

/// `None` when no money cap applies: none is configured, the model has no
/// price, or no configured window covers this generation.
async fn plan_spend(
    state: &EngineState,
    ctx: &ActionContext,
    feature: &str,
) -> Result<Option<SpendPlan>, AppError> {
    let spend = &state.base.config.inference.spend;
    if !spend.has_caps() {
        return Ok(None);
    }
    let Some(price) = model_price(state).await? else {
        return Ok(None);
    };
    // The agent a session was started with, only when agents have a cap.
    let agent = match (spend.agent_monthly, ctx.agent_session_id) {
        (Some(_), Some(session)) => sqlx::query_scalar::<_, Option<uuid::Uuid>>(
            "SELECT agent_object_ref FROM agent_session WHERE id = $1",
        )
        .bind(session)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .flatten(),
        _ => None,
    };
    let caller = (!ctx.anonymous_channel).then_some(ctx.security.user_id);
    let windows = spend_windows(spend, caller, agent, feature);
    Ok((!windows.is_empty()).then_some(SpendPlan { price, windows }))
}

/// Shortens `request` when any of `plan`'s windows is near its cap.
async fn degrade_if_near(
    redis: &attome_cache::Store,
    spend: &SpendSection,
    plan: &SpendPlan,
    request: &mut GenerationRequest,
) -> Result<(), AppError> {
    let Some(ceiling) = spend.degraded_max_output_tokens else {
        return Ok(());
    };
    for window in &plan.windows {
        let held = token_window::read(redis, &window.key, SPEND_WINDOW).await?;
        if near_cap(held.consumed, window.limit, spend.degrade_at_percent) {
            request.max_output_tokens = Some(
                request
                    .max_output_tokens
                    .map_or(ceiling, |m| m.min(ceiling)),
            );
            metrics::counter!(SPEND_DEGRADED_TOTAL, "scope" => window.scope).increment(1);
            tracing::info!(
                scope = window.scope,
                consumed = held.consumed,
                limit = window.limit,
                ceiling,
                "generation shortened — a money budget is near its cap"
            );
            break;
        }
    }
    Ok(())
}

/// Generations shortened because a money budget was near its cap.
pub const SPEND_DEGRADED_TOTAL: &str = "attome_ai_spend_degraded_total";

/// Reserves a generation's estimated cost in every money window, or refuses
/// with 429 charging nothing.
async fn reserve_spend(
    redis: &attome_cache::Store,
    plan: SpendPlan,
    estimated_tokens: u64,
    priority: Priority,
) -> Result<SpendGrant, AppError> {
    // The estimate does not split prompt from completion, so it is priced at
    // the dearer rate; settling corrects it.
    let dearer = plan
        .price
        .prompt_per_million
        .max(plan.price.completion_per_million);
    let estimated = cost_micros(
        &ModelPrice {
            prompt_per_million: dearer,
            completion_per_million: dearer,
        },
        0,
        estimated_tokens,
    );
    let windows: Vec<token_window::ReserveWindow<'_>> = plan
        .windows
        .iter()
        .map(|w| token_window::ReserveWindow {
            key: &w.key,
            window: SPEND_WINDOW,
            limit: w.limit,
        })
        .collect();
    match reserve(redis, &windows, estimated).await? {
        Admission::Reserved => {}
        Admission::Refused {
            index, consumed, ..
        } => {
            let window = &plan.windows[index];
            metrics::counter!(
                budget::BUDGET_REJECTED_TOTAL,
                "scope" => window.scope,
                "priority" => priority_label(priority),
            )
            .increment(1);
            tracing::info!(
                scope = window.scope,
                consumed,
                estimated,
                limit = window.limit,
                "inference request refused — money budget exhausted"
            );
            return Err(AppError::TooManyRequests {
                retry_after_secs: None,
            });
        }
    }
    Ok(SpendGrant {
        keys: plan.windows.into_iter().map(|w| w.key).collect(),
        estimated,
        price: plan.price,
    })
}

/// The money a generation reserved, to settle or refund.
#[derive(Debug)]
struct SpendGrant {
    keys: Vec<String>,
    estimated: u64,
    price: ModelPrice,
}

impl SpendGrant {
    async fn charge_all(&self, redis: &attome_cache::Store, delta: i64) {
        for key in &self.keys {
            if let Err(error) = token_window::charge(redis, key, delta, SPEND_WINDOW).await {
                tracing::warn!(%error, key, "failed to reconcile a money budget");
            }
        }
    }

    /// Returns the reservation when the token windows refuse afterwards.
    async fn refund(&self, redis: &attome_cache::Store) {
        self.charge_all(redis, -(self.estimated as i64)).await;
    }

    async fn settle(&self, redis: &attome_cache::Store, usage: &Usage) {
        let actual = cost_micros(
            &self.price,
            u64::from(usage.prompt_tokens),
            u64::from(usage.completion_tokens),
        );
        self.charge_all(redis, actual as i64 - self.estimated as i64)
            .await;
    }
}

/// What one atomic admission decided, before any metric or log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// `estimated` is now charged to every window.
    Reserved,
    /// Nothing was charged. `index` names the refusing window in the slice
    /// passed to [`reserve`]; `consumed` is what it held at the decision.
    Refused {
        index: usize,
        consumed: u64,
        retry_after: std::time::Duration,
    },
}

/// The admission decision [`admit`] makes: one atomic `reserve_all` across
/// every window, and a refusal's `retry_after` derived through
/// `budget::check` on the store's own numbers.
///
/// Public so the A0.1 conformance suite (`tests/budget_conformance.rs`) drives
/// this exact path through `attome_inference::budget::CONFORMANCE` rather than a
/// copy of it (BIN-G1, BIN-D8). Fails closed: a Redis error is `Err`.
pub async fn reserve(
    redis: &attome_cache::Store,
    windows: &[token_window::ReserveWindow<'_>],
    estimated: u64,
) -> Result<Admission, AppError> {
    match token_window::reserve_all(redis, windows, estimated).await? {
        token_window::Reservation::Reserved(_) => Ok(Admission::Reserved),
        token_window::Reservation::Refused(refused) => {
            let window = windows
                .get(refused.index)
                .ok_or_else(|| AppError::internal("token budget refused an unknown window"))?;
            // Derive retry_after through the same function the read path used,
            // so the two cannot disagree about when the window frees up.
            let retry_after = match budget::check(
                budget::Budget {
                    window: window.window,
                    tokens: window.limit,
                },
                refused.state.consumed,
                estimated,
                refused.state.elapsed,
            ) {
                BudgetVerdict::Rejected { retry_after } => retry_after,
                // reserve_all refused on the same numbers, so this is 1s of
                // slack rather than a path anyone should reach.
                BudgetVerdict::Allowed { .. } => std::time::Duration::from_secs(1),
            };
            Ok(Admission::Refused {
                index: refused.index,
                consumed: refused.state.consumed,
                retry_after,
            })
        }
    }
}

impl Grant {
    /// Reconciles the estimate against actual usage and records the spend.
    ///
    /// Best-effort and infallible by design: the generation has already
    /// happened and its result is on its way to the caller. Failing their
    /// request because a metering write did not land would trade a correct
    /// answer for a bookkeeping error — the reverse of the trade worth making.
    /// A failed reconciliation leaves the estimate standing, which over- or
    /// under-charges by a bounded amount for one window and is logged.
    pub async fn settle(self, state: &EngineState, usage: &Usage) {
        let actual = u64::from(usage.prompt_tokens) + u64::from(usage.completion_tokens);

        metrics::counter!(
            budget::TOKENS_TOTAL,
            "priority" => priority_label(self.priority),
            "kind" => "prompt",
        )
        .increment(u64::from(usage.prompt_tokens));
        metrics::counter!(
            budget::TOKENS_TOTAL,
            "priority" => priority_label(self.priority),
            "kind" => "completion",
        )
        .increment(u64::from(usage.completion_tokens));

        record_usage(state, &self.meter, usage).await;

        // A model server that reports no usage at all leaves the estimate in
        // place rather than zeroing the charge (BIN-G3: `reported` is false
        // when the response omitted the block); treating "unknown" as "free"
        // would make an unmetered provider the cheapest one to use.
        if !usage.reported {
            tracing::debug!(
                estimated = self.estimated,
                "model reported no token usage — leaving the estimate charged"
            );
            return;
        }

        if let Some(spend) = &self.spend {
            spend.settle(&state.base.redis_coordination, usage).await;
        }

        let delta = actual as i64 - self.estimated as i64;
        if delta == 0 {
            return;
        }

        let redis = &state.base.redis_coordination;
        if let Some(key) = &self.session_key
            && let Err(error) =
                token_window::charge(redis, key, delta, Budget::PER_SESSION_DEFAULT.window).await
        {
            tracing::warn!(%error, "failed to reconcile the session token budget");
        }
        if let Err(error) =
            token_window::charge(redis, &self.caller_key, delta, self.caller_window).await
        {
            tracing::warn!(%error, "failed to reconcile the caller token budget");
        }
        if let Some((key, window)) = &self.deployment
            && let Err(error) = token_window::charge(redis, key, delta, *window).await
        {
            tracing::warn!(%error, "failed to reconcile the web-chat deployment token budget");
        }
    }
}

/// Stable metric label per priority class. A `Debug` format would silently
/// rename every series the day someone renames a variant.
fn priority_label(priority: Priority) -> &'static str {
    match priority {
        Priority::Drain => "drain",
        Priority::QueryEmbedding => "query_embedding",
        Priority::Rerank => "rerank",
        Priority::Chat => "chat",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_inference::ChatMessage;

    #[test]
    fn usage_cost_needs_a_price_for_the_answering_model() {
        let usage = Usage {
            model_id: "m1".into(),
            prompt_tokens: 1_000,
            completion_tokens: 200,
            reported: true,
            cached_prompt_tokens: None,
        };
        let mut prices = std::collections::BTreeMap::new();
        assert_eq!(
            usage_cost(&prices, &usage),
            None,
            "an unpriced model costs unknown"
        );
        prices.insert(
            "m1".to_owned(),
            ModelPrice {
                prompt_per_million: 3.0,
                completion_per_million: 15.0,
            },
        );
        assert_eq!(usage_cost(&prices, &usage), Some(6_000));
    }

    fn request_of(chars: usize) -> GenerationRequest {
        GenerationRequest::new(vec![ChatMessage::user("x".repeat(chars))])
    }

    /// D-512 §1: a session's policy token limit narrows the per-session
    /// budget and can never widen it past `Budget::PER_SESSION_DEFAULT`; a
    /// session with no policy term keeps the default.
    #[test]
    fn a_session_token_limit_only_narrows_the_default_budget() {
        let default = Budget::PER_SESSION_DEFAULT;
        let mut ctx = ActionContext::user(crate::context::tests::security_context());
        assert_eq!(session_budget(&ctx), default);

        ctx.session_max_tokens = Some(1_000);
        assert_eq!(
            session_budget(&ctx),
            Budget {
                tokens: 1_000,
                window: default.window
            }
        );

        let above = i64::try_from(default.tokens).unwrap() + 1;
        ctx.session_max_tokens = Some(above);
        assert_eq!(session_budget(&ctx), default);

        ctx.session_max_tokens = Some(-1);
        assert_eq!(session_budget(&ctx), default);
    }

    fn webchat(session: Option<u64>, daily: Option<u64>) -> WebchatSection {
        WebchatSection {
            enabled: true,
            agent_definition_id: Some(uuid::Uuid::nil()),
            session_token_cap: session,
            daily_token_cap: daily,
            deployment_daily_token_cap: Some(1_000_000),
        }
    }

    /// **The aggregate is deployment-wide.** Two visitors on one principal —
    /// including a brand-new session — draw on the same key, which names no
    /// session, visitor or principal; a non-channel context draws on none.
    /// The cap is clamped to `PER_CALLER_DEFAULT`, and a missing cap refuses.
    #[test]
    fn every_anonymous_session_draws_on_one_deployment_budget() {
        let config = webchat(Some(1_000), Some(5_000));
        let a = anonymous(uuid::Uuid::now_v7());
        let fresh = anonymous(uuid::Uuid::now_v7());
        let (da, df) = (
            deployment_budget(&a, &config).unwrap().unwrap(),
            deployment_budget(&fresh, &config).unwrap().unwrap(),
        );
        assert_eq!(da.key, WEBCHAT_DEPLOYMENT_KEY);
        assert_eq!(da, df, "a new session gets no fresh allowance");
        assert_ne!(da.key, caller_budget(&a, &config).unwrap().key);
        assert_eq!(
            da.budget,
            Budget::PER_CALLER_DEFAULT,
            "1M is clamped to the default"
        );

        let small = WebchatSection {
            deployment_daily_token_cap: Some(7_000),
            ..config.clone()
        };
        assert_eq!(
            deployment_budget(&a, &small)
                .unwrap()
                .unwrap()
                .budget
                .tokens,
            7_000
        );

        let uncapped = WebchatSection {
            deployment_daily_token_cap: None,
            ..config.clone()
        };
        assert!(deployment_budget(&a, &uncapped).is_none(), "fail closed");

        let staff = ActionContext::user(crate::context::tests::security_context());
        assert_eq!(
            deployment_budget(&staff, &WebchatSection::default()),
            Some(None)
        );
    }

    fn anonymous(session: uuid::Uuid) -> ActionContext {
        let mut ctx = ActionContext::agent(
            crate::context::tests::security_context(),
            crate::RiskTier::Reversible,
        )
        .with_agent_session(session);
        ctx.anonymous_channel = true;
        ctx
    }

    /// **C9 invariant 3.** Two anonymous visitors run as the same service
    /// principal, yet each draws on its own visitor budget: the keys differ,
    /// neither is the principal's caller key, and the principal's own
    /// (non-channel) budget is untouched by either.
    #[test]
    fn anonymous_visitors_are_metered_apart_never_as_the_shared_principal() {
        let config = webchat(Some(20_000), Some(100_000));
        let principal = crate::context::tests::security_context();
        let mut a = ActionContext::agent(
            std::sync::Arc::clone(&principal),
            crate::RiskTier::Reversible,
        )
        .with_agent_session(uuid::Uuid::now_v7());
        a.anonymous_channel = true;
        let mut b = ActionContext::agent(
            std::sync::Arc::clone(&principal),
            crate::RiskTier::Reversible,
        )
        .with_agent_session(uuid::Uuid::now_v7());
        b.anonymous_channel = true;
        let staff = ActionContext::agent(principal, crate::RiskTier::Reversible)
            .with_agent_session(uuid::Uuid::now_v7());

        let (ka, kb, ks) = (
            caller_budget(&a, &config).unwrap(),
            caller_budget(&b, &config).unwrap(),
            caller_budget(&staff, &config).unwrap(),
        );
        assert_ne!(
            ka.key, kb.key,
            "one visitor must not spend another's budget"
        );
        assert_eq!(
            ks.key,
            caller_key(&staff),
            "a non-channel session keeps the caller key"
        );
        assert!(
            ka.key != ks.key && kb.key != ks.key,
            "no visitor draws on the principal's quota"
        );
        assert_eq!((ka.scope, ks.scope), ("visitor", "caller"));
    }

    /// The configured caps narrow the defaults and are clamped to them: a
    /// larger value is enforced as the default, never beyond it.
    #[test]
    fn webchat_caps_narrow_the_defaults_and_never_widen_them() {
        let ctx = anonymous(uuid::Uuid::now_v7());
        let small = webchat(Some(1_000), Some(5_000));
        assert_eq!(
            effective_session_budget(&ctx, &small).unwrap().tokens,
            1_000
        );
        assert_eq!(caller_budget(&ctx, &small).unwrap().budget.tokens, 5_000);

        let huge = webchat(Some(u64::MAX), Some(u64::MAX));
        assert_eq!(
            effective_session_budget(&ctx, &huge).unwrap(),
            Budget::PER_SESSION_DEFAULT
        );
        assert_eq!(
            caller_budget(&ctx, &huge).unwrap().budget,
            Budget::PER_CALLER_DEFAULT
        );
    }

    /// A missing cap refuses (fail closed) instead of inheriting a default the
    /// operator never chose; a non-channel context needs no webchat caps.
    #[test]
    fn an_anonymous_session_without_caps_is_refused_not_defaulted() {
        let ctx = anonymous(uuid::Uuid::now_v7());
        assert!(effective_session_budget(&ctx, &webchat(None, Some(5_000))).is_none());
        assert!(caller_budget(&ctx, &webchat(Some(1_000), None)).is_none());

        let mut no_session = anonymous(uuid::Uuid::now_v7());
        no_session.agent_session_id = None;
        assert!(caller_budget(&no_session, &webchat(Some(1_000), Some(5_000))).is_none());

        let staff = ActionContext::user(crate::context::tests::security_context());
        let unset = WebchatSection::default();
        assert_eq!(
            effective_session_budget(&staff, &unset),
            Some(Budget::PER_SESSION_DEFAULT)
        );
        assert_eq!(
            caller_budget(&staff, &unset).unwrap().budget,
            Budget::PER_CALLER_DEFAULT
        );
    }

    /// The estimate charges the **ceiling**, not an optimistic completion
    /// guess. This is the property that stops a caller sitting just under
    /// budget from starting an unbounded generation — the exact case
    /// `budget::check`'s doc comment says the budget exists for.
    #[test]
    fn the_estimate_assumes_the_completion_runs_to_its_ceiling() {
        let request = request_of(0);
        assert!(
            estimate_tokens(&request, 2_000) >= estimate_tokens(&request, 0) + 2_000,
            "an empty prompt must still be charged the full output ceiling"
        );
    }

    /// A caller's own ceiling never raises the deployment's — mirroring
    /// `GenerationClient::generate`'s clamp, so the estimate can never exceed
    /// what the call will actually be allowed to spend.
    #[test]
    fn a_callers_ceiling_cannot_raise_the_deployments() {
        let mut asks_more = request_of(0);
        asks_more.max_output_tokens = Some(100_000);
        let mut asks_exactly = request_of(0);
        asks_exactly.max_output_tokens = Some(500);
        assert_eq!(
            estimate_tokens(&asks_more, 500),
            estimate_tokens(&asks_exactly, 500)
        );

        let mut asks_less = request_of(0);
        asks_less.max_output_tokens = Some(100);
        assert_eq!(
            estimate_tokens(&asks_less, 500),
            estimate_tokens(&asks_less, 100)
        );
    }

    /// Prompt bytes round **up** to tokens. Rounding down would under-charge
    /// every request by up to a token, and the whole point of a pre-flight
    /// estimate is that it never under-states.
    #[test]
    fn prompt_estimation_rounds_up_never_down() {
        for chars in [0, 1, 4, 5, 1_000] {
            let request = request_of(chars);
            let bytes = request.wire_bytes_estimate("", 0) as u64;
            let estimate = estimate_tokens(&request, 0);
            assert!(estimate * CHARS_PER_TOKEN >= bytes, "{chars} chars");
            assert!(
                estimate * CHARS_PER_TOKEN < bytes + CHARS_PER_TOKEN,
                "{chars} chars"
            );
            assert!(estimate >= (chars as u64).div_ceil(CHARS_PER_TOKEN));
        }
    }

    /// Every message counts, not just the last — a long system prompt plus
    /// retrieved content is exactly the shape that would slip past a
    /// last-message-only estimate.
    #[test]
    fn every_message_in_the_request_is_counted() {
        let many = GenerationRequest::new(vec![
            ChatMessage::system("s".repeat(400)),
            ChatMessage::user("u".repeat(400)),
            ChatMessage::assistant("a".repeat(400)),
        ]);
        assert!(estimate_tokens(&many, 0) >= 300);
    }

    /// **ai-10-10 O16 / BIN-F8.** Tool schemas ride in the request body, so a
    /// request with tools reserves more than the same prompt without them.
    #[test]
    fn a_request_with_tools_reserves_more_than_without() {
        let bare = request_of(100);
        let tools: Vec<attome_inference::ToolDefinition> = (0..20)
            .map(|i| attome_inference::ToolDefinition {
                name: format!("record.tool_{i}"),
                description: "Reads one record by id and returns its fields.".into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": { "id": { "type": "string" } },
                    "required": ["id"],
                }),
            })
            .collect();
        let with_tools = request_of(100).with_tools(tools);
        assert!(
            estimate_tokens(&with_tools, 0) > estimate_tokens(&bare, 0) + 250,
            "twenty tool schemas must not be free: {} vs {}",
            estimate_tokens(&with_tools, 0),
            estimate_tokens(&bare, 0)
        );
    }

    /// Metric labels are stable strings, not `Debug` output — a renamed
    /// variant must not silently rename a Prometheus series.
    #[test]
    fn priority_labels_are_stable_and_distinct() {
        let labels = [
            priority_label(Priority::Drain),
            priority_label(Priority::QueryEmbedding),
            priority_label(Priority::Rerank),
            priority_label(Priority::Chat),
        ];
        let mut seen = std::collections::HashSet::new();
        for label in labels {
            assert!(seen.insert(label), "duplicate priority label {label}");
            assert!(label.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
        }
    }

    fn spend(feature: Option<f64>) -> SpendSection {
        let mut spend = SpendSection {
            deployment_monthly: Some(100.0),
            caller_monthly: Some(10.0),
            agent_monthly: Some(5.0),
            ..SpendSection::default()
        };
        if let Some(cap) = feature {
            spend.feature_monthly.insert("record.summarize".into(), cap);
        }
        spend
    }

    #[test]
    fn spend_windows_are_narrowest_first_and_only_where_capped() {
        let caller = uuid::Uuid::now_v7();
        let agent = uuid::Uuid::now_v7();
        let windows = spend_windows(
            &spend(Some(1.5)),
            Some(caller),
            Some(agent),
            "record.summarize",
        );
        let scopes: Vec<_> = windows.iter().map(|w| w.scope).collect();
        assert_eq!(
            scopes,
            [
                "spend_feature",
                "spend_agent",
                "spend_caller",
                "spend_deployment"
            ]
        );
        assert_eq!(windows[0].limit, 1_500_000);
        assert_eq!(windows[1].key, format!("attome-ai:spend:agent:{agent}"));
        // No agent, an anonymous caller, an uncapped feature: deployment only.
        let windows = spend_windows(&spend(None), None, None, "agent.turn");
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].key, "attome-ai:spend:deployment");
    }

    #[test]
    fn cost_is_tokens_times_price_in_millionths() {
        let price = ModelPrice {
            prompt_per_million: 3.0,
            completion_per_million: 15.0,
        };
        // 1,000 prompt tokens at 3 per million = 0.003 = 3,000 millionths;
        // 200 completion tokens at 15 per million = 0.003 = 3,000.
        assert_eq!(cost_micros(&price, 1_000, 200), 6_000);
        assert_eq!(cost_micros(&price, 0, 0), 0);
    }

    #[test]
    fn a_catalogue_price_is_read_per_million_tokens() {
        let per_1k = price_from_catalogue("per_1k_tokens", 0.003, 0.015).unwrap();
        assert!((per_1k.prompt_per_million - 3.0).abs() < 1e-9);
        assert!((per_1k.completion_per_million - 15.0).abs() < 1e-9);
        assert_eq!(
            price_from_catalogue("per_1m_tokens", 3.0, 15.0),
            Some(ModelPrice {
                prompt_per_million: 3.0,
                completion_per_million: 15.0
            })
        );
        assert_eq!(price_from_catalogue("per_response", 1.0, 1.0), None);
        assert_eq!(price_from_catalogue("per_1m_tokens", -1.0, 1.0), None);
    }

    #[test]
    fn near_cap_is_a_percentage_of_the_limit() {
        assert!(!near_cap(79, 100, 80));
        assert!(near_cap(80, 100, 80));
        assert!(near_cap(100, 100, 100));
        assert!(near_cap(0, 0, 80), "a zero cap is always at its limit");
        assert!(!near_cap(u64::MAX - 1, u64::MAX, 100));
    }

    /// The degrade and refuse decisions against a real counter (the
    /// in-memory store), through the same `reserve` admission uses.
    #[tokio::test]
    async fn a_money_window_refuses_at_its_cap_and_charges_nothing() {
        let redis = attome_cache::Store::memory();
        let plan = SpendPlan {
            price: ModelPrice {
                prompt_per_million: 1_000.0,
                completion_per_million: 1_000.0,
            },
            windows: vec![SpendWindow {
                key: "attome-ai:spend:deployment".into(),
                limit: 1_000_000,
                scope: "spend_deployment",
            }],
        };
        // 600 tokens at 1,000 per million = 0.6 of a 1.0 cap.
        let first = reserve_spend(&redis, plan, 600, Priority::Chat)
            .await
            .expect("within the cap");
        let held = token_window::read(&redis, "attome-ai:spend:deployment", SPEND_WINDOW)
            .await
            .unwrap();
        assert_eq!(held.consumed, 600_000);
        assert!(near_cap(held.consumed, 1_000_000, 50));
        let again = SpendPlan {
            price: first.price,
            windows: vec![SpendWindow {
                key: "attome-ai:spend:deployment".into(),
                limit: 1_000_000,
                scope: "spend_deployment",
            }],
        };
        let refused = reserve_spend(&redis, again, 600, Priority::Chat).await;
        assert!(matches!(refused, Err(AppError::TooManyRequests { .. })));
        let held = token_window::read(&redis, "attome-ai:spend:deployment", SPEND_WINDOW)
            .await
            .unwrap();
        assert_eq!(held.consumed, 600_000, "a refusal charges nothing");
        first.refund(&redis).await;
        let held = token_window::read(&redis, "attome-ai:spend:deployment", SPEND_WINDOW)
            .await
            .unwrap();
        assert_eq!(held.consumed, 0, "a refund returns the reservation");
    }

    /// **The structural claim.** Every `client.generate(` in this crate must
    /// be preceded by a budget admission in the same file — the same
    /// source-scanning shape `read.rs` and `classify.rs` already use to pin
    /// the model-registry check's position, and for the same reason: the
    /// ordering *is* the control, and a diff that drops one line of it looks
    /// entirely ordinary in review.
    #[test]
    fn every_generation_call_site_is_preceded_by_a_budget_admission() {
        for (name, source) in [
            ("read.rs", include_str!("actions/read.rs")),
            ("classify.rs", include_str!("actions/classify.rs")),
            (
                "route_classify.rs",
                include_str!("actions/route_classify.rs"),
            ),
            ("translate.rs", include_str!("actions/translate.rs")),
            ("ai_field.rs", include_str!("actions/ai_field.rs")),
        ] {
            let code: String = source
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");

            let Some(generate_at) = code.find("client.generate(") else {
                panic!("{name} no longer calls client.generate — update this test");
            };
            let admit_at = code.find("budget_guard::admit(").unwrap_or_else(|| {
                panic!(
                    "{name} calls client.generate without admitting against the \
                     token budget first — that is an unmetered generation"
                )
            });
            assert!(
                admit_at < generate_at,
                "{name} must admit against the token budget BEFORE generating, \
                 not after — a budget checked afterwards has already been spent"
            );
        }
    }
}
