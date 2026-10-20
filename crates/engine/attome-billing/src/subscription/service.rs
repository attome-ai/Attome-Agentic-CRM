//! The subscription service (roadmap F3-T5): create, amend, cancel, pause,
//! resume and reverse an amendment. Each is one transaction under a
//! per-subscription advisory lock (`attome-billing/subscription:{id}`), so
//! two changes to one subscription never interleave: the second answers
//! 409. Every record is written through the records engine
//! (`create_one_as`/`update_one_as`), so validation, row versions and the
//! change feed apply, and each operation also writes a named change event
//! (`billing.subscription.created`, `.amended`, `.cancelled`, `.paused`,
//! `.resumed`) that the entitlement, revenue and metrics consumers act on
//! after commit, plus one business audit event.
//!
//! A change never edits a segment's quantity or price: it closes the segment
//! in force (its `valid_to`) and opens the next (`segments::split_at`). A
//! mid-period amendment plans a proration charge, or a credit for a
//! decrease, for the rest of the period it falls in
//! (`schedule::proration_for_change`); the billing run invoices it.
//!
//! Sources: by hand, or from an accepted quote (its lines are copied). An
//! order's lines carry no line type yet (D10), so creating from an order is
//! refused until they do.

use attome_core::EngineState;
use attome_core::change_feed::ChangeOperation;
use attome_records::entity_mutation::{CreateStamp, MutationMode, Principal};
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::NaiveDate;
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use super::charge_model::{ChargeModel, period_amount};
use super::schedule::{Alignment, Cadence, Frequency, Timing, periods, proration_for_change};
use super::segments::{ChangeKind, Segment, split_at};

/// Where a new subscription comes from.
#[derive(Debug, Clone)]
pub enum Source {
    ByHand(Vec<NewLine>),
    FromQuote(Uuid),
    FromOrder(Uuid),
}

/// A line of a subscription made by hand.
#[derive(Debug, Clone)]
pub struct NewLine {
    pub product_ref: Uuid,
    pub quantity: Decimal,
    pub unit_price: Decimal,
    /// A `subscription_line.charge_model` choice; `per_unit` when absent.
    pub charge_model: Option<String>,
}

/// What [`create`] needs.
#[derive(Debug, Clone)]
pub struct CreateSubscription {
    pub name: String,
    pub account_ref: Uuid,
    pub currency: String,
    pub start_date: NaiveDate,
    pub end_date: Option<NaiveDate>,
    pub term_months: Option<i32>,
    pub frequency: Cadence,
    pub timing: Timing,
    pub alignment: Alignment,
    pub source: Source,
}

/// One line's change in an amendment.
#[derive(Debug, Clone)]
pub struct LineChange {
    pub line_id: Uuid,
    pub quantity: Decimal,
    pub unit_price: Decimal,
    /// `Add`, `Remove`, `Upgrade`, `Downgrade` or `PriceChange`.
    pub kind: ChangeKind,
}

#[derive(Debug, Clone)]
pub struct Amendment {
    pub effective: NaiveDate,
    pub changes: Vec<LineChange>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AmendmentResult {
    pub amendment_id: Uuid,
    pub segments_opened: usize,
    pub charges: usize,
}

/// The `snake_case` name of a change kind (its stored choice). Pure.
pub fn kind_name(kind: ChangeKind) -> &'static str {
    match kind {
        ChangeKind::New => "new",
        ChangeKind::Add => "add",
        ChangeKind::Remove => "remove",
        ChangeKind::Upgrade => "upgrade",
        ChangeKind::Downgrade => "downgrade",
        ChangeKind::PriceChange => "price_change",
        ChangeKind::Renewal => "renewal",
        ChangeKind::Cancel => "cancel",
        ChangeKind::Pause => "pause",
        ChangeKind::Resume => "resume",
    }
}

fn cadence_name(c: Cadence) -> &'static str {
    match c {
        Cadence::Monthly => "monthly",
        Cadence::Quarterly => "quarterly",
        Cadence::Yearly => "yearly",
    }
}

fn cadence_of(s: Option<&str>) -> Cadence {
    match s {
        Some("quarterly") => Cadence::Quarterly,
        Some("yearly") => Cadence::Yearly,
        _ => Cadence::Monthly,
    }
}

fn timing_of(s: Option<&str>) -> Timing {
    if s == Some("arrears") {
        Timing::Arrears
    } else {
        Timing::Advance
    }
}

fn alignment_of(s: Option<&str>) -> Alignment {
    if s == Some("calendar_month") {
        Alignment::CalendarMonth
    } else {
        Alignment::Anniversary
    }
}

/// The charge model a line's stored choice names; tiers are not needed for
/// a proration estimate of flat and per-unit lines, so a tiered line is
/// priced per unit here and re-rated by the billing run. Pure.
fn model_of(choice: Option<&str>) -> ChargeModel {
    match choice {
        Some("flat") => ChargeModel::Flat,
        _ => ChargeModel::PerUnit,
    }
}

/// The signed proration of one change over the rest of its period: the new
/// period amount less the old, times the share of the period left. Pure.
pub fn proration(
    model: &ChargeModel,
    old: (Decimal, Decimal),
    new: (Decimal, Decimal),
    share: Decimal,
) -> Decimal {
    let before = period_amount(model, old.0, old.1);
    let after = period_amount(model, new.0, new.1);
    ((after - before) * share).round_dp(2)
}

fn num(d: Decimal) -> Value {
    d.to_f64().map_or(Value::Null, |f| json!(f))
}

fn date(d: NaiveDate) -> Value {
    Value::String(d.to_string())
}

fn uuid(u: Uuid) -> Value {
    Value::String(u.to_string())
}

/// The entities the service writes, resolved once per call.
struct Entities {
    subscription: (Uuid, Vec<attome_core::AttrInfo>),
    line: (Uuid, Vec<attome_core::AttrInfo>),
    segment: (Uuid, Vec<attome_core::AttrInfo>),
    charge: (Uuid, Vec<attome_core::AttrInfo>),
}

impl Entities {
    async fn resolve(state: &EngineState) -> Result<Self, AppError> {
        let one = |name: &'static str| async move {
            let (id, _, attrs, _) =
                attome_records::entity_crud::resolve_entity(state, name).await?;
            Ok::<_, AppError>((id, attrs))
        };
        Ok(Self {
            subscription: one("subscription").await?,
            line: one("subscription_line").await?,
            segment: one("subscription_segment").await?,
            charge: one("subscription_charge").await?,
        })
    }
}

/// One write session: the caller, their stamp and the open transaction.
struct Writer<'a> {
    state: &'a EngineState,
    ctx: &'a SecurityContext,
    stamp: CreateStamp,
    entities: Entities,
}

impl Writer<'_> {
    async fn create(
        &self,
        tx: &mut attome_db::Tx<'_>,
        entity: &str,
        obj: Map<String, Value>,
    ) -> Result<Uuid, AppError> {
        let attrs = self.attrs(entity);
        let result = attome_records::entity_mutation::create_one_as(
            tx,
            self.state,
            Principal::Staff(self.ctx),
            entity,
            attrs,
            &obj,
            CreateStamp {
                created_by: self.stamp.created_by,
                org_ref: self.stamp.org_ref,
                owner_ref: self.stamp.owner_ref,
                owner_type: self.stamp.owner_type,
            },
            MutationMode::Strict,
        )
        .await?;
        Ok(result.record_id)
    }

    async fn update(
        &self,
        tx: &mut attome_db::Tx<'_>,
        entity: &str,
        id: Uuid,
        obj: Map<String, Value>,
    ) -> Result<(), AppError> {
        let row_version: i64 = sqlx::query_scalar(&format!(
            "SELECT row_version FROM {} WHERE id = $1 FOR UPDATE",
            attome_core::quote_ident(entity)
        ))
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound)?;
        let entity_id = self.entity_id(entity);
        attome_records::entity_mutation::update_one_as(
            tx,
            self.state,
            Principal::Staff(self.ctx),
            entity,
            entity_id,
            id,
            self.attrs(entity),
            &obj,
            Some(self.ctx.user_id),
            row_version,
            MutationMode::Strict,
        )
        .await?;
        Ok(())
    }

    fn pair(&self, entity: &str) -> &(Uuid, Vec<attome_core::AttrInfo>) {
        match entity {
            "subscription" => &self.entities.subscription,
            "subscription_line" => &self.entities.line,
            "subscription_segment" => &self.entities.segment,
            _ => &self.entities.charge,
        }
    }

    fn attrs(&self, entity: &str) -> &[attome_core::AttrInfo] {
        &self.pair(entity).1
    }

    fn entity_id(&self, entity: &str) -> Uuid {
        self.pair(entity).0
    }

    async fn event(
        &self,
        tx: &mut attome_db::Tx<'_>,
        subscription: Uuid,
        operation: attome_audit::AuditOperation,
        name: &str,
        comment: String,
    ) -> Result<(), AppError> {
        attome_core::change_feed::emit_named(
            &mut **tx,
            "subscription",
            subscription,
            ChangeOperation::Update,
            name,
        )
        .await?;
        attome_audit::write_business_event_in_tx(
            tx,
            &attome_audit::audit_service(self.state),
            attome_audit::BusinessEvent::new(
                "subscription",
                subscription,
                operation,
                name,
                self.ctx.user_id,
            )
            .comment(comment),
        )
        .await?;
        Ok(())
    }
}

async fn writer<'a>(
    state: &'a EngineState,
    ctx: &'a SecurityContext,
) -> Result<Writer<'a>, AppError> {
    let actor = attome_records::mutation_ring::MutationActor::fetch(state, ctx.user_id).await;
    Ok(Writer {
        state,
        ctx,
        stamp: CreateStamp::staff(ctx.user_id, actor.org_ref),
        entities: Entities::resolve(state).await?,
    })
}

/// Takes the subscription's lock in `tx`, or answers 409.
async fn lock(tx: &mut attome_db::Tx<'_>, subscription: Uuid) -> Result<(), AppError> {
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-billing/subscription:{subscription}"))
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    if locked {
        Ok(())
    } else {
        Err(AppError::Conflict(
            "another change to this subscription is in progress",
        ))
    }
}

/// The subscription's billing terms, read under its lock.
#[derive(Debug, sqlx::FromRow)]
struct Terms {
    status: Option<String>,
    currency: String,
    start_date: NaiveDate,
    end_date: Option<NaiveDate>,
    billing_frequency: Option<String>,
    billing_timing: Option<String>,
    billing_alignment: Option<String>,
}

async fn terms(tx: &mut attome_db::Tx<'_>, subscription: Uuid) -> Result<Terms, AppError> {
    sqlx::query_as(
        "SELECT status, currency, start_date, end_date, billing_frequency, billing_timing, \
                billing_alignment \
           FROM subscription WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(subscription)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

/// A stored segment.
#[derive(Debug, Clone)]
struct StoredSegment {
    id: Uuid,
    segment: Segment,
    invoiced: bool,
}

type SegmentRow = (
    Uuid,
    Uuid,
    NaiveDate,
    Option<NaiveDate>,
    String,
    String,
    Option<String>,
    Option<bool>,
);

fn kind_of(s: Option<&str>) -> ChangeKind {
    serde_json::from_value(Value::String(s.unwrap_or("new").to_owned())).unwrap_or(ChangeKind::New)
}

/// The live segments of a subscription's lines, oldest first.
async fn segments_of(
    tx: &mut attome_db::Tx<'_>,
    subscription: Uuid,
) -> Result<Vec<StoredSegment>, AppError> {
    let rows: Vec<SegmentRow> = sqlx::query_as(
        "SELECT s.id, s.line_ref, s.valid_from, s.valid_to, s.quantity::text, s.unit_price::text, \
                s.change_kind, s.invoiced \
           FROM subscription_segment s JOIN subscription_line l ON l.id = s.line_ref \
          WHERE l.subscription_ref = $1 \
            AND (s.is_active IS NULL OR s.is_active = true) \
            AND (l.is_active IS NULL OR l.is_active = true) \
          ORDER BY s.line_ref, s.valid_from",
    )
    .bind(subscription)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(
            |(id, line, from, to, qty, price, kind, invoiced)| StoredSegment {
                id,
                segment: Segment {
                    line_id: line,
                    valid_from: from,
                    valid_to: to,
                    quantity: qty.parse().unwrap_or_default(),
                    unit_price: price.parse().unwrap_or_default(),
                    change_kind: kind_of(kind.as_deref()),
                },
                invoiced: invoiced.unwrap_or(false),
            },
        )
        .collect())
}

fn in_force(segments: &[StoredSegment], line: Uuid, on: NaiveDate) -> Option<&StoredSegment> {
    segments
        .iter()
        .find(|s| s.segment.line_id == line && s.segment.covers(on))
}

fn segment_body(segment: &Segment, amendment: Option<Uuid>) -> Map<String, Value> {
    let mut obj = Map::new();
    obj.insert("line_ref".into(), uuid(segment.line_id));
    obj.insert("valid_from".into(), date(segment.valid_from));
    obj.insert(
        "valid_to".into(),
        segment.valid_to.map_or(Value::Null, date),
    );
    obj.insert("quantity".into(), num(segment.quantity));
    obj.insert("unit_price".into(), num(segment.unit_price));
    obj.insert(
        "change_kind".into(),
        Value::String(kind_name(segment.change_kind).to_owned()),
    );
    obj.insert("invoiced".into(), Value::Bool(false));
    if let Some(a) = amendment {
        obj.insert("amendment_id".into(), Value::String(a.to_string()));
    }
    obj
}

/// Closes a stored segment at `on`.
async fn close(
    w: &Writer<'_>,
    tx: &mut attome_db::Tx<'_>,
    segment: &StoredSegment,
    on: NaiveDate,
) -> Result<(), AppError> {
    let mut obj = Map::new();
    obj.insert("valid_to".into(), date(on));
    w.update(tx, "subscription_segment", segment.id, obj).await
}

/// Creates a subscription with its lines and their first segments.
pub async fn create(
    state: &EngineState,
    ctx: &SecurityContext,
    input: CreateSubscription,
) -> Result<Uuid, AppError> {
    ctx.require("subscription", "create")?;
    if input.end_date.is_some_and(|end| end <= input.start_date) {
        return Err(AppError::Validation(
            "the end date must come after the start date".into(),
        ));
    }
    let (lines, quote): (Vec<NewLine>, Option<Uuid>) = match &input.source {
        Source::ByHand(lines) => (lines.clone(), None),
        Source::FromQuote(quote) => (quote_lines(state, ctx, *quote).await?, Some(*quote)),
        Source::FromOrder(_) => {
            return Err(AppError::Validation(
                "an order's lines carry no line type yet, so a subscription is created by hand \
                 or from its accepted quote"
                    .into(),
            ));
        }
    };
    if lines.is_empty() {
        return Err(AppError::Validation(
            "a subscription needs at least one line".into(),
        ));
    }
    let w = writer(state, ctx).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let mut sub = Map::new();
    sub.insert("name".into(), Value::String(input.name.clone()));
    sub.insert("account_ref".into(), uuid(input.account_ref));
    sub.insert("currency".into(), Value::String(input.currency.clone()));
    sub.insert("status".into(), Value::String("active".into()));
    sub.insert("start_date".into(), date(input.start_date));
    sub.insert("end_date".into(), input.end_date.map_or(Value::Null, date));
    if let Some(term) = input.term_months {
        sub.insert("term_months".into(), json!(term));
    }
    sub.insert(
        "billing_frequency".into(),
        Value::String(cadence_name(input.frequency).into()),
    );
    sub.insert(
        "billing_timing".into(),
        Value::String(
            match input.timing {
                Timing::Advance => "advance",
                Timing::Arrears => "arrears",
            }
            .into(),
        ),
    );
    sub.insert(
        "billing_alignment".into(),
        Value::String(
            match input.alignment {
                Alignment::Anniversary => "anniversary",
                Alignment::CalendarMonth => "calendar_month",
            }
            .into(),
        ),
    );
    if let Some(q) = quote {
        sub.insert("quote_ref".into(), uuid(q));
    }
    let subscription = w.create(&mut tx, "subscription", sub).await?;
    lock(&mut tx, subscription).await?;
    for line in &lines {
        let mut obj = Map::new();
        obj.insert("subscription_ref".into(), uuid(subscription));
        obj.insert("product_ref".into(), uuid(line.product_ref));
        obj.insert("quantity".into(), num(line.quantity));
        obj.insert("unit_price".into(), num(line.unit_price));
        obj.insert(
            "charge_model".into(),
            Value::String(
                line.charge_model
                    .clone()
                    .unwrap_or_else(|| "per_unit".into()),
            ),
        );
        obj.insert("start_date".into(), date(input.start_date));
        obj.insert("end_date".into(), input.end_date.map_or(Value::Null, date));
        let line_id = w.create(&mut tx, "subscription_line", obj).await?;
        let segment = Segment {
            line_id,
            valid_from: input.start_date,
            valid_to: input.end_date,
            quantity: line.quantity,
            unit_price: line.unit_price,
            change_kind: ChangeKind::New,
        };
        w.create(
            &mut tx,
            "subscription_segment",
            segment_body(&segment, None),
        )
        .await?;
    }
    w.event(
        &mut tx,
        subscription,
        attome_audit::AuditOperation::Create,
        "billing.subscription.created",
        format!("{} lines", lines.len()),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(subscription)
}

/// An accepted quote's lines, as the caller reads the quote.
async fn quote_lines(
    state: &EngineState,
    ctx: &SecurityContext,
    quote: Uuid,
) -> Result<Vec<NewLine>, AppError> {
    let record = attome_records::entity_crud::read_record(state, ctx, "quote", quote).await?;
    if record.data().get("status").and_then(Value::as_str) != Some("accepted") {
        return Err(AppError::Validation(
            "only an accepted quote becomes a subscription".into(),
        ));
    }
    ctx.require("quote_line", "read")?;
    let rows: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT product_ref, quantity::text, unit_price::text FROM quote_line \
          WHERE quote_ref = $1 AND product_ref IS NOT NULL \
            AND (is_active IS NULL OR is_active = true) ORDER BY created_at, id",
    )
    .bind(quote)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(product_ref, qty, price)| NewLine {
            product_ref,
            quantity: qty.parse().unwrap_or(Decimal::ONE),
            unit_price: price.parse().unwrap_or_default(),
            charge_model: None,
        })
        .collect())
}

/// Amends a subscription from `amendment.effective`: each changed line's
/// segment in force is closed and the next opened, and the rest of the
/// period is prorated.
pub async fn amend(
    state: &EngineState,
    ctx: &SecurityContext,
    subscription: Uuid,
    amendment: Amendment,
) -> Result<AmendmentResult, AppError> {
    ctx.require("subscription", "update")?;
    if amendment.changes.is_empty() {
        return Err(AppError::Validation(
            "an amendment changes at least one line".into(),
        ));
    }
    let w = writer(state, ctx).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock(&mut tx, subscription).await?;
    let t = terms(&mut tx, subscription).await?;
    if matches!(t.status.as_deref(), Some("cancelled" | "ended")) {
        return Err(AppError::Validation(
            "a cancelled or ended subscription is not amended".into(),
        ));
    }
    let frequency = Frequency {
        cadence: cadence_of(t.billing_frequency.as_deref()),
        hijri: false,
    };
    let schedule = periods(
        t.start_date,
        t.end_date,
        frequency,
        alignment_of(t.billing_alignment.as_deref()),
        timing_of(t.billing_timing.as_deref()),
        amendment.effective,
    )
    .map_err(|e| AppError::Validation(e.to_string()))?;
    let period = schedule
        .iter()
        .find(|p| p.start <= amendment.effective && amendment.effective < p.end)
        .cloned();
    let stored = segments_of(&mut tx, subscription).await?;
    let models: Vec<(Uuid, Option<String>)> = sqlx::query_as(
        "SELECT id, charge_model FROM subscription_line WHERE subscription_ref = $1",
    )
    .bind(subscription)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let amendment_id = Uuid::now_v7();
    let mut opened = 0;
    let mut charges = 0;
    for change in &amendment.changes {
        let current = in_force(&stored, change.line_id, amendment.effective).ok_or_else(|| {
            AppError::Validation(format!(
                "line {} has no segment in force on {}",
                change.line_id, amendment.effective
            ))
        })?;
        // F3-T6: a new price needs its own privilege.
        if change.unit_price != current.segment.unit_price {
            ctx.require("subscription", "amend_price")?;
        }
        let (_, next) = split_at(
            &current.segment,
            amendment.effective,
            change.quantity,
            change.unit_price,
            change.kind,
        )
        .map_err(|e| AppError::Validation(e.to_string()))?;
        close(&w, &mut tx, current, amendment.effective).await?;
        w.create(
            &mut tx,
            "subscription_segment",
            segment_body(&next, Some(amendment_id)),
        )
        .await?;
        opened += 1;
        if let Some(period) = &period {
            let model = model_of(
                models
                    .iter()
                    .find(|(id, _)| *id == change.line_id)
                    .and_then(|(_, m)| m.as_deref()),
            );
            let amount = proration(
                &model,
                (current.segment.quantity, current.segment.unit_price),
                (change.quantity, change.unit_price),
                proration_for_change(period, amendment.effective),
            );
            if !amount.is_zero() {
                let mut obj = Map::new();
                obj.insert("subscription_ref".into(), uuid(subscription));
                obj.insert("line_ref".into(), uuid(change.line_id));
                obj.insert("period_start".into(), date(amendment.effective));
                obj.insert("period_end".into(), date(period.end));
                obj.insert("amount".into(), num(amount));
                obj.insert("currency".into(), Value::String(t.currency.clone()));
                obj.insert(
                    "kind".into(),
                    Value::String(
                        if amount.is_sign_negative() {
                            "credit"
                        } else {
                            "proration"
                        }
                        .into(),
                    ),
                );
                obj.insert("status".into(), Value::String("planned".into()));
                obj.insert(
                    "idempotency_key".into(),
                    Value::String(format!("amend:{amendment_id}:{}", change.line_id)),
                );
                w.create(&mut tx, "subscription_charge", obj).await?;
                charges += 1;
            }
        }
    }
    w.event(
        &mut tx,
        subscription,
        attome_audit::AuditOperation::Update,
        "billing.subscription.amended",
        format!("amendment {amendment_id} from {}", amendment.effective),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(AmendmentResult {
        amendment_id,
        segments_opened: opened,
        charges,
    })
}

/// Cancels a subscription, at the end of its term or on `on`.
pub async fn cancel(
    state: &EngineState,
    ctx: &SecurityContext,
    subscription: Uuid,
    at_term_end: bool,
    on: NaiveDate,
    reason: &str,
) -> Result<NaiveDate, AppError> {
    ctx.require("subscription", "update")?;
    ctx.require("subscription", "cancel")?;
    let w = writer(state, ctx).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock(&mut tx, subscription).await?;
    let t = terms(&mut tx, subscription).await?;
    let effective = if at_term_end {
        t.end_date.ok_or_else(|| {
            AppError::Validation("an evergreen subscription has no term end to cancel at".into())
        })?
    } else {
        on
    };
    if effective < t.start_date {
        return Err(AppError::Validation(
            "a subscription cannot end before it starts".into(),
        ));
    }
    let stored = segments_of(&mut tx, subscription).await?;
    for s in &stored {
        let runs_past = s.segment.valid_to.is_none_or(|to| to > effective);
        if !runs_past {
            continue;
        }
        if s.segment.valid_from >= effective {
            // Starts after the cancellation: it never takes effect.
            close(&w, &mut tx, s, s.segment.valid_from).await?;
        } else {
            close(&w, &mut tx, s, effective).await?;
        }
    }
    let lines: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM subscription_line WHERE subscription_ref = $1 \
            AND (is_active IS NULL OR is_active = true) \
            AND (end_date IS NULL OR end_date > $2)",
    )
    .bind(subscription)
    .bind(effective)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    for line in lines {
        let mut obj = Map::new();
        obj.insert("end_date".into(), date(effective));
        w.update(&mut tx, "subscription_line", line, obj).await?;
    }
    let mut obj = Map::new();
    obj.insert("cancel_reason".into(), Value::String(reason.to_owned()));
    obj.insert("cancel_effective".into(), date(effective));
    obj.insert("end_date".into(), date(effective));
    if !at_term_end && effective <= on {
        obj.insert("status".into(), Value::String("cancelled".into()));
    }
    w.update(&mut tx, "subscription", subscription, obj).await?;
    w.event(
        &mut tx,
        subscription,
        attome_audit::AuditOperation::Update,
        "billing.subscription.cancelled",
        format!("from {effective}: {reason}"),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(effective)
}

/// Pauses a subscription from `from`, until `resume_on` when given: each
/// line bills nothing while paused.
pub async fn pause(
    state: &EngineState,
    ctx: &SecurityContext,
    subscription: Uuid,
    from: NaiveDate,
    resume_on: Option<NaiveDate>,
) -> Result<(), AppError> {
    ctx.require("subscription", "update")?;
    if resume_on.is_some_and(|r| r <= from) {
        return Err(AppError::Validation(
            "a pause resumes after it starts".into(),
        ));
    }
    let w = writer(state, ctx).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock(&mut tx, subscription).await?;
    let t = terms(&mut tx, subscription).await?;
    if t.status.as_deref() != Some("active") {
        return Err(AppError::Validation(
            "only an active subscription is paused".into(),
        ));
    }
    let stored = segments_of(&mut tx, subscription).await?;
    let lines: Vec<Uuid> = {
        let mut ids: Vec<Uuid> = stored.iter().map(|s| s.segment.line_id).collect();
        ids.dedup();
        ids
    };
    for line in lines {
        let Some(current) = in_force(&stored, line, from) else {
            continue;
        };
        let (_, paused) = split_at(
            &current.segment,
            from,
            Decimal::ZERO,
            current.segment.unit_price,
            ChangeKind::Pause,
        )
        .map_err(|e| AppError::Validation(e.to_string()))?;
        close(&w, &mut tx, current, from).await?;
        let paused = Segment {
            valid_to: resume_on.or(paused.valid_to),
            ..paused
        };
        w.create(&mut tx, "subscription_segment", segment_body(&paused, None))
            .await?;
        if let Some(resume) = resume_on
            && current.segment.valid_to.is_none_or(|to| resume < to)
        {
            let back = Segment {
                line_id: line,
                valid_from: resume,
                valid_to: current.segment.valid_to,
                quantity: current.segment.quantity,
                unit_price: current.segment.unit_price,
                change_kind: ChangeKind::Resume,
            };
            w.create(&mut tx, "subscription_segment", segment_body(&back, None))
                .await?;
        }
    }
    let mut obj = Map::new();
    obj.insert("status".into(), Value::String("paused".into()));
    obj.insert("paused_from".into(), date(from));
    obj.insert("resume_on".into(), resume_on.map_or(Value::Null, date));
    w.update(&mut tx, "subscription", subscription, obj).await?;
    w.event(
        &mut tx,
        subscription,
        attome_audit::AuditOperation::Update,
        "billing.subscription.paused",
        format!("from {from}"),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(())
}

/// Resumes a paused subscription on `on`: each line's pause segment closes
/// there and the line bills at its quantity before the pause again.
pub async fn resume(
    state: &EngineState,
    ctx: &SecurityContext,
    subscription: Uuid,
    on: NaiveDate,
) -> Result<(), AppError> {
    ctx.require("subscription", "update")?;
    let w = writer(state, ctx).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock(&mut tx, subscription).await?;
    let t = terms(&mut tx, subscription).await?;
    if t.status.as_deref() != Some("paused") {
        return Err(AppError::Validation(
            "only a paused subscription is resumed".into(),
        ));
    }
    let stored = segments_of(&mut tx, subscription).await?;
    let pauses: Vec<&StoredSegment> = stored
        .iter()
        .filter(|s| s.segment.change_kind == ChangeKind::Pause && s.segment.covers(on))
        .collect();
    for paused in pauses {
        let before = stored
            .iter()
            .filter(|s| s.segment.line_id == paused.segment.line_id)
            .filter(|s| s.segment.valid_to == Some(paused.segment.valid_from))
            .next_back();
        // A planned resume already opened the next segment: drop it, this
        // resume replaces it.
        if let Some(planned) = stored.iter().find(|s| {
            s.segment.line_id == paused.segment.line_id
                && s.segment.change_kind == ChangeKind::Resume
                && Some(s.segment.valid_from) == paused.segment.valid_to
        }) {
            close(&w, &mut tx, planned, planned.segment.valid_from).await?;
        }
        if on > paused.segment.valid_from {
            close(&w, &mut tx, paused, on).await?;
        }
        let back = Segment {
            line_id: paused.segment.line_id,
            valid_from: on.max(paused.segment.valid_from),
            valid_to: t.end_date,
            quantity: before.map_or(Decimal::ONE, |b| b.segment.quantity),
            unit_price: before.map_or(paused.segment.unit_price, |b| b.segment.unit_price),
            change_kind: ChangeKind::Resume,
        };
        w.create(&mut tx, "subscription_segment", segment_body(&back, None))
            .await?;
    }
    let mut obj = Map::new();
    obj.insert("status".into(), Value::String("active".into()));
    obj.insert("resume_on".into(), Value::Null);
    w.update(&mut tx, "subscription", subscription, obj).await?;
    w.event(
        &mut tx,
        subscription,
        attome_audit::AuditOperation::Update,
        "billing.subscription.resumed",
        format!("on {on}"),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(())
}

/// Reverses an amendment that nothing has invoiced yet: its segments are
/// voided (they end where they start),
/// the segments it closed run on again, and its planned charges are
/// cancelled. Once any of its segments is invoiced, a new amendment is the
/// way back (409).
pub async fn reverse_amendment(
    state: &EngineState,
    ctx: &SecurityContext,
    subscription: Uuid,
    amendment_id: Uuid,
) -> Result<(), AppError> {
    ctx.require("subscription", "update")?;
    let w = writer(state, ctx).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock(&mut tx, subscription).await?;
    let stored = segments_of(&mut tx, subscription).await?;
    let ids: Vec<(Uuid, Option<String>)> = sqlx::query_as(
        "SELECT s.id, s.amendment_id FROM subscription_segment s \
           JOIN subscription_line l ON l.id = s.line_ref \
          WHERE l.subscription_ref = $1 AND s.amendment_id = $2",
    )
    .bind(subscription)
    .bind(amendment_id.to_string())
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let opened: Vec<&StoredSegment> = stored
        .iter()
        .filter(|s| ids.iter().any(|(id, _)| *id == s.id))
        .collect();
    if opened.is_empty() {
        return Err(AppError::NotFound);
    }
    if opened.iter().any(|s| s.invoiced) {
        return Err(AppError::Conflict(
            "part of this amendment is invoiced; amend again instead",
        ));
    }
    for segment in &opened {
        // The segment it closed ran up to its start: let it run on.
        if let Some(previous) = stored.iter().find(|s| {
            s.segment.line_id == segment.segment.line_id
                && s.segment.valid_to == Some(segment.segment.valid_from)
        }) {
            let mut obj = Map::new();
            obj.insert(
                "valid_to".into(),
                segment.segment.valid_to.map_or(Value::Null, date),
            );
            w.update(&mut tx, "subscription_segment", previous.id, obj)
                .await?;
        }
        // Void it: a segment that ends where it starts is in force on no day.
        close(&w, &mut tx, segment, segment.segment.valid_from).await?;
    }
    let planned: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM subscription_charge WHERE subscription_ref = $1 \
            AND idempotency_key LIKE $2 AND status = 'planned'",
    )
    .bind(subscription)
    .bind(format!("amend:{amendment_id}:%"))
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    for charge in planned {
        let mut obj = Map::new();
        obj.insert("status".into(), Value::String("cancelled".into()));
        w.update(&mut tx, "subscription_charge", charge, obj)
            .await?;
    }
    w.event(
        &mut tx,
        subscription,
        attome_audit::AuditOperation::Update,
        "billing.subscription.amended",
        format!("amendment {amendment_id} reversed"),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(())
}

/// F3-T9: a renewal price: `price` raised by `uplift_percent`, to two
/// decimals. Pure.
pub fn uplifted(price: Decimal, uplift_percent: Decimal) -> Decimal {
    (price * (Decimal::ONE_HUNDRED + uplift_percent) / Decimal::ONE_HUNDRED).round_dp(2)
}

/// F3-T9: renews a subscription for another term from its end date: each
/// line still running at the end gets a `renewal` segment at its price
/// raised by `uplift_percent`, and the subscription and its lines end one
/// term later. `renewal_handled_for` records the end date renewed, so a
/// second sweep the same day does nothing. Answers the new end date.
pub async fn renew(
    state: &EngineState,
    ctx: &SecurityContext,
    subscription: Uuid,
    uplift_percent: Decimal,
) -> Result<NaiveDate, AppError> {
    let w = writer(state, ctx).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock(&mut tx, subscription).await?;
    let t = terms(&mut tx, subscription).await?;
    let end = t
        .end_date
        .ok_or_else(|| AppError::Validation("an evergreen subscription is not renewed".into()))?;
    let (months, handled): (Option<f64>, Option<NaiveDate>) = sqlx::query_as(
        "SELECT term_months::float8, renewal_handled_for FROM subscription WHERE id = $1",
    )
    .bind(subscription)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if handled == Some(end) {
        return Ok(end);
    }
    let months = months
        .and_then(|m| u32::try_from(m as i64).ok())
        .filter(|m| *m > 0)
        .unwrap_or(12);
    let new_end = end
        .checked_add_months(chrono::Months::new(months))
        .ok_or_else(|| AppError::Validation("the next term is out of range".into()))?;
    let last_day = end.pred_opt().unwrap_or(end);
    let stored = segments_of(&mut tx, subscription).await?;
    let lines: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM subscription_line WHERE subscription_ref = $1 AND (is_active IS NULL OR is_active = true) AND (end_date IS NULL OR end_date >= $2)",
    )
    .bind(subscription)
    .bind(end)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    for line in lines {
        let Some(current) = in_force(&stored, line, last_day) else {
            continue;
        };
        if current.segment.valid_to.is_some_and(|to| to > end) {
            // Already runs past the end: nothing to open.
            continue;
        }
        let next = Segment {
            line_id: line,
            valid_from: end,
            valid_to: Some(new_end),
            quantity: current.segment.quantity,
            unit_price: uplifted(current.segment.unit_price, uplift_percent),
            change_kind: ChangeKind::Renewal,
        };
        w.create(&mut tx, "subscription_segment", segment_body(&next, None))
            .await?;
        let mut obj = Map::new();
        obj.insert("end_date".into(), date(new_end));
        w.update(&mut tx, "subscription_line", line, obj).await?;
    }
    let mut obj = Map::new();
    obj.insert("end_date".into(), date(new_end));
    obj.insert("renewal_handled_for".into(), date(end));
    w.update(&mut tx, "subscription", subscription, obj).await?;
    w.event(
        &mut tx,
        subscription,
        attome_audit::AuditOperation::Update,
        "billing.subscription.renewed",
        format!("renewed from {end} to {new_end}, uplift {uplift_percent}%"),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(new_end)
}

/// F3-T9: opens a renewal opportunity for a subscription in
/// `renewal_quote` mode (name "Renewal: <subscription>", the account, the
/// end date as the close date, the term's value as the amount) and records
/// the end date as handled, in one transaction. Answers the opportunity.
pub async fn renewal_opportunity(
    state: &EngineState,
    ctx: &SecurityContext,
    subscription: Uuid,
) -> Result<Option<Uuid>, AppError> {
    let w = writer(state, ctx).await?;
    let (_, _, opp_attrs, _) =
        attome_records::entity_crud::resolve_entity(state, "opportunity").await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock(&mut tx, subscription).await?;
    let t = terms(&mut tx, subscription).await?;
    let Some(end) = t.end_date else {
        return Ok(None);
    };
    let (name, account, months, handled): (String, Uuid, Option<f64>, Option<NaiveDate>) =
        sqlx::query_as(
            "SELECT name, account_ref, term_months::float8, renewal_handled_for FROM subscription WHERE id = $1",
        )
        .bind(subscription)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if handled == Some(end) {
        return Ok(None);
    }
    let stored = segments_of(&mut tx, subscription).await?;
    let last_day = end.pred_opt().unwrap_or(end);
    let per_period: Decimal = super::segments::as_of(
        &stored.iter().map(|s| s.segment.clone()).collect::<Vec<_>>(),
        last_day,
    )
    .iter()
    .map(|s| s.quantity * s.unit_price)
    .sum();
    let months = months.map_or(12, |m| m as i64).max(1);
    let periods_per_term = match cadence_of(t.billing_frequency.as_deref()) {
        Cadence::Monthly => months,
        Cadence::Quarterly => (months / 3).max(1),
        Cadence::Yearly => (months / 12).max(1),
    };
    let mut obj = Map::new();
    obj.insert("name".into(), Value::String(format!("Renewal: {name}")));
    obj.insert("account_ref".into(), uuid(account));
    obj.insert("close_date".into(), date(end));
    obj.insert("stage".into(), Value::String("prospecting".into()));
    obj.insert(
        "amount".into(),
        num(per_period * Decimal::from(periods_per_term)),
    );
    let created = attome_records::entity_mutation::create_one_as(
        &mut tx,
        state,
        Principal::Staff(ctx),
        "opportunity",
        &opp_attrs,
        &obj,
        CreateStamp {
            created_by: w.stamp.created_by,
            org_ref: w.stamp.org_ref,
            owner_ref: w.stamp.owner_ref,
            owner_type: w.stamp.owner_type,
        },
        MutationMode::Strict,
    )
    .await?;
    let mut mark = Map::new();
    mark.insert("renewal_handled_for".into(), date(end));
    w.update(&mut tx, "subscription", subscription, mark)
        .await?;
    w.event(
        &mut tx,
        subscription,
        attome_audit::AuditOperation::Update,
        "billing.subscription.renewal_opened",
        format!(
            "renewal opportunity {} for the term ending {end}",
            created.record_id
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Some(created.record_id))
}

/// F3-T9: moves a subscription between lifecycle states outside an
/// amendment (a trial converting or ending), or stamps a field, with its
/// named event. `fields` are written as given.
pub async fn set_fields(
    state: &EngineState,
    ctx: &SecurityContext,
    subscription: Uuid,
    fields: Map<String, Value>,
    event: &str,
) -> Result<(), AppError> {
    let w = writer(state, ctx).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock(&mut tx, subscription).await?;
    let comment = fields.keys().cloned().collect::<Vec<_>>().join(", ");
    w.update(&mut tx, "subscription", subscription, fields)
        .await?;
    w.event(
        &mut tx,
        subscription,
        attome_audit::AuditOperation::Update,
        event,
        comment,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(())
}

/// One line's usage over a range of days.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct UsageTotal {
    pub line_id: Uuid,
    pub metric: String,
    pub quantity: f64,
}

/// F3-T12: a subscription's metered usage per line and metric over
/// `[from, to)`, for a subscription the caller may read.
pub async fn usage_summary(
    state: &EngineState,
    ctx: &SecurityContext,
    subscription: Uuid,
    from: NaiveDate,
    to: NaiveDate,
) -> Result<Vec<UsageTotal>, AppError> {
    attome_records::entity_crud::read_record(state, ctx, "subscription", subscription).await?;
    let rows: Vec<(Uuid, String, f64)> = sqlx::query_as(
        "SELECT d.subscription_line_id, d.metric, SUM(d.quantity)::float8 FROM billing_usage_daily d JOIN subscription_line l ON l.id = d.subscription_line_id WHERE l.subscription_ref = $1 AND d.day >= $2 AND d.day < $3 GROUP BY d.subscription_line_id, d.metric ORDER BY d.subscription_line_id, d.metric",
    )
    .bind(subscription)
    .bind(from)
    .bind(to)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(line_id, metric, quantity)| UsageTotal {
            line_id,
            metric,
            quantity,
        })
        .collect())
}

/// What one line of an amendment would do.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct AmendPreviewLine {
    pub line_id: Uuid,
    pub quantity_before: f64,
    pub unit_price_before: f64,
    pub quantity_after: f64,
    pub unit_price_after: f64,
    /// The proration charge (positive) or credit (negative) for the rest of
    /// the period the change falls in.
    pub proration: f64,
    pub changes_price: bool,
}

/// F3-T12: what [`amend`] would do, changing nothing: each line's values
/// before and after and the proration it would plan. Read as the caller.
pub async fn preview_amend(
    state: &EngineState,
    ctx: &SecurityContext,
    subscription: Uuid,
    amendment: &Amendment,
) -> Result<Vec<AmendPreviewLine>, AppError> {
    attome_records::entity_crud::read_record(state, ctx, "subscription", subscription).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let t = terms(&mut tx, subscription).await?;
    let schedule = periods(
        t.start_date,
        t.end_date,
        Frequency {
            cadence: cadence_of(t.billing_frequency.as_deref()),
            hijri: false,
        },
        alignment_of(t.billing_alignment.as_deref()),
        timing_of(t.billing_timing.as_deref()),
        amendment.effective,
    )
    .map_err(|e| AppError::Validation(e.to_string()))?;
    let period = schedule
        .into_iter()
        .find(|p| p.start <= amendment.effective && amendment.effective < p.end);
    let stored = segments_of(&mut tx, subscription).await?;
    let models: Vec<(Uuid, Option<String>)> = sqlx::query_as(
        "SELECT id, charge_model FROM subscription_line WHERE subscription_ref = $1",
    )
    .bind(subscription)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    let mut out = Vec::new();
    for change in &amendment.changes {
        let current = in_force(&stored, change.line_id, amendment.effective).ok_or_else(|| {
            AppError::Validation(format!(
                "line {} has no segment in force on {}",
                change.line_id, amendment.effective
            ))
        })?;
        let model = model_of(
            models
                .iter()
                .find(|(id, _)| *id == change.line_id)
                .and_then(|(_, m)| m.as_deref()),
        );
        let amount = period.as_ref().map_or(Decimal::ZERO, |p| {
            proration(
                &model,
                (current.segment.quantity, current.segment.unit_price),
                (change.quantity, change.unit_price),
                proration_for_change(p, amendment.effective),
            )
        });
        out.push(AmendPreviewLine {
            line_id: change.line_id,
            quantity_before: current.segment.quantity.to_f64().unwrap_or_default(),
            unit_price_before: current.segment.unit_price.to_f64().unwrap_or_default(),
            quantity_after: change.quantity.to_f64().unwrap_or_default(),
            unit_price_after: change.unit_price.to_f64().unwrap_or_default(),
            proration: amount.to_f64().unwrap_or_default(),
            changes_price: change.unit_price != current.segment.unit_price,
        });
    }
    Ok(out)
}

/// One line as it stood on a date.
#[derive(Debug, Clone, PartialEq, serde::Serialize, utoipa::ToSchema)]
pub struct LineAsOf {
    pub line_id: Uuid,
    pub product_ref: Option<Uuid>,
    /// `None` when the line had no segment in force that day.
    pub quantity: Option<f64>,
    pub unit_price: Option<f64>,
    pub change_kind: Option<String>,
}

/// A subscription as it stood on a date.
#[derive(Debug, Clone, PartialEq, serde::Serialize, utoipa::ToSchema)]
pub struct SubscriptionAsOf {
    pub id: Uuid,
    pub as_of: NaiveDate,
    /// The record as the caller reads it.
    #[schema(value_type = Object)]
    pub subscription: Value,
    pub lines: Vec<LineAsOf>,
}

/// Reads a subscription and its lines as they stood on `as_of`: the record
/// as the caller may read it, and each line's segment in force that day.
pub async fn read_as_of(
    state: &EngineState,
    ctx: &SecurityContext,
    subscription: Uuid,
    as_of: NaiveDate,
) -> Result<SubscriptionAsOf, AppError> {
    let record =
        attome_records::entity_crud::read_record(state, ctx, "subscription", subscription).await?;
    ctx.require("subscription_line", "read")?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let stored = segments_of(&mut tx, subscription).await?;
    let lines: Vec<(Uuid, Option<Uuid>)> = sqlx::query_as(
        "SELECT id, product_ref FROM subscription_line WHERE subscription_ref = $1 AND (is_active IS NULL OR is_active = true) ORDER BY created_at, id",
    )
    .bind(subscription)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    let segments: Vec<Segment> = stored.into_iter().map(|s| s.segment).collect();
    let in_force = super::segments::as_of(&segments, as_of);
    Ok(SubscriptionAsOf {
        id: subscription,
        as_of,
        subscription: record.data().clone(),
        lines: lines
            .into_iter()
            .map(|(line_id, product_ref)| {
                let segment = in_force.iter().find(|s| s.line_id == line_id);
                LineAsOf {
                    line_id,
                    product_ref,
                    quantity: segment.and_then(|s| s.quantity.to_f64()),
                    unit_price: segment.and_then(|s| s.unit_price.to_f64()),
                    change_kind: segment.map(|s| kind_name(s.change_kind).to_owned()),
                }
            })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_names_match_the_stored_choices() {
        for kind in [
            ChangeKind::New,
            ChangeKind::PriceChange,
            ChangeKind::Pause,
            ChangeKind::Resume,
        ] {
            assert_eq!(
                serde_json::to_value(kind).unwrap(),
                Value::String(kind_name(kind).into())
            );
            assert_eq!(kind_of(Some(kind_name(kind))), kind);
        }
    }

    #[test]
    fn an_upgrade_halfway_through_a_period_charges_half_the_difference() {
        let half = Decimal::new(5, 1);
        let charge = proration(
            &ChargeModel::PerUnit,
            (Decimal::from(10), Decimal::from(100)),
            (Decimal::from(20), Decimal::from(100)),
            half,
        );
        assert_eq!(charge, Decimal::from(500));
        let credit = proration(
            &ChargeModel::PerUnit,
            (Decimal::from(20), Decimal::from(100)),
            (Decimal::from(10), Decimal::from(100)),
            half,
        );
        assert_eq!(credit, Decimal::from(-500));
    }
}
