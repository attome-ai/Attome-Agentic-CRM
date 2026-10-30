//! A19-T1: the companion attribute `<field>_currency` beside every money
//! (`currency`) attribute, and the currency given to amounts stored before
//! it existed.
//!
//! The companion is an ordinary text attribute (ISO 4217 code, three
//! capitals), so generic reads, writes, filters, forms and audit carry it
//! with no special path; the record write path (`attome_records::money`)
//! fills it with the base currency when a write names none and rounds the
//! amount to the currency's decimals. Reconciling a money attribute ensures
//! its companion; [`backfill_currency_companions`] adds the companion to
//! money attributes made before A19-T1, at boot. A19-T3: a money attribute
//! whose options carry `fx` also gets `<field>_base` and `<field>_rate`
//! ([`ensure_conversion`]).

use attome_core::money::{BASE_CURRENCY_SETTING, DEFAULT_BASE_CURRENCY, companion};
use attome_core::quote_ident;
use attome_db::DbPool;
use attome_types::AppError;
use serde_json::json;
use uuid::Uuid;

use super::changeset::RecordAs;
use super::identifiers::valid_identifier;
use super::reconcile::{AttributeDesc, ReconcileOutcome, ReconcilePolicy};

/// Rows given the base currency per statement by the backfill.
const BACKFILL_BATCH: i64 = 5_000;

/// Ensures the companion of the money attribute `field` (display name
/// `display_name`) on `entity_id`, under the same policy and layer as the
/// money attribute itself (`rec` records nothing of its own). When the
/// companion is new, amounts already stored get the base currency. A name
/// already taken by an attribute of another type is left alone, with a
/// warning: its amounts are then read as the base currency.
pub(super) async fn ensure_companion(
    db: &DbPool,
    entity_id: Uuid,
    field: &str,
    display_name: &str,
    policy: ReconcilePolicy,
    rec: Option<RecordAs<'_>>,
) -> Result<(), AppError> {
    let name = companion(field);
    if !valid_identifier(&name) {
        tracing::warn!(%entity_id, %field, "money field name too long for a currency companion");
        return Ok(());
    }
    let taken: Option<i32> = sqlx::query_scalar(
        r#"SELECT COALESCE("type", 3) FROM attribute_info
            WHERE entity_ref = $1 AND logicalname = $2
              AND (is_active IS NULL OR is_active = true)
            LIMIT 1"#,
    )
    .bind(entity_id)
    .bind(&name)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    if taken.is_some_and(|t| t != attome_core::FieldType::Text.to_int()) {
        tracing::warn!(
            %entity_id, %field, companion = %name,
            "a currency companion name is taken by an attribute of another type; amounts use the base currency"
        );
        return Ok(());
    }
    let desc = AttributeDesc {
        logicalname: name.clone(),
        display_name: format!("{display_name} currency"),
        field_type: "text".to_owned(),
        is_required: false,
        is_sensitive: false,
        is_write_restricted: None,
        is_sortable: false,
        is_filterable: true,
        lookup_entity: None,
        options: Some(
            json!({"pattern": "^[A-Z]{3}$", "mask_description": "ISO 4217 currency code"}),
        ),
        // The pattern holds the length; a max length would be a contract
        // change, refused inline on a large table.
        max_length: None,
        on_target_delete: None,
        data_classification: None,
        purpose: Some(format!("A19-T1: the currency of {field}")),
    };
    let rec = rec.map(|r| RecordAs {
        recording: r.recording,
        op: None,
    });
    let (_, outcome) =
        super::reconcile::reconcile_attribute_inner(db, entity_id, &desc, None, policy, None, rec)
            .await?;
    if outcome == ReconcileOutcome::Created {
        backfill_base_currency(db, entity_id, field, &name).await?;
    }
    Ok(())
}

/// A19-T3: ensures the number attributes `<field>_base` (the amount in the
/// base currency) and `<field>_rate` (the rate used) beside a money
/// attribute whose options ask for conversion, under the money attribute's
/// policy and layer. The record write path fills them; amounts stored
/// before are converted on their next write. A name already taken by an
/// attribute of another type is left alone, with a warning, and the amount
/// is then not converted.
pub(super) async fn ensure_conversion(
    db: &DbPool,
    entity_id: Uuid,
    field: &str,
    display_name: &str,
    policy: ReconcilePolicy,
    rec: Option<RecordAs<'_>>,
) -> Result<(), AppError> {
    for (name, label, purpose) in [
        (
            attome_core::fx::base_field(field),
            format!("{display_name} (base currency)"),
            format!("A19-T3: {field} in the base currency"),
        ),
        (
            attome_core::fx::rate_field(field),
            format!("{display_name} rate"),
            format!("A19-T3: the exchange rate {field}'s base amount used"),
        ),
    ] {
        if !valid_identifier(&name) {
            tracing::warn!(%entity_id, %field, "money field name too long for its conversion attributes");
            return Ok(());
        }
        let taken: Option<i32> = sqlx::query_scalar(
            r#"SELECT COALESCE("type", 3) FROM attribute_info
                WHERE entity_ref = $1 AND logicalname = $2
                  AND (is_active IS NULL OR is_active = true)
                LIMIT 1"#,
        )
        .bind(entity_id)
        .bind(&name)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        if taken.is_some_and(|t| t != attome_core::FieldType::Number.to_int()) {
            tracing::warn!(
                %entity_id, %field, attribute = %name,
                "a conversion attribute name is taken by an attribute of another type; the amount is not converted"
            );
            return Ok(());
        }
        let desc = AttributeDesc {
            logicalname: name,
            display_name: label,
            field_type: "number".to_owned(),
            is_required: false,
            is_sensitive: false,
            is_write_restricted: None,
            is_sortable: false,
            is_filterable: true,
            lookup_entity: None,
            options: None,
            max_length: None,
            on_target_delete: None,
            data_classification: None,
            purpose: Some(purpose),
        };
        let rec = rec.map(|r| RecordAs {
            recording: r.recording,
            op: None,
        });
        super::reconcile::reconcile_attribute_inner(db, entity_id, &desc, None, policy, None, rec)
            .await?;
    }
    Ok(())
}

/// The deployment's base currency: the setting, else USD.
pub async fn base_currency(db: &DbPool) -> Result<String, AppError> {
    let set: Option<String> = sqlx::query_scalar(
        "SELECT value #>> '{}' FROM setting \
          WHERE key = $1 AND scope = 'deployment' AND NOT is_deleted \
          LIMIT 1",
    )
    .bind(BASE_CURRENCY_SETTING)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?
    .flatten();
    Ok(set
        .filter(|c| attome_core::money::is_code(c))
        .unwrap_or_else(|| DEFAULT_BASE_CURRENCY.to_owned()))
}

/// Gives every stored amount of `field` without a currency the base
/// currency, a bounded batch per statement so a large table is never held
/// by one long update.
async fn backfill_base_currency(
    db: &DbPool,
    entity_id: Uuid,
    field: &str,
    companion_name: &str,
) -> Result<(), AppError> {
    let entity: Option<String> =
        sqlx::query_scalar("SELECT logicalname FROM entity_info WHERE id = $1")
            .bind(entity_id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    let Some(entity) = entity.filter(|e| valid_identifier(e)) else {
        return Ok(());
    };
    let base = base_currency(db).await?;
    let (table, amount, code) = (
        quote_ident(&entity),
        quote_ident(field),
        quote_ident(companion_name),
    );
    let sql = format!(
        "UPDATE {table} SET {code} = $1 \
          WHERE id IN (SELECT id FROM {table} \
                        WHERE {amount} IS NOT NULL AND {code} IS NULL \
                        LIMIT $2)"
    );
    let mut total = 0u64;
    loop {
        let done = sqlx::query(&sql)
            .bind(&base)
            .bind(BACKFILL_BATCH)
            .execute(db)
            .await
            .map_err(AppError::internal)?
            .rows_affected();
        total += done;
        if done < BACKFILL_BATCH as u64 {
            break;
        }
    }
    tracing::info!(%entity, %field, currency = %base, rows = total, "provision: stored amounts given the base currency");
    Ok(())
}

/// Boot sweep: adds the companion to every live money attribute that has
/// none (made before A19-T1), as a project-layer attribute, and gives its
/// stored amounts the base currency. One catalog query; nothing more once
/// every money attribute has its companion.
pub async fn backfill_currency_companions(db: &DbPool) -> Result<(), AppError> {
    let missing: Vec<(Uuid, String, String)> = sqlx::query_as(
        r#"SELECT a.entity_ref, a.logicalname, COALESCE(a.name, a.logicalname)
             FROM attribute_info a
             JOIN entity_info e ON e.id = a.entity_ref
            WHERE a."type" = $1
              AND (a.is_active IS NULL OR a.is_active = true)
              AND (e.is_active IS NULL OR e.is_active = true)
              AND NOT EXISTS (
                  SELECT 1 FROM attribute_info c
                   WHERE c.entity_ref = a.entity_ref
                     AND c.logicalname = a.logicalname || $2
                     AND (c.is_active IS NULL OR c.is_active = true))
            ORDER BY e.logicalname, a.logicalname"#,
    )
    .bind(attome_core::FieldType::Currency.to_int())
    .bind(attome_core::money::CURRENCY_SUFFIX)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    for (entity_id, field, display_name) in missing {
        ensure_companion(
            db,
            entity_id,
            &field,
            &display_name,
            ReconcilePolicy::Admin,
            None,
        )
        .await?;
    }
    Ok(())
}
