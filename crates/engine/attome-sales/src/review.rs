//! F8-T8: verified-buyer product reviews, behind a person (V2-D1595 (1)).
//!
//! [`submit`] takes a review from a portal member for a product only when
//! the member's contact has a `fulfilled` order with that product (else
//! `Forbidden`), one review per contact and product, rating 1 to 5. It is
//! written through the record engine as the portal's service user with
//! status `pending`, and nothing publishes it automatically: a store person
//! sets `published`, `held` or `rejected` (with `moderation_reason`) through
//! the generic record API (`PATCH /api/v1/product_review/{id}` with
//! `If-Match`, `product_review.update`). G13's moderation check plugs in
//! here when it exists. [`published`] is all a shopper ever sees: the
//! published reviews of a product, with no name or contact.

use attome_audit::{AuditOperation, BusinessEvent, audit_service, write_business_event_in_tx};
use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

/// The longest review kept.
pub const MAX_BODY_CHARS: usize = 2000;
/// Published reviews listed at most.
const MAX_LISTED: i64 = 100;

/// A published review, as a shopper sees it.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct PublicReview {
    pub rating: Option<f64>,
    pub body: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
}

/// Checks a review's rating and text; the text trimmed. Pure.
pub fn check(rating: i32, body: Option<&str>) -> Result<Option<String>, AppError> {
    if !(1..=5).contains(&rating) {
        return Err(AppError::Validation("rating is 1 to 5".into()));
    }
    let body = body.map(str::trim).filter(|b| !b.is_empty());
    if body.is_some_and(|b| b.chars().count() > MAX_BODY_CHARS) {
        return Err(AppError::Validation(format!(
            "a review is at most {MAX_BODY_CHARS} characters"
        )));
    }
    Ok(body.map(str::to_owned))
}

/// Takes `contact`'s review of `product` as the service user `ctx` for
/// `behalf`; the review's id.
pub async fn submit(
    state: &EngineState,
    ctx: &SecurityContext,
    behalf: &str,
    contact: Uuid,
    product: Uuid,
    rating: i32,
    body: Option<&str>,
) -> Result<Uuid, AppError> {
    let body = check(rating, body)?;
    ctx.require("product_review", "create")?;
    let db = &state.base.db;
    let bought: Option<Uuid> = sqlx::query_scalar(
        "SELECT o.id FROM \"order\" o JOIN order_line l ON l.order_ref = o.id \
          WHERE o.updates_contact_ref = $1 AND l.product_ref = $2 \
            AND o.status::text = 'fulfilled' \
            AND (o.is_active IS NULL OR o.is_active = true) \
            AND (l.is_active IS NULL OR l.is_active = true) \
          ORDER BY o.created_at DESC LIMIT 1",
    )
    .bind(contact)
    .bind(product)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some(order) = bought else {
        return Err(AppError::Forbidden);
    };
    let reviewed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM product_review \
                         WHERE contact_ref = $1 AND product_ref = $2 \
                           AND (is_active IS NULL OR is_active = true))",
    )
    .bind(contact)
    .bind(product)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if reviewed {
        return Err(AppError::Conflict("this product has your review already"));
    }
    let (id, _) = attome_records::entity_crud::create_record_for(
        state,
        ctx,
        ctx.user_id,
        "product_review",
        json!({
            "product_ref": product,
            "contact_ref": contact,
            "order_ref": order,
            "rating": rating,
            "body": body,
            "status": "pending",
        }),
    )
    .await?;
    let mut tx = attome_db::tx::begin(db).await?;
    write_business_event_in_tx(
        &mut tx,
        &audit_service(state),
        BusinessEvent::new(
            "product_review",
            id,
            AuditOperation::Create,
            "sales.product_review.submitted",
            ctx.user_id,
        )
        .comment(format!("from the portal, on behalf of {behalf}")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(id)
}

/// `product`'s published reviews, newest first.
pub async fn published(state: &EngineState, product: Uuid) -> Result<Vec<PublicReview>, AppError> {
    sqlx::query_as(
        "SELECT rating::float8 AS rating, body, created_at FROM product_review \
          WHERE product_ref = $1 AND status::text = 'published' \
            AND (is_active IS NULL OR is_active = true) \
          ORDER BY created_at DESC, id DESC LIMIT $2",
    )
    .bind(product)
    .bind(MAX_LISTED)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn review_rating_and_length_are_checked() {
        assert!(check(0, None).is_err());
        assert!(check(6, None).is_err());
        assert_eq!(check(5, Some("  ")).unwrap(), None);
        assert_eq!(check(4, Some(" Good ")).unwrap().as_deref(), Some("Good"));
        assert!(check(3, Some(&"x".repeat(MAX_BODY_CHARS + 1))).is_err());
    }
}
