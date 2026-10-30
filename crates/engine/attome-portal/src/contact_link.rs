//! D1-T3: a portal sign-up becomes a known customer only after its email
//! address is verified.
//!
//! When the crm pack is installed (its changeset 0010 adds
//! `webportal_user.contact_ref` and `contact.portal_review`), the signup's
//! verification, in its own transaction, links the new portal user to the
//! contact with that verified email: exactly one live contact with the
//! address is linked; none, or several (which a person must tell apart), gets
//! a new contact marked `portal_review = pending` for staff to confirm or
//! merge. A name never matches on its own. Without the pack nothing happens.
//!
//! The new contact is owned by the portal's owning team, as every record a
//! portal user creates is (G-15); a portal with no live owning team creates
//! none and leaves the user unlinked. Both writes announce the change, and
//! the link is audited in the same transaction.

use attome_core::{EngineState, quote_ident};
use attome_types::AppError;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::provision::PortalDetail;

/// What the verification did about the contact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContactLink {
    /// The one live contact with the verified email.
    Linked(Uuid),
    /// A new contact, pending staff review.
    Created(Uuid),
    /// No contact: the crm pack is not installed, or the portal has no
    /// owning team to own a new one.
    None,
}

/// Whether today's metadata has what linking needs. Pure over the registry.
fn installed(state: &EngineState) -> bool {
    let registry = state.entities.load();
    let has = |entity: &str, field: &str| {
        registry
            .get(entity)
            .is_some_and(|meta| meta.attrs.iter().any(|a| a.logicalname == field))
    };
    has("webportal_user", "contact_ref")
        && has("contact", "email")
        && has("contact", "full_name")
        && has("contact", "portal_review")
}

/// Links `user_id` (just created from a verified signup for `email_lower`)
/// to its contact, inside the signup's transaction (see the module docs).
pub async fn link_verified(
    state: &EngineState,
    tx: &mut Transaction<'_, Postgres>,
    portal: &PortalDetail,
    user_id: Uuid,
    email_lower: &str,
    name: &str,
) -> Result<ContactLink, AppError> {
    if !installed(state) {
        return Ok(ContactLink::None);
    }
    let matches: Vec<Uuid> = sqlx::query_scalar(&format!(
        "SELECT id FROM {contact} WHERE lower(email) = $1 AND is_active = true \
          ORDER BY id LIMIT 2",
        contact = quote_ident("contact"),
    ))
    .bind(email_lower)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;

    let link = if let [only] = matches.as_slice() {
        ContactLink::Linked(*only)
    } else {
        let Some((team, org)) = crate::context::owning_team(&mut *tx, portal).await? else {
            return Ok(ContactLink::None);
        };
        let id = Uuid::now_v7();
        sqlx::query(&format!(
            "INSERT INTO {contact} \
                 (id, full_name, email, portal_review, owner_ref, owner_type, organization_ref) \
             VALUES ($1, $2, $3, 'pending', $4, 1, $5)",
            contact = quote_ident("contact"),
        ))
        .bind(id)
        .bind(name)
        .bind(email_lower)
        .bind(team)
        .bind(org)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
        attome_core::change_feed::emit_tx(tx, "contact", id, attome_core::ChangeOperation::Create)
            .await?;
        ContactLink::Created(id)
    };
    let contact_id = match &link {
        ContactLink::Linked(id) | ContactLink::Created(id) => *id,
        ContactLink::None => return Ok(link),
    };
    sqlx::query(&format!(
        "UPDATE {portal_user} SET contact_ref = $2, row_version = row_version + 1 WHERE id = $1",
        portal_user = quote_ident("webportal_user"),
    ))
    .bind(user_id)
    .bind(contact_id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    attome_core::change_feed::emit_tx(
        tx,
        "webportal_user",
        user_id,
        attome_core::ChangeOperation::Update,
    )
    .await?;
    Ok(link)
}
