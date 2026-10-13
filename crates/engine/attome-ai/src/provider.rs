//! The `ai_provider` record as this crate reads it, and the API protocol
//! a provider speaks.
//!
//! **A catalog, plus enough connection detail to enumerate a provider's
//! models — not a dispatch target.** Generation still goes through the single
//! `inference.generation` endpoint `attome-inference` owns (D-360 ruling 3), and
//! [`ApiProtocol`] is deliberately *not* consulted there. D-554 forbids a
//! provider-adapter layer until a native non-OpenAI-compatible API is actually
//! targeted; listing a provider's models is not that, because all three
//! protocols below expose the same `GET {base}/models` shape and differ only
//! in which header carries the key. Adding an adapter to the *generation* path
//! remains a decision to be taken, not a consequence of this module existing.

use attome_types::AppError;
use uuid::Uuid;

/// The entity this module reads. Its physical table is provisioned at runtime
/// from `platform-bundles/attome-ai-provider.json`, not by a migration (I-8).
pub const ENTITY: &str = "ai_provider";

/// Which HTTP API a provider speaks.
///
/// The three values match the identifiers the wider ecosystem uses verbatim
/// (`openai-completions`, `openai-responses`, `anthropic-messages`) rather
/// than being re-slugged into this repo's usual snake_case choice style:
/// these name a published wire protocol, so an operator reading the field
/// should see the name they already know from the provider's own docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiProtocol {
    OpenAiCompletions,
    OpenAiResponses,
    AnthropicMessages,
}

impl ApiProtocol {
    /// Parses the entity's `api_protocol` column. `None` for an unset or
    /// unrecognised value — the caller turns that into a validation error
    /// naming the field, never a silent default: guessing "probably OpenAI"
    /// would send the operator's key to a third party in a header that
    /// provider never asked for.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            "openai-completions" => Some(Self::OpenAiCompletions),
            "openai-responses" => Some(Self::OpenAiResponses),
            "anthropic-messages" => Some(Self::AnthropicMessages),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenAiCompletions => "openai-completions",
            Self::OpenAiResponses => "openai-responses",
            Self::AnthropicMessages => "anthropic-messages",
        }
    }

    /// Every supported protocol, for an error message that tells an operator
    /// what they *can* set rather than only that their value was wrong.
    pub const ALL: [Self; 3] = [
        Self::OpenAiCompletions,
        Self::OpenAiResponses,
        Self::AnthropicMessages,
    ];
}

/// One provider row, as the credential and model-discovery paths need it.
///
/// `credential_ref` is a plain string column holding a
/// `ai_provider_credential.id` — never the key itself (migration 0478).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ProviderRow {
    pub id: Uuid,
    pub provider_id: Option<String>,
    pub name: Option<String>,
    pub endpoint_url: Option<String>,
    pub api_protocol: Option<String>,
    pub credential_ref: Option<String>,
    /// D-568 — this provider's own permission to be dialled at a Base URL
    /// outside the deployment. A write-restricted field (D-507), so only an
    /// administrator or a holder of the field-write grant can set it. `NULL`
    /// (a record that predates the field) reads as "not allowed".
    pub allow_external_endpoint: Option<bool>,
    pub row_version: i64,
}

/// Loads a live provider row. `None` for a missing or soft-deleted record, so
/// the caller can answer `404` without distinguishing the two.
///
/// Engine-owned SQL against the engine's own entity, the same way
/// `model_registry::require_approved_model` reads `ai_model` — the
/// API-first rule (§4) governs *operating* a deployment by hand, not the
/// platform's own queries. Columns are enumerated, never `SELECT *`.
///
/// `is_active IS NOT FALSE`, not `is_deleted`: `ai_provider` is a
/// runtime-provisioned entity table, whose soft-delete flag is `is_active`
/// (`attome-metadata/src/provision/table.rs::ensure_is_active`) — `is_deleted` has
/// never existed on one, and querying it fails every request with "column
/// does not exist" (the live M53 defect `attome_integration::system::load`
/// documents). `IS NOT FALSE` rather than `= true` so a legacy NULL never
/// silently hides an otherwise-active row.
pub async fn load(db: &attome_db::DbPool, id: Uuid) -> Result<Option<ProviderRow>, AppError> {
    sqlx::query_as::<_, ProviderRow>(
        "SELECT id, provider_id, name, endpoint_url, api_protocol, credential_ref, \
                allow_external_endpoint, row_version \
         FROM ai_provider \
         WHERE id = $1 AND is_active IS NOT FALSE",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_protocol_round_trips_through_its_wire_name() {
        for protocol in ApiProtocol::ALL {
            assert_eq!(
                ApiProtocol::parse(protocol.as_str()),
                Some(protocol),
                "{} must parse back to itself",
                protocol.as_str()
            );
        }
    }

    /// The bundle's choice list and this enum are two hand-maintained copies
    /// of one closed set; a value in the bundle that this cannot parse is a
    /// provider an operator can select and then never fetch models for.
    #[test]
    fn the_parsed_set_matches_the_bundle_choice_list() {
        let bundle = include_str!("../../../../platform-bundles/attome-ai-provider.json");
        for protocol in ApiProtocol::ALL {
            assert!(
                bundle.contains(&format!("\"{}\"", protocol.as_str())),
                "platform-bundles/attome-ai-provider.json is missing the api_protocol choice {:?} \
                 — the entity cannot hold a value this crate understands",
                protocol.as_str()
            );
        }
    }

    /// Guessing a default would put the operator's key in a header the
    /// provider never asked for, so an unset column must refuse.
    #[test]
    fn an_unset_or_unknown_protocol_refuses_rather_than_defaulting() {
        assert_eq!(ApiProtocol::parse(""), None);
        assert_eq!(ApiProtocol::parse("openai"), None);
        assert_eq!(ApiProtocol::parse("OPENAI-COMPLETIONS"), None);
    }
}
