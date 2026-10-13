//! The AI model approval gate (D-435, simplified by D-491) — model approval
//! is DATA, checked before dispatch, and it now lives directly on the AI
//! Model catalog entity rather than in a separate registry.
//!
//! **D-491 removed the separate `ai_model_approval` entity.** D-435
//! originally kept approval as its own record, distinct from the AI Model
//! catalog (`ai_model`, D-490), so that a technical registration
//! ("this model exists, here is its provider and cost") and a governance
//! sign-off ("this model may actually be used") were two different admin
//! actions with two different audit trails. D-491 collapses that into one
//! field, `ai_model.approval_status` (`pending` / `approved` /
//! `blocked`), because every deployment of this platform is single-customer
//! (coding-guidelines.md §8) and the separation-of-duties case for a second
//! entity was judged not worth the extra admin screen for that deployment
//! shape. See `document/decisions/runtime/D-491.md` for the full trade-off
//! this gave up: per-action approval scoping, a distinct "revoked" state,
//! and a separately-recorded approver identity/timestamp.
//!
//! **Named `approval_status`, not `status`, with values `pending`/
//! `approved`/`blocked`, not `active`/`inactive`.** Every entity already
//! carries a generic `is_active` enable/disable column (the platform's
//! standard soft-delete/record-enablement flag, filtered by this catalog's
//! own "Active/Inactive AI Models" queries). Naming this field `status` with
//! `active`/`inactive` values would be a second, easily-confused meaning for
//! the same words on the same row.
//!
//! **Defaults closed, not open.** A freshly registered model starts
//! `pending`, not `approved` — the same "nobody can approve a model on an
//! operator's behalf" posture D-435 established, just enforced by the
//! choice field's first value rather than by a built-in row.
//!
//! **Why this lives here and not in `attome-inference`.** `attome-inference`
//! (D-360, invariant I-11) is the platform's one model-transport crate and
//! must stay XRM-agnostic: it has zero `xrm-*` dependencies, and
//! `layer-guard` enforces that. Whether a model id is approved for use is
//! exactly the kind of XRM governance knowledge `attome-inference` must never
//! hold an opinion about. So the check is a gate `attome-ai` runs on its own
//! model-transport call sites, BEFORE the request reaches
//! `GenerationClient::generate`/`EmbeddingClient::embed` — never inside
//! `attome-inference` itself, and never left to the model server to reject.
//!
//! **Where this is actually called.** `crate::actions::read::RecordSummarize`,
//! `crate::actions::classify::RecordClassify`, and
//! `crate::actions::route_classify::RouteClassify` are, today, the only
//! places in this crate that reach a model (each file's own
//! `client.generate(request)` call) — see each file's
//! `the_model_approval_check_precedes_the_generate_call` test, which asserts
//! the ordering structurally so a later refactor cannot silently drop the
//! check. Any future action that reaches `attome-inference` must call
//! [`require_approved_model`] the same way, before its own transport call.
//!
//! No per-action scoping any more (D-491): approving a model approves it for
//! every action that reaches `attome-inference`, not a chosen subset. The
//! action id a caller passes in is retained only for the warning log line, so
//! an operator can see which action a refusal came from.

use attome_db::DbPool;
use attome_types::AppError;

/// Refuses `model_id` unless a currently-live `ai_model` row names it in
/// `provider_model_id` with `approval_status = 'approved'`.
///
/// **Must be called before any `attome-inference` transport call** — see this
/// module's doc comment. `model_id` is `GenerationClient::model_id()` (or the
/// embedding client's equivalent): the wire identifier the deployment's
/// `inference.generation`/`inference.embedding` config actually points at,
/// which is what an approval must be checked against — not a caller-supplied
/// value, which would let a caller simply omit or misname the model it is
/// really using.
///
/// A model with no matching catalog row, or one whose `approval_status` is
/// not `approved`, is refused with `AppError::NotFound` — the same dark shape
/// `gate::GateRefusal::NotAvailable` uses for an unlicensed or switched-off
/// feature (see that type's doc comment). The caller already knows the
/// ACTION exists (it passed licensing, the kill-switch, and the risk gate to
/// get this far); what is being withheld is a governance detail ("this
/// specific model isn't approved yet") a caller cannot act on anyway. The
/// detail itself is not lost — it is logged at `warn` for an operator, who is
/// the only party who can act on it (by approving the model or pointing
/// configuration at one that already is).
///
/// `fetch_all` rather than `fetch_one`: the catalog does not enforce
/// `provider_model_id` as unique (two catalog rows can legitimately name the
/// same wire model under different `deployment_name`s), so this accepts the
/// model when ANY matching, live catalog row is approved.
pub async fn require_approved_model(
    db: &DbPool,
    model_id: &str,
    action_id: &str,
) -> Result<(), AppError> {
    let statuses: Vec<String> = sqlx::query_scalar(
        "SELECT approval_status FROM ai_model WHERE provider_model_id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(model_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    if !statuses.iter().any(|s| s == "approved") {
        tracing::warn!(
            model_id,
            action_id,
            "AI model is not approved in ai_model.approval_status — refusing before dispatch to attome-inference (D-435, D-491)"
        );
        return Err(AppError::NotFound);
    }
    Ok(())
}
