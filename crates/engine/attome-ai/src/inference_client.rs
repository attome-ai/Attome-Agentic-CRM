//! BIN-FX1 — one pooled [`GenerationClient`] per live `AppConfig`.
//!
//! Building a client per turn or per action call built a fresh
//! `reqwest::Client`, and with it a fresh TCP/TLS handshake every call. The
//! client is cheap to clone (its connection pool is shared), so this keeps one
//! per configuration and hands out clones.
//!
//! Cache contract (caching-and-state): source of truth is the process's
//! `Arc<AppConfig>`, which is immutable for its lifetime; the key is that
//! `Arc`'s identity, held as a `Weak` so the entry dies with its config (a new
//! config is a new key, never a stale hit); no TTL is needed; nothing is
//! shared across nodes; a cold start builds on first use; a build failure is
//! returned and nothing is cached.

use std::sync::{Arc, Mutex, PoisonError, Weak};

use attome_config::AppConfig;
use attome_inference::{GenerationClient, InferenceError};

type Slot<K, C> = Mutex<Vec<(Weak<K>, C)>>;

static GENERATION: Slot<AppConfig, GenerationClient> = Mutex::new(Vec::new());

/// The generation client for `config.inference.generation`, built once per
/// config and cloned per call.
pub fn generation_client(config: &Arc<AppConfig>) -> Result<GenerationClient, InferenceError> {
    cached(&GENERATION, config, |config| {
        GenerationClient::new(&config.inference)
    })
}

/// The generation client a task runs on (N25-T1): the catalogue model
/// `inference.task_models` names for it, reached through that model's
/// provider, or `inference.generation` when none is named.
///
/// A routed model must be live in the catalogue and its provider must speak
/// `openai-completions` (one wire format, D-554); its endpoint passes the same
/// reachability rules and dialler as model discovery
/// (`provider_models::http_client_for`). Whether the model is approved is
/// the caller's check, as for every generation
/// (`model_registry::require_approved_model` on `client.model_id()`). Any
/// failure is `NotFound`, the dark shape every unavailable model takes.
pub async fn client_for(
    state: &attome_core::EngineState,
    task: &str,
) -> Result<GenerationClient, attome_types::AppError> {
    use attome_types::AppError;
    let inference = &state.base.config.inference;
    let Some(model) = inference.task_models.get(task).copied() else {
        return generation_client(&state.base.config).map_err(|e| {
            tracing::warn!(error = %e, task, "generation client unavailable");
            AppError::NotFound
        });
    };
    let row: Option<(Option<uuid::Uuid>, Option<String>)> = sqlx::query_as(
        "SELECT provider_ref, provider_model_id FROM ai_model \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(model)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (Some(provider_id), Some(provider_model_id)) = row.unwrap_or((None, None)) else {
        tracing::warn!(task, %model, "routed model is missing, inactive or has no provider");
        return Err(AppError::NotFound);
    };
    let provider = crate::provider::load(&state.base.db, provider_id)
        .await?
        .ok_or(AppError::NotFound)?;
    crate::actions::agent_playground::require_chat_completions(provider.api_protocol.as_deref())?;
    let base_url = provider
        .endpoint_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or(AppError::NotFound)?
        .to_owned();
    let ring = state.base.secrets.load().ai_provider_credential_key.clone();
    let api_key = crate::provider_credential::resolve(
        &state.base.db,
        &ring,
        provider.credential_ref.as_deref(),
    )
    .await?;
    let timeout_secs = match inference.generation.request_timeout_secs {
        0 => 60,
        configured => configured,
    };
    let http = crate::provider_models::http_client_for(
        &base_url,
        inference,
        provider.allow_external_endpoint.unwrap_or(false),
        timeout_secs,
    )
    .await?;
    GenerationClient::for_endpoint(
        attome_config::InferenceEndpoint {
            base_url,
            model: provider_model_id.trim().to_owned(),
            api_key,
            request_timeout_secs: timeout_secs,
        },
        inference.max_output_tokens,
        http,
    )
    .map_err(|e| {
        tracing::warn!(error = %e, task, "routed generation client unavailable");
        AppError::NotFound
    })
}

fn cached<K, C: Clone, E>(
    slot: &Slot<K, C>,
    key: &Arc<K>,
    build: impl FnOnce(&K) -> Result<C, E>,
) -> Result<C, E> {
    let mut entries = slot.lock().unwrap_or_else(PoisonError::into_inner);
    entries.retain(|(owner, _)| owner.strong_count() > 0);
    if let Some((_, client)) = entries
        .iter()
        .find(|(owner, _)| std::ptr::eq(owner.as_ptr(), Arc::as_ptr(key)))
    {
        return Ok(client.clone());
    }
    let client = build(key)?;
    entries.push((Arc::downgrade(key), client.clone()));
    Ok(client)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn a_config_builds_once_a_new_config_builds_its_own_and_a_dropped_one_is_pruned() {
        let slot: Slot<String, usize> = Mutex::new(Vec::new());
        let builds = AtomicUsize::new(0);
        let build = |_: &String| -> Result<usize, ()> { Ok(builds.fetch_add(1, Ordering::SeqCst)) };

        let first = Arc::new("a".to_owned());
        assert_eq!(cached(&slot, &first, build), Ok(0));
        assert_eq!(cached(&slot, &first, build), Ok(0), "reused, not rebuilt");
        assert_eq!(builds.load(Ordering::SeqCst), 1);

        let second = Arc::new("a".to_owned());
        assert_eq!(
            cached(&slot, &second, build),
            Ok(1),
            "keyed by identity, not value"
        );

        drop(first);
        assert_eq!(cached(&slot, &second, build), Ok(1));
        assert_eq!(
            slot.lock().unwrap().len(),
            1,
            "the dropped config's entry is gone"
        );

        let failing = Arc::new("b".to_owned());
        assert_eq!(cached(&slot, &failing, |_| Err::<usize, ()>(())), Err(()));
        assert_eq!(
            slot.lock().unwrap().len(),
            1,
            "a failed build caches nothing"
        );
    }
}
