//! D-360 / P-inference — the inference stack's configuration, and the
//! platform's AI kill-switch (MASTER-PLAN-AI-PLATFORM TODO-055).
//!
//! Two concerns in one section, deliberately:
//!
//! * **Where models live** — endpoints, model ids, timeouts, token budgets.
//! * **Whether AI runs at all** — a master switch plus per-surface switches an
//!   operator can flip without a release.
//!
//! The kill-switch is not a nice-to-have and not a later hardening pass. An
//! operator must be able to turn every AI surface off during an incident, an
//! injection scare, or a compliance review, and a buyer who licenses the
//! platform now and enables AI next quarter needs the same lever. Building one
//! gate under zero consumers is cheap; retrofitting one under four live ones is
//! not — which is why this lands with the first registry code rather than after
//! the chatbot.
//!
//! The switch is checked at **one** enforcement point, the action registry's
//! gate, so a disabled surface looks exactly like an unlicensed one: actions
//! 404 and components do not render. Two mechanisms producing two different
//! shapes of "not available" is how a UI ends up rendering a button that
//! 500s.

use crate::keyring::KeyRing;
use serde::Deserialize;

use crate::Secret;

/// Which AI surfaces are enabled. Every field defaults to **off**: a
/// deployment that upgrades into a build containing AI code gets no AI
/// behaviour, no model traffic, and no GPU expectation until someone turns it
/// on deliberately. This is the same ships-dark posture `idempotency` and
/// `approval` already use, and it is the correct default for a subsystem whose
/// failure modes include "said something wrong to a customer".
/// `Default` is derived rather than hand-written specifically so that adding a
/// new surface field cannot accidentally default it to `true` — the derive
/// gives every `bool` `false`, which is the ships-dark answer, and there is no
/// hand-maintained list to forget to update.
#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
pub struct AiEnablement {
    /// Master switch. `false` disables **every** AI surface regardless of the
    /// per-surface flags below — an operator reaching for the kill-switch
    /// during an incident must not have to reason about which of five flags
    /// they missed.
    #[serde(default)]
    pub enabled: bool,

    /// AI form fields and components (`MODULE_AI`) — summarise, draft,
    /// classify, translate. Read-only suggestions.
    #[serde(default)]
    pub fields: bool,

    /// The conversational agent (`MODULE_BOT`).
    #[serde(default)]
    pub chat: bool,

    /// Semantic/dense retrieval within search (`MODULE_SEARCH`). Turning this
    /// off leaves lexical search fully working — that degradation is a
    /// supported configuration, not an outage (P-inference §4.3).
    #[serde(default)]
    pub semantic_search: bool,

    /// AI nodes inside workflows (`MODULE_AUTOMATION`).
    #[serde(default)]
    pub workflow_nodes: bool,
}

/// The surfaces the kill-switch can gate, as a closed enum rather than a
/// string. A typo in a string surface name is a silently-ungated feature; this
/// makes the same mistake a compile error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiSurface {
    Fields,
    Chat,
    SemanticSearch,
    WorkflowNodes,
}

impl AiEnablement {
    /// The single question every gate asks. Master switch AND the surface's
    /// own flag — never either alone.
    pub fn allows(&self, surface: AiSurface) -> bool {
        self.enabled
            && match surface {
                AiSurface::Fields => self.fields,
                AiSurface::Chat => self.chat,
                AiSurface::SemanticSearch => self.semantic_search,
                AiSurface::WorkflowNodes => self.workflow_nodes,
            }
    }
}

/// One model endpoint. Both the generation server and the embedding server
/// speak the same OpenAI-compatible HTTP surface (D-360 ruling 3), so one
/// shape describes either.
#[derive(Clone, Deserialize, schemars::JsonSchema)]
pub struct InferenceEndpoint {
    /// Base URL of the serving process, e.g. `http://127.0.0.1:8000/v1`.
    /// Empty means "not configured", which the client reports as unavailable
    /// rather than attempting a request to an empty host.
    #[serde(default)]
    pub base_url: String,

    /// The model id to request. Recorded on every suggestion as provenance
    /// (`model_id`), so an auditor can answer "which model wrote this" — see
    /// TODO-054.
    #[serde(default)]
    pub model: String,

    /// Optional bearer token. Local serving processes normally need none;
    /// this exists for a deployment fronting them with an authenticating
    /// proxy, and for the config-gated external-provider case below.
    #[serde(default)]
    pub api_key: Option<Secret>,

    /// Per-request timeout. Generation is slow by nature and a bare default
    /// would either cut off a legitimate long answer or hang a request thread
    /// for minutes; naming it per endpoint lets the embedding endpoint keep a
    /// tight bound while generation gets a loose one.
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,
}

/// Hand-written: `provider_credential_key` holds the AES master key(s)
/// protecting AI provider API keys at rest, and the section transitively owns
/// the endpoints' own bearer tokens. See `S2SSection`'s impl for why the
/// section owns a hand-written `Debug` (BCF-1).
impl std::fmt::Debug for InferenceSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InferenceSection")
            .field("ai", &self.ai)
            .field("generation", &self.generation)
            .field("embedding", &self.embedding)
            .field("speech", &self.speech)
            .field("ocr", &self.ocr)
            .field("rerank", &self.rerank)
            .field("embedding_query_prefix", &self.embedding_query_prefix)
            .field("embedding_document_prefix", &self.embedding_document_prefix)
            .field("allow_external_provider", &self.allow_external_provider)
            .field(
                "caller_token_budget_per_min",
                &self.caller_token_budget_per_min,
            )
            .field("max_output_tokens", &self.max_output_tokens)
            .field("provider_credential_key", &self.provider_credential_key)
            .field("knowledge_article_entity", &self.knowledge_article_entity)
            .field(
                "knowledge_article_data_source",
                &self.knowledge_article_data_source,
            )
            .field("spend", &self.spend)
            .field("translation", &self.translation)
            .field("task_models", &self.task_models)
            .finish()
    }
}

#[derive(Clone, Deserialize, schemars::JsonSchema)]
pub struct InferenceSection {
    /// The kill-switch. See [`AiEnablement`].
    #[serde(default)]
    pub ai: AiEnablement,

    /// Generation (chat/completions).
    #[serde(default)]
    pub generation: InferenceEndpoint,

    /// Embeddings. Separate serving process from generation by design — one
    /// vLLM instance serves one task, so the VRAM split is a deployment
    /// sizing decision rather than a runtime surprise (D-360 ruling 3).
    #[serde(default)]
    pub embedding: InferenceEndpoint,

    /// Speech to text (N22-T1): an OpenAI-compatible transcription server.
    /// Recordings are customer data, so it must be inside the deployment.
    /// Empty `base_url` means transcription is off.
    #[serde(default)]
    pub speech: InferenceEndpoint,

    /// Reading text from images (N21-T1): a vision-language model behind an
    /// OpenAI-compatible chat endpoint. Documents are customer data, so it
    /// must be inside the deployment. Empty `base_url` means OCR is off.
    #[serde(default)]
    pub ocr: InferenceEndpoint,

    /// Reranking knowledge passages (N15-T1): a cross-encoder behind TEI's
    /// `/rerank`. Inside the deployment only. Empty `base_url`: no reranking,
    /// passages keep their fused order.
    #[serde(default)]
    pub rerank: InferenceEndpoint,

    /// Prefix prepended to every **query** text before it is embedded,
    /// overriding the model-family heuristic (BIN-D6/BIN-G5).
    ///
    /// Asymmetric embedding models (E5, Qwen3) need one prefix for a query and
    /// another for a document, and getting it wrong degrades recall silently
    /// rather than erroring. The heuristic here recognises the families it
    /// knows; this key makes the answer explicit for any model it does not,
    /// and an explicit empty string means "no prefix" — which is how a
    /// deployment turns the heuristic off. Lives on the section rather than on
    /// [`InferenceEndpoint`] because only embedding has prefixes, and because
    /// an endpoint is also built in code where an exhaustive literal exists.
    #[serde(default)]
    pub embedding_query_prefix: Option<String>,

    /// Prefix prepended to every **document** text before it is embedded.
    /// See [`Self::embedding_query_prefix`].
    #[serde(default)]
    pub embedding_document_prefix: Option<String>,

    /// Whether [`Self::generation`]/[`Self::embedding`] may point outside the
    /// data plane.
    ///
    /// **Default false, and load-bearing.** With local inference a prompt
    /// never leaves the customer's plane and no classification event is
    /// raised. Pointing the same client at a third-party API means every
    /// prompt — case notes, customer names, whatever the record holds — is
    /// customer data leaving the plane, classified under the existing
    /// `0087`/`0088` scheme and audited at the moment it is enabled. An
    /// air-gapped deployment must fail at boot if this is true, not at first
    /// use: "we discovered we were sending case notes to a third party" is
    /// not an acceptable way to find out.
    #[serde(default)]
    pub allow_external_provider: bool,

    /// BIN-D7 — deprecated: accepted and ignored, nothing enforces it (the
    /// per-caller budget lives in `xrm-ai`'s budget guard). Kept for one
    /// release so an existing config still loads; boot warns when it is set
    /// (`AppConfig::deprecated_keys`), then the field goes.
    #[serde(default)]
    pub caller_token_budget_per_min: Option<u32>,

    /// Maximum tokens one request may generate. Bounds a runaway loop and
    /// makes latency predictable enough to set a timeout against.
    #[serde(default = "default_max_output_tokens")]
    pub max_output_tokens: u32,

    /// Encrypts `xrm_ai_provider_credential.secret_encrypted` at rest — the
    /// API key an operator gives an `xrm_ai_provider` record so the platform
    /// can list that provider's models.
    ///
    /// Its own [`KeyRing`] and its own trust domain (D-069), deliberately
    /// separate from `integration.credential_encryption_key`: both hold "a
    /// third party's secret", but connector credentials and AI provider keys
    /// are held by different operators and rotated on different schedules, so
    /// a compromise or rotation of one must not implicate the other. Never
    /// used to sign or verify anything.
    ///
    /// Empty by default: a deployment that never sets a provider API key
    /// never needs this configured, and the credential route refuses with an
    /// operator-actionable error rather than encrypting under an absent key.
    #[serde(default)]
    pub provider_credential_key: KeyRing,

    /// The entity `article.draft` writes into (TODO-060).
    ///
    /// Configuration rather than a constant because entities are
    /// **provisioned at runtime through the admin API** (I-8), so a deployment
    /// is free to name its own article entity.
    ///
    /// **Defaults to `xrm_knowledge_data_item`** — the entity D-489 makes the
    /// canonical Knowledge Base article, whose chunks the `xrm-search` drain
    /// projects. Before D-489 the default was `None`, so `article.draft`
    /// refused to run on a stock deployment; now the case→draft loop works
    /// out of the box. Setting it to `null` still disables the action.
    ///
    /// A deployment *can* override the name, but only where `article.draft`
    /// writes changes: the chunking drain and gap-queue retrieval are
    /// hardcoded to the canonical entity's own columns, not to this value, so
    /// an override to anything other than `xrm_knowledge_data_item` gets
    /// drafts written but never chunked or retrievable — `boot.rs`'s
    /// `warn_if_knowledge_article_entity_diverges` logs exactly this at
    /// startup rather than failing silently.
    #[serde(default = "default_knowledge_article_entity")]
    pub knowledge_article_entity: Option<String>,

    /// The Data Source (UUID, as text) new drafts are filed under.
    ///
    /// Required only when the target article entity is the Knowledge Base item,
    /// whose `data_source_ref` lookup is required. A draft is filed by
    /// configuration rather than by the model, because "which container does
    /// this belong in" is a governance decision an operator makes once, not a
    /// model makes per draft. Left unset, a draft against the KB item fails
    /// with a validation error naming this key rather than writing an orphan.
    #[serde(default)]
    pub knowledge_article_data_source: Option<String>,

    /// N24-T1 — money budgets for generation. Empty by default: no prices,
    /// no money budgets, only the token budgets apply.
    #[serde(default)]
    pub spend: SpendSection,

    /// N20-T1 — the deployment's translation glossary.
    #[serde(default)]
    pub translation: TranslationSection,

    /// N25-T1 — which approved catalogue model (`ai_model` id) a task runs
    /// on, by action id (or `agent.turn` for chat and agent turns). A task
    /// not listed runs on `generation`.
    #[serde(default)]
    pub task_models: std::collections::BTreeMap<String, uuid::Uuid>,
}

/// D-489 — the canonical KB article, so the case→draft loop runs unconfigured.
///
/// Naming an engine-provisioned entity here does not break the boundary
/// ruling this crate records (attome-config plan BCF-14): the value is plain
/// data, not an engine dependency, and `attome-config` neither knows nor
/// imports the engine that provisions it. See the plan's §4.1 last bullet.
fn default_knowledge_article_entity() -> Option<String> {
    Some("knowledge_data_item".to_string())
}

impl Default for InferenceSection {
    fn default() -> Self {
        Self {
            ai: AiEnablement::default(),
            generation: InferenceEndpoint::default(),
            embedding: InferenceEndpoint::default(),
            speech: InferenceEndpoint::default(),
            ocr: InferenceEndpoint::default(),
            rerank: InferenceEndpoint::default(),
            embedding_query_prefix: None,
            embedding_document_prefix: None,
            allow_external_provider: false,
            provider_credential_key: KeyRing::default(),
            caller_token_budget_per_min: None,
            max_output_tokens: default_max_output_tokens(),
            knowledge_article_entity: default_knowledge_article_entity(),
            knowledge_article_data_source: None,
            spend: SpendSection::default(),
            translation: TranslationSection::default(),
            task_models: std::collections::BTreeMap::new(),
        }
    }
}

/// N24-T1 — what generation may cost per rolling month (30 days), in the
/// unit the prices are written in (the deployment's currency).
///
/// Every cap is optional and applies only when the generation model has a
/// price: a model with no price is never counted against a money budget
/// (the token budgets still apply). Each cap is a separate window: the
/// whole deployment, each person (`caller_monthly`), each agent
/// (`agent_monthly`, for sessions started with an agent) and each feature
/// (`feature_monthly`, by action id such as `record.summarize`, or
/// `agent.turn` for chat and agent turns). Once any window passes
/// `degrade_at_percent` of its cap, generations are shortened to
/// `degraded_max_output_tokens`; at the cap they are refused (429) before
/// anything is spent.
#[derive(Clone, Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpendSection {
    /// Price per million tokens, by model id (`inference.generation.model`).
    #[serde(default)]
    pub prices: std::collections::BTreeMap<String, ModelPrice>,
    #[serde(default)]
    pub deployment_monthly: Option<f64>,
    #[serde(default)]
    pub caller_monthly: Option<f64>,
    #[serde(default)]
    pub agent_monthly: Option<f64>,
    #[serde(default)]
    pub feature_monthly: std::collections::BTreeMap<String, f64>,
    /// Percent of a cap at which generations are shortened.
    #[serde(default = "default_degrade_at_percent")]
    pub degrade_at_percent: u8,
    /// The output ceiling near a cap; unset leaves generations unshortened.
    #[serde(default)]
    pub degraded_max_output_tokens: Option<u32>,
}

/// N20-T1 — how `text.translate` renders the deployment's own terms:
/// `glossary` maps a term to its translation per language code, e.g.
/// `{ "Purchase order": { "ar": "أمر شراء" } }`. A term found in the text
/// is given to the model with its required translation.
#[derive(Clone, Debug, Default, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TranslationSection {
    #[serde(default)]
    pub glossary: std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>,
}

/// One model's price per million tokens.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelPrice {
    pub prompt_per_million: f64,
    pub completion_per_million: f64,
}

fn default_degrade_at_percent() -> u8 {
    80
}

impl Default for SpendSection {
    fn default() -> Self {
        Self {
            prices: std::collections::BTreeMap::new(),
            deployment_monthly: None,
            caller_monthly: None,
            agent_monthly: None,
            feature_monthly: std::collections::BTreeMap::new(),
            degrade_at_percent: default_degrade_at_percent(),
            degraded_max_output_tokens: None,
        }
    }
}

impl SpendSection {
    /// Whether any money cap is set.
    pub fn has_caps(&self) -> bool {
        self.deployment_monthly.is_some()
            || self.caller_monthly.is_some()
            || self.agent_monthly.is_some()
            || !self.feature_monthly.is_empty()
    }

    /// Boot check: prices and caps are finite and not negative, the degrade
    /// threshold is a percentage, a degraded ceiling is at least one token.
    pub fn validate(&self) -> Result<(), (String, String)> {
        let money = |field: String, value: f64| {
            if value.is_finite() && value >= 0.0 {
                Ok(())
            } else {
                Err((field, "must be a finite amount, not negative".to_owned()))
            }
        };
        for (model, price) in &self.prices {
            money(
                format!("inference.spend.prices.{model}.prompt_per_million"),
                price.prompt_per_million,
            )?;
            money(
                format!("inference.spend.prices.{model}.completion_per_million"),
                price.completion_per_million,
            )?;
        }
        for (field, cap) in [
            ("deployment_monthly", self.deployment_monthly),
            ("caller_monthly", self.caller_monthly),
            ("agent_monthly", self.agent_monthly),
        ] {
            if let Some(cap) = cap {
                money(format!("inference.spend.{field}"), cap)?;
            }
        }
        for (feature, cap) in &self.feature_monthly {
            money(format!("inference.spend.feature_monthly.{feature}"), *cap)?;
        }
        if !(1..=100).contains(&self.degrade_at_percent) {
            return Err((
                "inference.spend.degrade_at_percent".to_owned(),
                "must be between 1 and 100".to_owned(),
            ));
        }
        if self.degraded_max_output_tokens == Some(0) {
            return Err((
                "inference.spend.degraded_max_output_tokens".to_owned(),
                "must be at least 1".to_owned(),
            ));
        }
        Ok(())
    }
}

fn default_request_timeout_secs() -> u64 {
    60
}

/// Hand-written: `api_key` is an optional bearer token for the serving
/// process, and the derived `Debug` would print it raw — including
/// transitively through `InferenceSection`'s own `Debug`.
impl std::fmt::Debug for InferenceEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InferenceEndpoint")
            .field("base_url", &self.base_url)
            .field("model", &self.model)
            .field("api_key", &self.api_key.as_ref().map(|_| "[REDACTED]"))
            .field("request_timeout_secs", &self.request_timeout_secs)
            .finish()
    }
}

/// Hand-written, not derived: a derived `Default` would give
/// `request_timeout_secs = 0`, a timeout that fires before any request can
/// complete, to every endpoint built in code rather than read from a config
/// file (where the serde default above applies). Same values as an empty JSON
/// object.
impl Default for InferenceEndpoint {
    fn default() -> Self {
        Self {
            base_url: String::new(),
            model: String::new(),
            api_key: None,
            request_timeout_secs: default_request_timeout_secs(),
        }
    }
}

/// Whether an endpoint's base URL points inside this deployment.
///
/// Parsed with the same `url` crate the HTTP client (reqwest) uses, so the
/// classifier sees exactly the host the transport will dial — bracketed IPv6
/// literals, integer and hex IPv4 forms, and embedded userinfo included. A
/// string-splitting classifier got all three of those wrong (BCF-F2/BCF-D6).
///
/// Inside means: loopback, RFC1918 (`ip.is_private()`), IPv6 unique-local, an
/// IPv4-mapped in-plane address, `localhost`/`*.localhost`/`*.local`, or a
/// single-label hostname (Docker/Kubernetes service names). **Everything else
/// is external** — public addresses, IPv4 and IPv6 link-local
/// (`169.254.0.0/16`, `fe80::/10`, which includes the cloud metadata service),
/// and anything the parser rejects. That fail-closed direction is the whole
/// point: a false "external" refuses an operator's own host, while a false
/// "internal" lets customer content leave the deployment unnoticed.
///
/// Lives in `attome-config` so boot validation (D-506) and `attome-inference`'s
/// transport share one classifier.
pub fn endpoint_is_in_deployment(base_url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(base_url) else {
        return false;
    };
    match parsed.host() {
        Some(url::Host::Ipv4(v4)) => v4.is_loopback() || v4.is_private(),
        Some(url::Host::Ipv6(v6)) => {
            v6.is_loopback()
                || v6.is_unique_local()
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| mapped.is_loopback() || mapped.is_private())
        }
        Some(url::Host::Domain(name)) => {
            name == "localhost"
                || name.ends_with(".localhost")
                || name.ends_with(".local")
                // A single-label hostname cannot be resolved on the public
                // internet, so it is a container or service name by construction.
                || (!name.is_empty() && !name.contains('.'))
        }
        None => false,
    }
}

fn default_max_output_tokens() -> u32 {
    2_048
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point of the master switch: an operator flips ONE thing and
    /// every surface is off, whatever the per-surface flags say.
    #[test]
    fn master_switch_off_disables_every_surface() {
        let ai = AiEnablement {
            enabled: false,
            fields: true,
            chat: true,
            semantic_search: true,
            workflow_nodes: true,
        };
        for surface in [
            AiSurface::Fields,
            AiSurface::Chat,
            AiSurface::SemanticSearch,
            AiSurface::WorkflowNodes,
        ] {
            assert!(
                !ai.allows(surface),
                "the master switch must dominate every per-surface flag"
            );
        }
    }

    /// The master switch alone enables nothing — a deployment that turns AI
    /// "on" without naming a surface gets no model traffic.
    #[test]
    fn master_switch_alone_enables_nothing() {
        let ai = AiEnablement {
            enabled: true,
            ..AiEnablement::default()
        };
        assert!(!ai.allows(AiSurface::Fields));
        assert!(!ai.allows(AiSurface::Chat));
    }

    #[test]
    fn a_surface_is_allowed_only_when_both_switches_agree() {
        let ai = AiEnablement {
            enabled: true,
            fields: true,
            ..AiEnablement::default()
        };
        assert!(ai.allows(AiSurface::Fields));
        assert!(
            !ai.allows(AiSurface::Chat),
            "one surface must not imply another"
        );
    }

    /// Every default is off. A deployment upgrading into a build that
    /// contains AI code must get no AI behaviour until someone opts in.
    #[test]
    fn everything_ships_dark() {
        let section = InferenceSection::default();
        assert!(!section.ai.enabled);
        assert!(!section.allow_external_provider);
        for surface in [
            AiSurface::Fields,
            AiSurface::Chat,
            AiSurface::SemanticSearch,
            AiSurface::WorkflowNodes,
        ] {
            assert!(!section.ai.allows(surface));
        }
    }

    /// BCF-P0.2 (finding BCF-F2): the classifier must agree with the parser
    /// the transport actually dials, for every host form that parser accepts.
    /// Every "outside" row below is a form the old string-splitting
    /// classifier read as inside.
    #[test]
    fn endpoint_classifier_table() {
        let cases: &[(&str, bool)] = &[
            // Inside this deployment's plane.
            ("http://127.0.0.1:8000/v1", true),
            ("http://localhost:8000/v1", true),
            ("http://localhost/v1", true),
            ("http://[::1]:8000/v1", true),
            ("http://[::1]/v1", true),
            ("http://[fd00::1]:8000/v1", true),
            ("http://[fd00:ec2::254]/v1", true),
            ("http://10.0.0.7:8080/v1", true),
            ("http://172.16.3.9:8000/v1", true),
            ("http://192.168.1.20:8000/v1", true),
            ("http://vllm:8000/v1", true),
            ("http://inference.local/v1", true),
            ("http://svc.localhost/v1", true),
            ("http://user:pass@10.0.0.7:8080/v1", true),
            ("http://127.0.0.1:8000/v1?x=1", true),
            // Outside: public, metadata and link-local are never in-plane.
            ("https://api.openai.com/v1", false),
            ("https://generativelanguage.googleapis.com/v1", false),
            ("http://8.8.8.8/v1", false),
            ("http://134744072/", false),
            ("http://0x08080808/", false),
            ("http://169.254.169.254/latest/meta-data/", false),
            ("http://169.254.169.254", false),
            ("http://[fe80::1]:8000/v1", false),
            ("http://[2001:db8::1]:8000/v1", false),
            ("", false),
            ("not a url at all", false),
            ("tei:80", false),
        ];
        for (url, expected) in cases {
            assert_eq!(
                endpoint_is_in_deployment(url),
                *expected,
                "endpoint_is_in_deployment({url:?})"
            );
        }
    }
}
