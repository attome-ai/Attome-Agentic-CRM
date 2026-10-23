//! Z9-T3: the model catalogue — every model the gateway may route to, with
//! what it can do, how much context it takes, what it costs and which data
//! labels it may be sent. Built from `inference.catalogue`; [`crate::router`]
//! picks from it.
//!
//! The catalogue is plain data. It knows nothing about where a label came
//! from: the caller (`attome-ai`) works out the highest label of the content
//! it is about to send and hands it to the router.

use attome_config::{CatalogueModel, DataLabel, InferenceSection, ModelCapability};

/// One routable model.
#[derive(Debug, Clone, PartialEq)]
pub struct ModelEntry {
    /// The model id requested from the provider.
    pub id: String,
    /// The adapter that calls it (`openai_compatible`).
    pub adapter: String,
    pub capabilities: Vec<ModelCapability>,
    /// The largest context it accepts, in tokens.
    pub max_context: u32,
    /// What 1,000 tokens cost, in the deployment's currency.
    pub cost_per_1k_tokens: f64,
    /// Whether it runs inside the deployment.
    pub self_hosted: bool,
    /// The labels of content it may be sent.
    pub allowed_labels: Vec<DataLabel>,
    /// Z9-T6: calls a self-hosted model serves at once.
    pub max_concurrent: usize,
}

impl ModelEntry {
    /// Whether it can do every one of `needs`.
    pub fn can(&self, needs: &[ModelCapability]) -> bool {
        needs.iter().all(|need| self.capabilities.contains(need))
    }

    /// Whether content labelled `label` may be sent to it.
    pub fn allows(&self, label: DataLabel) -> bool {
        self.allowed_labels.contains(&label)
    }
}

impl From<&CatalogueModel> for ModelEntry {
    fn from(model: &CatalogueModel) -> Self {
        Self {
            id: model.id.trim().to_owned(),
            adapter: model.adapter.clone(),
            capabilities: model.capabilities.clone(),
            max_context: model.max_context,
            cost_per_1k_tokens: model.cost_per_1k_tokens,
            self_hosted: model.self_hosted,
            allowed_labels: model.allowed_labels.clone(),
            max_concurrent: model
                .max_concurrent
                .unwrap_or(crate::gpu_queue::DEFAULT_SLOTS),
        }
    }
}

/// Every routable model, and whether the deployment lets content leave it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Catalogue {
    pub models: Vec<ModelEntry>,
    /// `inference.allow_external_provider`: without it, only self-hosted
    /// models receive anything.
    pub allow_external_provider: bool,
}

impl Catalogue {
    /// The catalogue `inference.catalogue` describes.
    pub fn from_config(section: &InferenceSection) -> Self {
        Self {
            models: section.catalogue.iter().map(ModelEntry::from).collect(),
            allow_external_provider: section.allow_external_provider,
        }
    }

    /// Whether nothing is configured, so tasks run on `inference.generation`.
    pub fn is_empty(&self) -> bool {
        self.models.is_empty()
    }
}
