//! Z9-T3: routing a task to a model. Each AI task says what it needs
//! ([`TaskNeeds`]); the router picks the cheapest catalogue model that meets
//! the needs and may receive the request's highest data label, and refuses
//! with a clear error when none can.
//!
//! The data rules come first and are never traded for cost or fit:
//!
//! - a model receives content only when the content's label is in its
//!   `allowed_labels`;
//! - `secret` content goes only to a self-hosted model, whatever the model's
//!   own list says;
//! - without `inference.allow_external_provider`, only self-hosted models
//!   receive anything.

use std::cmp::Ordering;

use attome_config::{DataLabel, ModelCapability};

use crate::catalogue::{Catalogue, ModelEntry};

/// Which end of the size range a task prefers when two models cost the same.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PreferredSize {
    /// Classifying, extracting, short answers.
    #[default]
    Small,
    /// Reasoning and long documents.
    Large,
}

/// What one AI task needs from a model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskNeeds<'a> {
    /// The task's name, for the error and the log.
    pub task: &'a str,
    pub capabilities: &'a [ModelCapability],
    /// The smallest context the task fits in, in tokens.
    pub min_context: u32,
    pub preferred: PreferredSize,
}

/// Why no model was chosen. The text names the task and the rule, never the
/// content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RouteError {
    #[error("no model is configured in inference.catalogue for task {task:?}")]
    EmptyCatalogue { task: String },
    #[error(
        "no catalogue model may receive {label:?} content for task {task:?}; \
         allow the label on a suitable model, or keep the content inside the deployment"
    )]
    NoModelForLabel { task: String, label: DataLabel },
    #[error(
        "no catalogue model allowed to receive {label:?} content meets task {task:?}'s needs \
         (capabilities and a context of at least {min_context} tokens)"
    )]
    NoModelMeetsNeeds {
        task: String,
        label: DataLabel,
        min_context: u32,
    },
}

/// Whether the data rules let `label` content reach `model`.
fn may_receive(catalogue: &Catalogue, model: &ModelEntry, label: DataLabel) -> bool {
    let outside_allowed = catalogue.allow_external_provider && label != DataLabel::Secret;
    model.allows(label) && (model.self_hosted || outside_allowed)
}

/// The model `needs` runs on for content whose highest label is `label`.
pub fn route<'c>(
    catalogue: &'c Catalogue,
    needs: &TaskNeeds<'_>,
    label: DataLabel,
) -> Result<&'c ModelEntry, RouteError> {
    candidates(catalogue, needs, label).map(|models| models[0])
}

/// Z9-T4: every model `needs` may run on for `label` content, best first
/// (cheapest, then the preferred size, then catalogue order); never empty.
/// [`crate::fallback`] tries them in this order.
pub fn candidates<'c>(
    catalogue: &'c Catalogue,
    needs: &TaskNeeds<'_>,
    label: DataLabel,
) -> Result<Vec<&'c ModelEntry>, RouteError> {
    if catalogue.is_empty() {
        return Err(RouteError::EmptyCatalogue {
            task: needs.task.to_owned(),
        });
    }
    let allowed: Vec<&ModelEntry> = catalogue
        .models
        .iter()
        .filter(|model| may_receive(catalogue, model, label))
        .collect();
    if allowed.is_empty() {
        return Err(RouteError::NoModelForLabel {
            task: needs.task.to_owned(),
            label,
        });
    }
    let mut fitting: Vec<&ModelEntry> = allowed
        .into_iter()
        .filter(|model| model.can(needs.capabilities) && model.max_context >= needs.min_context)
        .collect();
    if fitting.is_empty() {
        return Err(RouteError::NoModelMeetsNeeds {
            task: needs.task.to_owned(),
            label,
            min_context: needs.min_context,
        });
    }
    // A stable sort: equal models keep the catalogue's order.
    fitting.sort_by(|a, b| {
        let by_cost = a
            .cost_per_1k_tokens
            .partial_cmp(&b.cost_per_1k_tokens)
            .unwrap_or(Ordering::Equal);
        let by_size = match needs.preferred {
            PreferredSize::Small => a.max_context.cmp(&b.max_context),
            PreferredSize::Large => b.max_context.cmp(&a.max_context),
        };
        // Same cost and size: the catalogue's own order decides, so the
        // choice is stable from one call to the next.
        by_cost.then(by_size)
    });
    Ok(fitting)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model(
        id: &str,
        cost: f64,
        context: u32,
        self_hosted: bool,
        labels: &[DataLabel],
    ) -> ModelEntry {
        ModelEntry {
            id: id.to_owned(),
            adapter: "openai_compatible".to_owned(),
            capabilities: vec![ModelCapability::Chat, ModelCapability::Tools],
            max_context: context,
            cost_per_1k_tokens: cost,
            self_hosted,
            allowed_labels: labels.to_vec(),
            max_concurrent: 4,
        }
    }

    const CHAT: TaskNeeds<'static> = TaskNeeds {
        task: "case.summarise",
        capabilities: &[ModelCapability::Chat],
        min_context: 4_000,
        preferred: PreferredSize::Small,
    };

    use DataLabel::{Financial, Health, Internal, Personal, Public, Secret};

    #[test]
    fn router_picks_the_cheapest_allowed_model_that_meets_the_needs() {
        let catalogue = Catalogue {
            models: vec![
                model(
                    "frontier",
                    3.0,
                    200_000,
                    false,
                    &[Public, Internal, Personal],
                ),
                model("local-small", 0.0, 8_000, true, &[Public, Internal]),
                model("hosted-cheap", 0.2, 32_000, false, &[Public, Internal]),
            ],
            allow_external_provider: true,
        };
        assert_eq!(
            route(&catalogue, &CHAT, Internal).unwrap().id,
            "local-small"
        );

        let long = TaskNeeds {
            min_context: 100_000,
            ..CHAT
        };
        assert_eq!(route(&catalogue, &long, Internal).unwrap().id, "frontier");

        let vision = TaskNeeds {
            capabilities: &[ModelCapability::Vision],
            ..CHAT
        };
        assert!(matches!(
            route(&catalogue, &vision, Internal),
            Err(RouteError::NoModelMeetsNeeds { .. })
        ));
    }

    #[test]
    fn router_never_sends_health_content_to_a_model_without_health_allowed() {
        let catalogue = Catalogue {
            models: vec![
                model(
                    "cheap-no-health",
                    0.0,
                    128_000,
                    true,
                    &[Public, Internal, Personal],
                ),
                model(
                    "pricey-health",
                    5.0,
                    128_000,
                    true,
                    &[Public, Internal, Personal, Health],
                ),
            ],
            allow_external_provider: true,
        };
        assert_eq!(
            route(&catalogue, &CHAT, Health).unwrap().id,
            "pricey-health"
        );

        let no_health = Catalogue {
            models: vec![catalogue.models[0].clone()],
            ..catalogue
        };
        let err = route(&no_health, &CHAT, Health).unwrap_err();
        assert_eq!(
            err,
            RouteError::NoModelForLabel {
                task: "case.summarise".into(),
                label: Health
            }
        );
        assert!(err.to_string().contains("Health"), "{err}");
    }

    #[test]
    fn router_keeps_secret_content_and_a_closed_deployment_inside() {
        let outside = model(
            "frontier",
            0.0,
            128_000,
            false,
            &[Public, Internal, Personal, Financial, Health, Secret],
        );
        let inside = model("local", 1.0, 32_000, true, &[Public, Internal, Secret]);
        let open = Catalogue {
            models: vec![outside.clone(), inside.clone()],
            allow_external_provider: true,
        };
        // Cheaper, and its list names `secret`, but it is not self-hosted.
        assert_eq!(route(&open, &CHAT, Secret).unwrap().id, "local");
        assert_eq!(route(&open, &CHAT, Internal).unwrap().id, "frontier");

        let closed = Catalogue {
            allow_external_provider: false,
            ..open
        };
        assert_eq!(route(&closed, &CHAT, Public).unwrap().id, "local");
        assert!(matches!(
            route(&closed, &CHAT, Financial),
            Err(RouteError::NoModelForLabel { .. })
        ));
    }

    #[test]
    fn router_breaks_a_cost_tie_by_the_preferred_size_and_refuses_an_empty_catalogue() {
        let catalogue = Catalogue {
            models: vec![
                model("big", 0.0, 128_000, true, &[Internal]),
                model("small", 0.0, 8_000, true, &[Internal]),
            ],
            allow_external_provider: false,
        };
        assert_eq!(route(&catalogue, &CHAT, Internal).unwrap().id, "small");
        let large = TaskNeeds {
            preferred: PreferredSize::Large,
            ..CHAT
        };
        assert_eq!(route(&catalogue, &large, Internal).unwrap().id, "big");

        assert!(matches!(
            route(&Catalogue::default(), &CHAT, Public),
            Err(RouteError::EmptyCatalogue { .. })
        ));
    }

    #[test]
    fn router_catalogue_is_built_from_config() {
        let section = attome_config::InferenceSection {
            allow_external_provider: true,
            catalogue: vec![
                serde_json::from_value(serde_json::json!({
                    "id": " local ", "max_context": 8192, "self_hosted": true,
                    "capabilities": ["chat"], "allowed_labels": ["internal", "health"]
                }))
                .expect("catalogue model parses"),
            ],
            ..Default::default()
        };
        let catalogue = Catalogue::from_config(&section);
        assert!(catalogue.allow_external_provider);
        assert_eq!(catalogue.models[0].id, "local");
        assert_eq!(route(&catalogue, &CHAT, Health).unwrap().id, "local");
    }
}
