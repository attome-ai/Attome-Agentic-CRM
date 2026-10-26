//! Journey action steps (roadmap E8-T7), registered as workflow module
//! steps. `marketing.list_add` and `marketing.list_remove` change a static
//! list's members through E7's own functions (source `flow`), acting as the
//! run's identity (the flow's run-as user), so the list's access rules and
//! audit apply as for any other change. A dry run changes nothing.
//!
//! `marketing.campaign_add` adds the run's person to `config.campaign_id` as
//! a `targeted` member (E1-T3's campaign membership), skipping a person who
//! already is one.
//!
//! `marketing.score_change` and `sales.handoff` are declared so a journey
//! that names them is refused at publish with `feature_unavailable`, until
//! the scoring and hand-off features they call give them a run path.

use attome_core::EngineState;
use attome_core::workflow_step::{StepFuture, StepInvocation, StepOutcome, WorkflowStepHandler};
use attome_modules::{MODULE_MARKETING, ModuleId};
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::static_list::{self, Source};

/// Add (`true`) or remove the run's person from `config.list_id`.
#[derive(Debug)]
pub struct ListMembership {
    pub add: bool,
}

fn list_id(config: &Value) -> Option<Uuid> {
    config
        .get("list_id")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s.trim()).ok())
}

impl WorkflowStepHandler for ListMembership {
    fn key(&self) -> &'static str {
        if self.add {
            "marketing.list_add"
        } else {
            "marketing.list_remove"
        }
    }
    fn module_id(&self) -> ModuleId {
        MODULE_MARKETING
    }
    fn validate_config(&self, config: &Value) -> Result<(), String> {
        list_id(config)
            .map(|_| ())
            .ok_or_else(|| "list_id names a static list".into())
    }
    fn run<'a>(&'a self, state: &'a EngineState, inv: StepInvocation) -> StepFuture<'a> {
        Box::pin(async move {
            let list = list_id(&inv.config)
                .ok_or_else(|| AppError::Validation("list_id names a static list".into()))?;
            let Some(person) = inv.correlation_entity_id else {
                return Ok(StepOutcome::Blocked {
                    reason: "the run has no person".into(),
                    continue_after: true,
                });
            };
            if inv.simulate {
                return Ok(StepOutcome::Done(json!({
                    "would": if self.add { "add to list" } else { "remove from list" },
                    "list_id": list,
                })));
            }
            let user = inv.run_as_user.ok_or(AppError::Forbidden)?;
            let ctx = attome_security::resolve_uncached(&state.base.db, user).await?;
            let change = if self.add {
                static_list::add_member_from_source(state, &ctx, list, person, Source::Flow).await?
            } else {
                static_list::remove_members(state, &ctx, list, &[person]).await?
            };
            Ok(StepOutcome::Done(json!({
                "list_id": list,
                "changed": change.changed,
            })))
        })
    }
}

/// `marketing.campaign_add`: the run's person joins `config.campaign_id`.
#[derive(Debug)]
pub struct CampaignMembership;

fn campaign_id(config: &Value) -> Option<Uuid> {
    config
        .get("campaign_id")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s.trim()).ok())
}

impl WorkflowStepHandler for CampaignMembership {
    fn key(&self) -> &'static str {
        "marketing.campaign_add"
    }
    fn module_id(&self) -> ModuleId {
        MODULE_MARKETING
    }
    fn validate_config(&self, config: &Value) -> Result<(), String> {
        campaign_id(config)
            .map(|_| ())
            .ok_or_else(|| "campaign_id names a campaign".into())
    }
    fn run<'a>(&'a self, state: &'a EngineState, inv: StepInvocation) -> StepFuture<'a> {
        Box::pin(async move {
            let campaign = campaign_id(&inv.config)
                .ok_or_else(|| AppError::Validation("campaign_id names a campaign".into()))?;
            let Some(person) = inv.correlation_entity_id else {
                return Ok(StepOutcome::Blocked {
                    reason: "the run has no person".into(),
                    continue_after: true,
                });
            };
            if inv.simulate {
                return Ok(StepOutcome::Done(json!({
                    "would": "add to campaign",
                    "campaign_id": campaign,
                })));
            }
            let user = inv.run_as_user.ok_or(AppError::Forbidden)?;
            let ctx = attome_security::resolve_uncached(&state.base.db, user).await?;
            let added = crate::campaign::add_person(state, &ctx, campaign, person).await?;
            Ok(StepOutcome::Done(json!({
                "campaign_id": campaign,
                "added": added,
            })))
        })
    }
}

/// A step whose feature has no run path yet: refused at publish.
#[derive(Debug)]
pub struct Unavailable {
    pub key: &'static str,
}

impl WorkflowStepHandler for Unavailable {
    fn key(&self) -> &'static str {
        self.key
    }
    fn module_id(&self) -> ModuleId {
        MODULE_MARKETING
    }
    fn validate_config(&self, _config: &Value) -> Result<(), String> {
        Err("feature_unavailable".into())
    }
    fn run<'a>(&'a self, _state: &'a EngineState, _inv: StepInvocation) -> StepFuture<'a> {
        Box::pin(async { Err(AppError::FeatureUnavailable) })
    }
}

/// The steps declared but not yet runnable.
pub const UNAVAILABLE: [&str; 2] = ["marketing.score_change", "sales.handoff"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unbuilt_steps_are_refused_at_publish() {
        for key in UNAVAILABLE {
            assert_eq!(
                Unavailable { key }.validate_config(&json!({})),
                Err("feature_unavailable".into())
            );
        }
    }

    #[test]
    fn campaign_step_needs_a_campaign() {
        assert!(CampaignMembership.validate_config(&json!({})).is_err());
        assert!(
            CampaignMembership
                .validate_config(&json!({ "campaign_id": Uuid::now_v7() }))
                .is_ok()
        );
    }

    #[test]
    fn list_steps_need_a_list() {
        let add = ListMembership { add: true };
        assert!(add.validate_config(&json!({})).is_err());
        assert!(
            add.validate_config(&json!({ "list_id": Uuid::now_v7() }))
                .is_ok()
        );
    }
}
