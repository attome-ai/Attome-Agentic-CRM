//! `EngineModel` registration for Work Intake & Service Management. Every
//! entity `crate::seed::seed` registers gets generic entity CRUD for free;
//! `crate::convert` adds the Work Request conversion routes, `crate::sla`
//! adds the SLA-policy-assignment route, `crate::clock` (M73/D-422) adds
//! the SLA clock pause/resume routes, and `crate::timeline` (M85) adds the
//! read-only ticket timeline route.
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_SERVICE, ModuleId};
use axum::Router;

/// Registered via `EngineSystem::builder(state).register(ServiceModel)` — only
/// mounted when `service` is a licensed module bit (D-010).
#[derive(Debug)]
pub struct ServiceModel;

impl EngineModel for ServiceModel {
    fn name(&self) -> &'static str {
        "attome-service"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_SERVICE
    }

    /// D-383 — every entity `crate::seed` provisions.
    fn owned_entities(&self) -> &'static [&'static str] {
        &[
            "service_work_request",
            "service_ticket",
            "service_sla_policy",
            "service_offering",
            "service_sla_clock",
            // D-517 — append-only evidence of every SLA due-date calculation.
            "service_sla_calculation",
            // G9-T3: `platform-bundles/attome-service-supplier-sla.json`.
            "supplier_sla_clock",
            // M84 Phase 1 (Queue Management, D-464).
            "service_work_queue",
            "service_work_queue_member",
            // G8-T1: escalation rule sets.
            "service_escalation_rule",
            // G2-T3: conversion maps.
            "service_conversion_map",
            // G3-T1: catalogs, categories and offering versions.
            "service_catalog",
            "service_category",
            "service_offering_version",
            // G3-T2: cart orders.
            "service_request_item",
            "service_fulfilment_task",
            "service_order_guide",
        ]
    }

    fn routes(&self) -> Router<EngineState> {
        crate::convert::routes()
            .merge(crate::sla::routes())
            .merge(crate::offering::routes())
            .merge(crate::clock::routes())
            .merge(crate::timeline::routes())
            .merge(crate::queue::routes())
            .merge(crate::order::routes())
            .merge(crate::presence::routes())
    }
}
