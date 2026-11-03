//! One module per `attome` subcommand, each with a `run` entry point.

pub mod ai_pack;
/// AB8-T2: `attome upgrade check|sign-manifest`.
pub mod app_cmd;
pub mod audit_chainer;
pub mod bundle_offline;
pub mod changeset_replay;
/// AB9-T2: `attome drill chaos run`, a catalogue fault injected and undone.
pub mod chaos;
/// AB9-T3: the steady state around a chaos fault.
pub mod chaos_steady;
/// U2-T1: `attome cluster plan`, a deployment profile's files.
pub mod cluster;
/// U3-T1: `attome cluster create|expand`, a profile installed over SSH.
pub mod cluster_ssh;
/// T6-T4: `attome flags list|get|set|off-now`.
pub mod config_cmd;
/// T4-T4: `attome data query|export|import`.
pub mod data;
/// AE2-T2: `attome dev`, rebuilding and uploading an extension as it changes.
pub mod dev;
/// AB4-T3: drill keys, evidence verification and readiness.
pub mod drill;
pub mod flags;
pub mod healthcheck;
pub mod init;
/// T4-T1: `attome login`, `logout` and `targets` (the device grant).
pub mod login;
pub mod migrate;
pub mod model_files;
/// T3-T4: `attome new component`, a custom component project.
pub mod new_component;
/// T4-T5: `--json`, write confirmation and shell completions.
pub mod output;
/// T8-T4: build, publish and install packages.
pub mod package;
/// F9-T8: `attome partner portal-roles`.
pub mod partner_cmd;
pub mod preflight;
pub mod promote;
pub mod runbook;
pub mod secrets;
pub mod service;
pub mod settings;
pub mod sizing;
/// AB1-T1: availability probes and the monthly SLA report.
pub mod sla_report;
pub mod sovereignty;
pub mod status;
pub mod status_page;
pub mod storage_migrate;
/// AB7-T4: zero-downtime restarts over one inherited socket.
pub mod supervise;
/// U8-T1: rolling upgrade with a canary and automatic stop.
pub mod upgrade;
pub mod upgrade_apply;
pub mod upgrade_check;
pub mod verify_audit_chain;
pub mod worker;
/// T4-T3: `attome workspace list|create|switch|preview|publish|refresh|rollback`.
pub mod workspace;
