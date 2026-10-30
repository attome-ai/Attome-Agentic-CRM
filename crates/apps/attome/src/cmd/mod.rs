//! One module per `attome` subcommand, each with a `run` entry point.

pub mod ai_pack;
pub mod audit_chainer;
pub mod bundle_offline;
pub mod changeset_replay;
/// U2-T1: `attome cluster plan`, a deployment profile's files.
pub mod cluster;
/// U3-T1: `attome cluster create|expand`, a profile installed over SSH.
pub mod cluster_ssh;
/// T4-T4: `attome data query|export|import`.
pub mod data;
/// AB4-T3: drill keys, evidence verification and readiness.
pub mod drill;
pub mod healthcheck;
pub mod init;
/// T4-T1: `attome login`, `logout` and `targets` (the device grant).
pub mod login;
pub mod migrate;
pub mod model_files;
pub mod preflight;
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
pub mod verify_audit_chain;
pub mod worker;
