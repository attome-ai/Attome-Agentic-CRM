//! One module per `attome` subcommand, each with a `run` entry point.

pub mod ai_pack;
pub mod audit_chainer;
pub mod bundle_offline;
pub mod changeset_replay;
pub mod healthcheck;
pub mod init;
pub mod migrate;
pub mod model_files;
pub mod preflight;
pub mod service;
pub mod sizing;
pub mod sovereignty;
pub mod status;
pub mod verify_audit_chain;
pub mod worker;
