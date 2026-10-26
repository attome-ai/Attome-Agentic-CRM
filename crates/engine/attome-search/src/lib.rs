//! `attome-search` — the platform's retrieval engine (`MODULE_SEARCH`).
//!
//! Foundations, in build order:
//!
//! * `lang` — Arabic normalization (TODO-009) and light stemming for Arabic and
//!   English (TODO-010). Built first, deliberately: `P-search-and-retrieval`
//!   §10.3 requires the Arabic test-vector table to exist before the
//!   implementation it judges, because Arabic search without normalization
//!   looks like it works and quietly misses.
//! * `engine` — `EngineModel` registration (TODO-007). The license gate mounts the
//!   QUERY surface only; indexing runs regardless, or licensing search later
//!   would need a full backfill.
//! * migrations `0106` (normalization) and `0107` (`search_index`).
//!
//! Built on them (TODO-011 through TODO-017): the index `drain` and
//! `backfill`, the retrieval `legs`, the `router` that picks and fuses them,
//! and the query `routes`; plus knowledge retrieval, suggest, saved searches
//! and the evaluation harness (see the module list below).
//!
//! **Everything in `lang` runs at both index time and query time, from the same
//! code.** That symmetry is the contract the whole engine rests on: a
//! normalization or stemming step applied on one side only degrades matching
//! silently and progressively, with no error to notice.

pub mod access_cache;
/// A25-T9: search administration routes.
pub mod admin;
pub mod aggregate;
pub mod backfill;
/// A25-T3: synonyms, stop words, boosts, pins and personal ranking.
pub mod controls;
pub mod corpus;
pub mod coverage;
pub mod drain;
/// A25-T4: explaining a result and its rank.
pub mod explain;
pub mod dsl;
pub mod embedding_writer;
pub mod engine;
pub mod eval;
pub mod fallback;
pub mod glossary;
pub mod graph;
pub mod knowledge;
pub mod knowledge_coverage;
pub mod knowledge_eval;
pub mod knowledge_index;
pub mod lang;
pub mod legs;
pub mod metrics;
pub mod project;
/// A25-T8: zero-result and refinement rates from the impression log.
pub mod quality;
pub mod ranking;
pub mod router;
pub mod routes;
pub mod saved_search;
pub mod scheduler;
pub mod share_plan;
pub mod suggest;
pub mod telemetry;
pub mod vector;

pub use access_cache::{AccessMap, AccessMapCache, ResultsCacheKey};
pub use aggregate::{
    AggregateBucket, AggregateRequest, AggregateResponse, AggregateScope, BucketKey, DrillTarget,
    MAX_GROUP_BUCKETS, RecordColumn, StructuredAggregate, StructuredBucket, StructuredRecords,
    key_filters, run_structured_aggregate, run_structured_records,
};
pub use backfill::Backfill;
pub use corpus::knowledge::{ArticleChunk, Passage, chunk_article, expand};
pub use corpus::memory::{
    MAX_FACTS_BYTES, MAX_KIND_CHARS, MAX_RECALL_LIMIT, MAX_SOURCE_REFS_BYTES, MAX_SUMMARY_CHARS,
    MemoryHit, MemoryScopeKind, MemoryVisibility, NewMemory, RecallQuery, erase_for_subject,
    forget, purge_expired, recall, store,
};
pub use corpus::project_record;
pub use coverage::{CoverageReport, CoverageSet};
pub use drain::{DrainStats, delete_row, drain_once, upsert_row};
pub use dsl::{ParsedQuery, parse as parse_dsl};
pub use engine::SearchModel;
pub use eval::{EvalReport, GoldenSet, QueryKind};
pub use graph::{
    Direction as GraphDirection, GraphEdge, GraphNode, MAX_DEPTH as GRAPH_MAX_DEPTH,
    MAX_FANOUT_PER_HOP as GRAPH_MAX_FANOUT_PER_HOP, NodeRefInput as GraphNodeRefInput,
    TraverseOutcome, TraverseRequest as GraphTraverseRequest,
    TraverseResponse as GraphTraverseResponse, traverse as graph_traverse,
};
pub use knowledge::{
    DEFAULT_SEMANTIC_NEIGHBOR_LIMIT, KnowledgeCitation, KnowledgeHit, KnowledgeVisibility,
    LifecycleFilter, RetrievalMode, search_knowledge, search_knowledge_recorded,
    search_knowledge_with, semantic_neighbors, stale_by_source_id,
};
pub use knowledge_index::{
    ReindexStats, backfill_missing as backfill_knowledge_chunks, reindex_item, remove_item_chunks,
};
pub use lang::{normalize_ar, stem_ar, stem_en};
pub use legs::fuse::{FusedOutcome, build_phase, interpret_counts};
pub use legs::stage1::{ExactKeyLeg, FuzzyLeg, LexicalLeg, PrefixLeg};
pub use legs::{Completeness, LegPhase, SqlLeg, VisibilityShape, census, push_leg};
pub use project::{ProjectedRow, content_hash, index_text, project};
pub use ranking::{Candidate, FeatureVector, LinearRanker, Ranker, RankingSignal, extract_all};
pub use router::{Audience, Route, RouteHint, Tuning, route};
pub use routes::{SearchHit, SearchResponse, Total, execute_search};
pub use saved_search::{AlertSweepStats, sweep_alerts};
pub use scheduler::{DRAIN_INTERVAL, drain_tick, run_drain_loop};
pub use share_plan::{SHARE_INVERSION_MAX, plan_visibility_shape};
pub use suggest::{
    RefreshStats, SuggestResponse, Suggestion, refresh as refresh_suggestions, serve as suggest,
};
pub use telemetry::{
    GapTopic, Impression, ImpressionRow, list_gap_topics, normalize_gap_phrase, query_fingerprint,
    record_chunk_retrievals, record_gap_topic, record_impression, record_interaction,
    retrieval_counts_by_source, triage_gap_topic,
};

/// Advisory-lock namespace for the `"attome-search/…"` prefix.
///
/// Registered in `crates/server/tests/advisory_lock_namespaces.rs`. Always
/// taken through the two-argument `pg_try_advisory_xact_lock($1, hashtext($2))`
/// form: `hashtext` returns `int4`, so the one-argument form would put every
/// subsystem's keys into one shared 32-bit space and an unrelated collision
/// would surface here as a drain tick that silently never runs (D-351).
pub const ADVISORY_LOCK_NAMESPACE: i32 = 11;
