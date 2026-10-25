//! QuerySpec (roadmap S4): one JSON form for a structured query — entity,
//! columns, a condition tree, sort, paging, grouping and aggregates — that
//! the query engine, saved views and agents share.

pub mod aggregate;
pub mod cases;
pub mod compile;
pub mod model;
pub mod operators;
pub mod routes;
/// S4-T9: saved QuerySpecs with typed parameters.
pub mod saved;
pub mod text;

pub use compile::{Access, Compiled, Env, compile, next_cursor};
pub use model::{
    AggFunc, Aggregate, Condition, DateBucket, GroupKey, OPERATORS, QuerySpec, SortKey,
};
pub use operators::Clock;
pub use routes::RunRequest;
pub use text::parse as parse_text;
