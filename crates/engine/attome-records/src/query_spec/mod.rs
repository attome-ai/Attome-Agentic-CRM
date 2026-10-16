//! QuerySpec (roadmap S4): one JSON form for a structured query — entity,
//! columns, a condition tree, sort, paging, grouping and aggregates — that
//! the query engine, saved views and agents share.

pub mod model;

pub use model::{
    AggFunc, Aggregate, Condition, DateBucket, GroupKey, OPERATORS, QuerySpec, SortKey,
};
