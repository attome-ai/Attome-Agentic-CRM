//! Kinds this crate owns. Engine-specific kinds (entity and attribute
//! adapters, rules, flows, ...) live in the engine that owns them.

pub mod agent;
pub mod environment_variable;
pub mod eval_suite;
pub mod form;
pub mod navigation;
pub mod option_set;
pub mod prompt_override;
pub mod record_type;
pub mod reply_template;
pub mod tour;

pub use agent::{AGENT, AgentKind};
pub use environment_variable::{ENVIRONMENT_VARIABLE, EnvironmentVariableKind};
pub use eval_suite::{EVAL_SUITE, EvalSuiteKind};
pub use form::{ATTRIBUTE, ENTITY, FORM, FormKind};
pub use navigation::{NAVIGATION, NavigationKind};
pub use option_set::{OPTION_SET, OptionSetKind};
pub use prompt_override::{PROMPT_OVERRIDE, PromptOverrideKind};
pub use record_type::{RECORD_TYPE, RecordTypeKind};
pub use reply_template::{REPLY_TEMPLATE, ReplyTemplateKind};
pub use tour::{TOUR, TourKind};
