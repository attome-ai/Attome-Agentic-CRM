//! CPQ configuration rules (roadmap F1-T1): a bundle product has option
//! groups, each with a minimum and maximum number of choices, and rules
//! between options (one requires another, two exclude each other, or an
//! attome-rules expression over what is chosen). The server validates a
//! configuration and explains every failure, so the quote screen and an
//! agent drafting a quote get the same answer.
//!
//! The model lives in the sales pack's `product_option_group`,
//! `product_option` and `product_option_rule` records ([`load_model`]). In
//! an expression rule each option is a yes/no field named after its
//! product: `opt_` and the product's SKU in lower case with anything but
//! letters and digits as `_` (the first eight hex digits of its id when it
//! has no SKU), for example `opt_ssd_1tb or not opt_raid_kit`. The rule
//! holds when its expression is true; otherwise its message explains the
//! failure. An expression that does not compile fails too, so a broken rule
//! never lets a configuration through.
//!
//! `POST /api/v1/sales/cpq/validate` answers for one bundle and its chosen
//! options, writing nothing.

use std::collections::BTreeSet;

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, SelfService};
use attome_types::{AppError, ErrorResponse};
use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// A group of options inside a bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionGroup {
    pub id: Uuid,
    pub name: String,
    pub min: u32,
    pub max: Option<u32>,
    /// The products that may be chosen in this group.
    pub options: Vec<Uuid>,
}

/// A rule between options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptionRule {
    /// Choosing `option` needs `required` chosen too.
    Requires { option: Uuid, required: Uuid },
    /// `a` and `b` cannot both be chosen.
    Excludes { a: Uuid, b: Uuid },
    /// An attome-rules expression over the options' `opt_` fields that
    /// must be true; `message` explains a failure.
    Expression {
        id: Uuid,
        expression: String,
        message: String,
    },
}

/// A bundle's configuration model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleModel {
    pub bundle: Uuid,
    pub groups: Vec<OptionGroup>,
    pub rules: Vec<OptionRule>,
    /// Each option's field name in expression rules.
    pub keys: Vec<(Uuid, String)>,
}

/// One reason a configuration is not valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    NotAnOption(Uuid),
    TooFew { group: Uuid, min: u32, chosen: u32 },
    TooMany { group: Uuid, max: u32, chosen: u32 },
    MissingRequired { option: Uuid, required: Uuid },
    Excluded { a: Uuid, b: Uuid },
    RuleFailed { rule: Uuid, message: String },
}

/// An option's field name in expression rules. Pure.
pub fn option_key(product: Uuid, sku: Option<&str>) -> String {
    let base = sku
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.to_lowercase()
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                .collect::<String>()
        })
        .unwrap_or_else(|| product.simple().to_string()[..8].to_owned());
    format!("opt_{base}")
}

/// Whether an expression rule holds for `chosen`.
fn expression_holds(model: &BundleModel, expression: &str, chosen: &BTreeSet<Uuid>) -> bool {
    let mut schema = attome_rules::Schema::new();
    let mut ctx = attome_rules::Context::new(chrono::Utc::now());
    for (option, key) in &model.keys {
        schema = schema.with_field(key.clone(), attome_rules::Type::Bool);
        ctx = ctx.with_field(
            key.clone(),
            attome_rules::Value::Bool(chosen.contains(option)),
        );
    }
    match attome_rules::compile(expression, &schema) {
        Ok(compiled) => matches!(compiled.eval(&ctx), Ok(attome_rules::Value::Bool(true))),
        Err(_) => false,
    }
}

/// Validates the chosen options of one bundle; returns every failure.
pub fn validate_configuration(
    model: &BundleModel,
    chosen: &[Uuid],
) -> Result<(), Vec<ConfigError>> {
    let chosen: BTreeSet<Uuid> = chosen.iter().copied().collect();
    let mut errors = Vec::new();
    for option in &chosen {
        if !model.groups.iter().any(|g| g.options.contains(option)) {
            errors.push(ConfigError::NotAnOption(*option));
        }
    }
    for group in &model.groups {
        let count = group.options.iter().filter(|o| chosen.contains(o)).count() as u32;
        if count < group.min {
            errors.push(ConfigError::TooFew {
                group: group.id,
                min: group.min,
                chosen: count,
            });
        }
        if let Some(max) = group.max
            && count > max
        {
            errors.push(ConfigError::TooMany {
                group: group.id,
                max,
                chosen: count,
            });
        }
    }
    for rule in &model.rules {
        match rule {
            OptionRule::Requires { option, required } => {
                if chosen.contains(option) && !chosen.contains(required) {
                    errors.push(ConfigError::MissingRequired {
                        option: *option,
                        required: *required,
                    });
                }
            }
            OptionRule::Excludes { a, b } => {
                if chosen.contains(a) && chosen.contains(b) {
                    errors.push(ConfigError::Excluded { a: *a, b: *b });
                }
            }
            OptionRule::Expression {
                id,
                expression,
                message,
            } => {
                if !expression_holds(model, expression, &chosen) {
                    errors.push(ConfigError::RuleFailed {
                        rule: *id,
                        message: message.clone(),
                    });
                }
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

type GroupRow = (Uuid, Option<String>, Option<f64>, Option<f64>);
type OptionRow = (Uuid, Uuid, Option<String>);
type RuleRow = (
    Uuid,
    Option<String>,
    Option<Uuid>,
    Option<Uuid>,
    Option<String>,
    Option<String>,
);

/// A bundle's model from the sales pack's records.
pub async fn load_model(db: &attome_db::DbPool, bundle: Uuid) -> Result<BundleModel, AppError> {
    let groups: Vec<GroupRow> = sqlx::query_as(
        "SELECT id, name, min_choices::float8, max_choices::float8 FROM product_option_group \
          WHERE bundle_product_ref = $1 AND (is_active IS NULL OR is_active = true) \
          ORDER BY sort_order NULLS LAST, id",
    )
    .bind(bundle)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let options: Vec<OptionRow> = sqlx::query_as(
        "SELECT o.group_ref, o.product_ref, p.sku FROM product_option o \
           JOIN product_option_group g ON g.id = o.group_ref \
           JOIN product p ON p.id = o.product_ref \
          WHERE g.bundle_product_ref = $1 AND (o.is_active IS NULL OR o.is_active = true) \
          ORDER BY o.group_ref, o.id",
    )
    .bind(bundle)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let rules: Vec<RuleRow> = sqlx::query_as(
        "SELECT id, kind, option_ref, other_option_ref, expression, message \
           FROM product_option_rule \
          WHERE bundle_product_ref = $1 AND (is_active IS NULL OR is_active = true) ORDER BY id",
    )
    .bind(bundle)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let count = |v: Option<f64>| v.and_then(|n| u32::try_from(n.max(0.0) as i64).ok());
    Ok(BundleModel {
        bundle,
        groups: groups
            .into_iter()
            .map(|(id, name, min, max)| OptionGroup {
                id,
                name: name.unwrap_or_default(),
                min: count(min).unwrap_or(0),
                max: count(max),
                options: options
                    .iter()
                    .filter(|(group, _, _)| *group == id)
                    .map(|(_, product, _)| *product)
                    .collect(),
            })
            .collect(),
        rules: rules
            .into_iter()
            .filter_map(
                |(id, kind, option, other, expression, message)| match kind.as_deref() {
                    Some("requires") => Some(OptionRule::Requires {
                        option: option?,
                        required: other?,
                    }),
                    Some("excludes") => Some(OptionRule::Excludes {
                        a: option?,
                        b: other?,
                    }),
                    Some("expression") => Some(OptionRule::Expression {
                        id,
                        expression: expression?,
                        message: message.unwrap_or_default(),
                    }),
                    _ => None,
                },
            )
            .collect(),
        keys: options
            .iter()
            .map(|(_, product, sku)| (*product, option_key(*product, sku.as_deref())))
            .collect(),
    })
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SalesCpqValidateBody {
    pub bundle_product_id: Uuid,
    /// The chosen option products.
    pub chosen: Vec<Uuid>,
}

/// One failure, for a person or an agent to act on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SalesCpqProblem {
    /// `not_an_option`, `too_few`, `too_many`, `missing_required`,
    /// `excluded` or `rule_failed`.
    pub code: String,
    pub group_id: Option<Uuid>,
    pub option_id: Option<Uuid>,
    pub other_option_id: Option<Uuid>,
    pub rule_id: Option<Uuid>,
    pub min: Option<u32>,
    pub max: Option<u32>,
    pub chosen: Option<u32>,
    /// A rule's own message.
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SalesCpqValidation {
    pub valid: bool,
    pub problems: Vec<SalesCpqProblem>,
}

/// The wire form of a failure. Pure.
pub fn problem(error: &ConfigError) -> SalesCpqProblem {
    let blank = SalesCpqProblem {
        code: String::new(),
        group_id: None,
        option_id: None,
        other_option_id: None,
        rule_id: None,
        min: None,
        max: None,
        chosen: None,
        message: None,
    };
    match error {
        ConfigError::NotAnOption(option) => SalesCpqProblem {
            code: "not_an_option".into(),
            option_id: Some(*option),
            ..blank
        },
        ConfigError::TooFew { group, min, chosen } => SalesCpqProblem {
            code: "too_few".into(),
            group_id: Some(*group),
            min: Some(*min),
            chosen: Some(*chosen),
            ..blank
        },
        ConfigError::TooMany { group, max, chosen } => SalesCpqProblem {
            code: "too_many".into(),
            group_id: Some(*group),
            max: Some(*max),
            chosen: Some(*chosen),
            ..blank
        },
        ConfigError::MissingRequired { option, required } => SalesCpqProblem {
            code: "missing_required".into(),
            option_id: Some(*option),
            other_option_id: Some(*required),
            ..blank
        },
        ConfigError::Excluded { a, b } => SalesCpqProblem {
            code: "excluded".into(),
            option_id: Some(*a),
            other_option_id: Some(*b),
            ..blank
        },
        ConfigError::RuleFailed { rule, message } => SalesCpqProblem {
            code: "rule_failed".into(),
            rule_id: Some(*rule),
            message: Some(message.clone()),
            ..blank
        },
    }
}

/// Validates a bundle configuration.
///
/// Checks the chosen options against the bundle's option groups (minimum
/// and maximum) and rules (requires, excludes, expressions), and lists
/// every problem. Writes nothing.
#[utoipa::path(
    post,
    path = "/api/v1/sales/cpq/validate",
    tag = "sales",
    request_body = SalesCpqValidateBody,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "validates a configuration; writes nothing",
    )))),
    responses(
        (status = 200, description = "Whether the configuration is valid, and why not", body = SalesCpqValidation),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not read products", body = ErrorResponse),
        (status = 404, description = "No such bundle product, or configuration is not installed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn post_sales_cpq_validate(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(body): Json<SalesCpqValidateBody>,
) -> Result<Json<SalesCpqValidation>, AppError> {
    ctx.require("product", "read")?;
    if state.entities.load().get("product_option_group").is_none() {
        return Err(AppError::NotFound);
    }
    attome_records::entity_crud::read_record(&state, &ctx, "product", body.bundle_product_id)
        .await?;
    let model = load_model(&state.base.db, body.bundle_product_id).await?;
    let problems = match validate_configuration(&model, &body.chosen) {
        Ok(()) => Vec::new(),
        Err(errors) => errors.iter().map(problem).collect(),
    };
    Ok(Json(SalesCpqValidation {
        valid: problems.is_empty(),
        problems,
    }))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(post_sales_cpq_validate))]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod cpq_rules {
    use super::*;

    fn u(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn model() -> BundleModel {
        BundleModel {
            bundle: u(1),
            groups: vec![
                OptionGroup {
                    id: u(10),
                    name: "Laptop".into(),
                    min: 1,
                    max: Some(1),
                    options: vec![u(100), u(101)],
                },
                OptionGroup {
                    id: u(11),
                    name: "Accessories".into(),
                    min: 0,
                    max: Some(2),
                    options: vec![u(200), u(201), u(202)],
                },
            ],
            rules: vec![
                OptionRule::Requires {
                    option: u(202),
                    required: u(101),
                },
                OptionRule::Excludes {
                    a: u(200),
                    b: u(201),
                },
            ],
            keys: vec![
                (u(100), option_key(u(100), Some("LT-14"))),
                (u(101), option_key(u(101), Some("LT-16 Pro"))),
                (u(200), option_key(u(200), Some("BAG"))),
                (u(201), option_key(u(201), Some("SLEEVE"))),
                (u(202), option_key(u(202), Some("DOCK"))),
            ],
        }
    }

    #[test]
    fn a_valid_configuration_passes() {
        assert_eq!(validate_configuration(&model(), &[u(101), u(202)]), Ok(()));
    }

    #[test]
    fn group_minimum_and_maximum_are_enforced() {
        let errs = validate_configuration(&model(), &[u(200)]).unwrap_err();
        assert!(errs.contains(&ConfigError::TooFew {
            group: u(10),
            min: 1,
            chosen: 0
        }));
        let errs = validate_configuration(&model(), &[u(100), u(101)]).unwrap_err();
        assert!(errs.contains(&ConfigError::TooMany {
            group: u(10),
            max: 1,
            chosen: 2
        }));
    }

    #[test]
    fn requires_and_excludes_are_explained() {
        let errs = validate_configuration(&model(), &[u(100), u(202), u(200), u(201)]).unwrap_err();
        assert!(errs.contains(&ConfigError::MissingRequired {
            option: u(202),
            required: u(101)
        }));
        assert!(errs.contains(&ConfigError::Excluded {
            a: u(200),
            b: u(201)
        }));
        assert!(errs.contains(&ConfigError::TooMany {
            group: u(11),
            max: 2,
            chosen: 3
        }));
    }

    #[test]
    fn unknown_options_are_rejected() {
        let errs = validate_configuration(&model(), &[u(100), u(999)]).unwrap_err();
        assert_eq!(errs, vec![ConfigError::NotAnOption(u(999))]);
    }

    #[test]
    fn option_keys_come_from_the_sku() {
        assert_eq!(option_key(u(1), Some("LT-16 Pro")), "opt_lt_16_pro");
        assert_eq!(
            option_key(u(1), Some("  ")),
            format!("opt_{}", &u(1).simple().to_string()[..8])
        );
    }

    #[test]
    fn expression_rules_hold_or_explain() {
        let mut m = model();
        m.rules.push(OptionRule::Expression {
            id: u(7),
            expression: "not opt_dock or opt_lt_16_pro".into(),
            message: "The dock fits only the 16-inch laptop.".into(),
        });
        assert_eq!(validate_configuration(&m, &[u(101), u(202)]), Ok(()));
        let errs = validate_configuration(&m, &[u(100), u(202)]).unwrap_err();
        assert!(errs.contains(&ConfigError::RuleFailed {
            rule: u(7),
            message: "The dock fits only the 16-inch laptop.".into()
        }));
    }

    #[test]
    fn a_broken_expression_fails_closed() {
        let mut m = model();
        m.rules.push(OptionRule::Expression {
            id: u(8),
            expression: "opt_unknown_part".into(),
            message: "broken".into(),
        });
        let errs = validate_configuration(&m, &[u(101)]).unwrap_err();
        assert_eq!(
            errs,
            vec![ConfigError::RuleFailed {
                rule: u(8),
                message: "broken".into()
            }]
        );
    }
}
