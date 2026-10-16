//! CPQ configuration rules (roadmap F1-T1): a bundle product has option
//! groups, each with a minimum and maximum number of choices, and rules
//! between options (one requires another, two exclude each other). The
//! server validates a configuration and explains every failure, so the
//! quote screen and an agent drafting a quote get the same answer.

use std::collections::BTreeSet;
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

/// A rule between two options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptionRule {
    /// Choosing `option` needs `required` chosen too.
    Requires { option: Uuid, required: Uuid },
    /// `a` and `b` cannot both be chosen.
    Excludes { a: Uuid, b: Uuid },
}

/// A bundle's configuration model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleModel {
    pub bundle: Uuid,
    pub groups: Vec<OptionGroup>,
    pub rules: Vec<OptionRule>,
}

/// One reason a configuration is not valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    NotAnOption(Uuid),
    TooFew { group: Uuid, min: u32, chosen: u32 },
    TooMany { group: Uuid, max: u32, chosen: u32 },
    MissingRequired { option: Uuid, required: Uuid },
    Excluded { a: Uuid, b: Uuid },
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
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

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
}
