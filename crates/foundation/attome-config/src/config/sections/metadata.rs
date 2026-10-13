//! `metadata` section — Solution 7 Phase 1 (D-785,
//! `document/general/SOLUTION-7-PHASE-1-DESIGN.md` §4.7): how this deployment
//! records metadata admin writes as changesets.
//!
//! Plain data plus a shape check, as every section here. The recorder that
//! reads it is `xrm_foundation::changeset`; this crate knows no xrm type
//! (BCF-14), so the layer and mode enums live here and xrm-foundation
//! re-exports them.

use serde::Deserialize;

use crate::keyring::KeyRing;

/// `metadata` — additive, every field defaulted, so a config file without it
/// keeps today's behaviour: an unset mode is `auto` (see
/// [`ChangesetsSection::mode`]).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct MetadataSection {
    #[serde(default)]
    pub changesets: ChangesetsSection,
    /// Solution 7 Phase 2 (D-788 rule 9): the key-encryption-key ring of the
    /// 30-day recovery archive (`xrm_core_recovery_archive`), its own trust
    /// domain (D-069). Empty (the default) means "not configured": every
    /// operation that would archive a value (a field delete with values, a
    /// type change that nulls values) is refused with `archive_key_missing`
    /// (fail closed). When set, every entry must be 64 hex chars (a boot
    /// error otherwise). `KeyRing`'s `Debug` redacts the values.
    #[serde(default)]
    pub recovery_archive_key_encryption_key: KeyRing,
    /// Solution 7 Phase 2 (design §10.5): the post-apply release-report
    /// notification.
    #[serde(default)]
    pub release_report: ReleaseReportSection,
}

/// Most role names `metadata.release_report.notify_roles` accepts.
pub const MAX_NOTIFY_ROLES: usize = 20;

/// Longest role name accepted (the role table's name column is text; this
/// bounds a config typo, not the schema).
pub const MAX_ROLE_NAME_CHARS: usize = 200;

/// `metadata.release_report`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ReleaseReportSection {
    /// Who the post-apply notification goes to. Unset (the default) keeps
    /// today's recipients: the active holders of the admin privilege. Set,
    /// the notification goes to the active holders of these roles (by role
    /// `name`) instead; the recipient cap is unchanged. When none of the
    /// named roles has an active holder the notification falls back to the
    /// admin holders (logged at `warn`), so a stale name never silences it.
    /// A set list must be non-empty, without blanks or duplicates, at most
    /// [`MAX_NOTIFY_ROLES`] names (a boot error otherwise).
    #[serde(default)]
    pub notify_roles: Option<Vec<String>>,
}

impl ReleaseReportSection {
    /// Shape check run by `AppConfig::validate` in every profile. Returns the
    /// offending field and the reason.
    pub fn check(&self) -> Result<(), (String, String)> {
        let Some(roles) = &self.notify_roles else {
            return Ok(());
        };
        let field = || "metadata.release_report.notify_roles".to_string();
        if roles.is_empty() {
            return Err((
                field(),
                "must name at least one role when set; leave it unset (null) to notify \
                 the administrators"
                    .into(),
            ));
        }
        if roles.len() > MAX_NOTIFY_ROLES {
            return Err((
                field(),
                format!("names {} roles; at most {MAX_NOTIFY_ROLES}", roles.len()),
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for role in roles {
            if role.trim().is_empty() || role.trim() != role {
                return Err((
                    field(),
                    format!("{role:?} is blank or has surrounding whitespace"),
                ));
            }
            if role.chars().count() > MAX_ROLE_NAME_CHARS {
                return Err((
                    field(),
                    format!("a role name is longer than {MAX_ROLE_NAME_CHARS} characters"),
                ));
            }
            if !seen.insert(role.as_str()) {
                return Err((field(), format!("{role:?} is listed twice")));
            }
        }
        Ok(())
    }
}

/// `metadata.changesets`.
#[derive(Debug, Clone, Deserialize)]
pub struct ChangesetsSection {
    /// `required`: a metadata admin write with no open changeset is refused
    /// (409 `changeset_required`). `auto`: each request's writes become one
    /// closed automatic changeset. Unset means `auto` on every profile, so a
    /// config written before changesets existed (the production templates,
    /// every hand-written test config) keeps working unchanged; a
    /// development deployment opts into `required` explicitly, as
    /// `config.example.json` does. Read it through [`Self::effective_mode`],
    /// never this field directly.
    #[serde(default)]
    pub mode: Option<ChangesetMode>,
    /// The layer of automatic changesets. Phase 1 accepts only `project`;
    /// Phase 3 adds `customer` together with its authoring rules.
    #[serde(default = "default_auto_layer")]
    pub auto_layer: ChangesetLayer,
}

impl Default for ChangesetsSection {
    fn default() -> Self {
        Self {
            mode: None,
            auto_layer: default_auto_layer(),
        }
    }
}

fn default_auto_layer() -> ChangesetLayer {
    ChangesetLayer::Project
}

impl ChangesetsSection {
    /// The mode in force: the configured one, else `auto` on every profile.
    /// `required` (the development authoring mode) is always set explicitly
    /// in config; the unset default is `auto` so that configs that predate
    /// changesets, above all the hand-written test configs, keep passing
    /// once the admin routes record. `deployment_profile` is kept so a
    /// profile-specific default can return without changing callers.
    pub fn effective_mode(&self, deployment_profile: &str) -> ChangesetMode {
        let _ = deployment_profile;
        self.mode.unwrap_or(ChangesetMode::Auto)
    }

    /// Shape check run by `AppConfig::validate` in every profile. Returns the
    /// offending field and the reason.
    pub fn check(&self) -> Result<(), (String, String)> {
        if self.auto_layer != ChangesetLayer::Project {
            return Err((
                "metadata.changesets.auto_layer".into(),
                format!(
                    "must be \"project\" in this release, got {:?}: automatic changesets \
                     in the customer layer need the Phase 3 authoring rules, and platform or \
                     product changes are always authored (D-785)",
                    self.auto_layer.as_str()
                ),
            ));
        }
        Ok(())
    }
}

/// `metadata.changesets.mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangesetMode {
    Required,
    Auto,
}

impl ChangesetMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Auto => "auto",
        }
    }
}

/// The four owner layers (D-785 rule 2), lowest first. The wire and column
/// form is [`Self::as_str`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangesetLayer {
    Platform,
    Product,
    Project,
    Customer,
}

impl ChangesetLayer {
    pub const ALL: [Self; 4] = [Self::Platform, Self::Product, Self::Project, Self::Customer];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Platform => "platform",
            Self::Product => "product",
            Self::Project => "project",
            Self::Customer => "customer",
        }
    }

    /// Parses the column form; `None` for anything else.
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|layer| layer.as_str() == value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> MetadataSection {
        serde_json::from_str(json).expect("metadata section parses")
    }

    #[test]
    fn an_absent_section_is_auto_on_every_profile() {
        let section = parse("{}");
        let c = &section.changesets;
        assert_eq!(c.mode, None);
        for profile in ["development", "production", "test", ""] {
            assert_eq!(c.effective_mode(profile), ChangesetMode::Auto, "{profile}");
        }
        assert_eq!(c.auto_layer, ChangesetLayer::Project);
        assert!(c.check().is_ok());
    }

    #[test]
    fn a_configured_mode_wins_over_the_profile() {
        let section = parse(r#"{"changesets":{"mode":"auto"}}"#);
        assert_eq!(
            section.changesets.effective_mode("development"),
            ChangesetMode::Auto
        );
        let section = parse(r#"{"changesets":{"mode":"required"}}"#);
        for profile in ["development", "production"] {
            assert_eq!(
                section.changesets.effective_mode(profile),
                ChangesetMode::Required
            );
        }
        let section = parse(r#"{"changesets":{"mode":null}}"#);
        assert_eq!(
            section.changesets.effective_mode("development"),
            ChangesetMode::Auto
        );
    }

    #[test]
    fn unknown_values_fail_to_parse() {
        for bad in [
            r#"{"changesets":{"mode":"sometimes"}}"#,
            r#"{"changesets":{"auto_layer":"tenant"}}"#,
        ] {
            assert!(
                serde_json::from_str::<MetadataSection>(bad).is_err(),
                "{bad} must be refused"
            );
        }
    }

    #[test]
    fn only_the_project_layer_is_an_automatic_layer_in_phase_1() {
        for (layer, ok) in [
            ("platform", false),
            ("product", false),
            ("project", true),
            ("customer", false),
        ] {
            let section = parse(&format!(r#"{{"changesets":{{"auto_layer":"{layer}"}}}}"#));
            let result = section.changesets.check();
            assert_eq!(result.is_ok(), ok, "{layer}");
            if let Err((field, _)) = result {
                assert_eq!(field, "metadata.changesets.auto_layer");
            }
        }
    }

    #[test]
    fn notify_roles_default_to_unset_and_a_set_list_is_shape_checked() {
        let section = parse("{}");
        assert_eq!(section.release_report.notify_roles, None);
        assert!(section.release_report.check().is_ok());
        let section = parse(r#"{"release_report":{"notify_roles":null}}"#);
        assert!(section.release_report.check().is_ok());
        let section = parse(
            r#"{"release_report":{"notify_roles":["Release Manager","System Administrator"]}}"#,
        );
        assert!(section.release_report.check().is_ok());
        assert_eq!(
            section.release_report.notify_roles.as_deref(),
            Some(
                &[
                    "Release Manager".to_string(),
                    "System Administrator".to_string()
                ][..]
            )
        );
        let too_many: Vec<String> = (0..=MAX_NOTIFY_ROLES).map(|i| format!("r{i}")).collect();
        let long = "x".repeat(MAX_ROLE_NAME_CHARS + 1);
        for bad in [
            Vec::new(),
            vec![String::new()],
            vec![" Admin".to_string()],
            vec!["Admin".to_string(), "Admin".to_string()],
            vec![long],
            too_many,
        ] {
            let section = ReleaseReportSection {
                notify_roles: Some(bad.clone()),
            };
            let result = section.check();
            assert!(result.is_err(), "{bad:?} must be refused");
            if let Err((field, _)) = result {
                assert_eq!(field, "metadata.release_report.notify_roles");
            }
        }
    }

    #[test]
    fn layers_round_trip_through_their_column_form() {
        for layer in ChangesetLayer::ALL {
            assert_eq!(ChangesetLayer::parse(layer.as_str()), Some(layer));
        }
        assert_eq!(ChangesetLayer::parse("Project"), None);
        assert!(ChangesetLayer::Platform < ChangesetLayer::Customer);
    }
}
