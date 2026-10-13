//! `FeatureFlag` — the closed catalogue of code-declared feature flags (M95,
//! D-430).
//!
//! Mirrors `setting_descriptor.rs`'s `SettingDescriptor`/`SettingRegistry`
//! shape deliberately (itself mirroring `attome-ai`'s `ActionDescriptor`):
//! modules declare their flags in code at boot (a `Vec<FeatureFlag>` built by
//! `feature_flag_catalog::all()`), not by inventing a key at write time. The
//! registry is a `BTreeMap` behind a `LazyLock` — compile-time data, no
//! `AppState` field, no DB round trip to know which keys exist — and
//! `FeatureFlag` itself is sealed the same way `SettingDescriptor` is: `new()`
//! is `pub(crate)`, so only this crate can mint one and the closed set really
//! is closed. `attome-server::features_admin` rejects any key
//! `registry().get(key)` can't find (404), exactly like
//! `attome-server::settings_admin` already does for `SettingDescriptor`.
//!
//! This is the *shape* catalogue — which flags exist, which module gates
//! them, their code default, and their `requires` prerequisites. The
//! *stored policy value* for a flag (per-user/role overrides, rollout
//! percentage) lives in `setting` under the `feature.*` namespace
//! (`feature_flag_store.rs`), resolved against these descriptors — see that
//! module's doc for the storage shape and `setting_catalog.rs` for the
//! matching `SettingDescriptor` every flag here must have.
//!
//! # The invariant (D-430)
//!
//! A flag can only ever narrow what the deployment's active license already
//! allows for `module`, never widen it. `FeatureFlags::is_on`
//! (`feature_flag_store.rs`) enforces this by checking
//! `ModuleSet::has_module` — the exact same check
//! `ModelRegistry::mounted_routes` uses to decide whether to return
//! `AppError::FeatureHidden` — before it ever looks at the stored flag value.
//! An unlicensed or administratively-disabled module's flags can never
//! evaluate `true`, no matter what an admin sets the stored value to.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use attome_modules::ModuleId;

/// Zero-sized marker that makes [`FeatureFlag`] uninstantiable outside this
/// crate — same trick `SettingDescriptor`/`attome_ai::ActionDescriptor` use.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Sealed(());

/// One registered feature flag. Modules declare these in
/// `feature_flag_catalog.rs`'s `all()`; nothing else can construct one
/// (`_sealed` + `pub(crate) new`).
#[derive(Debug, Clone)]
pub struct FeatureFlag {
    /// `"{module}.{name}"` — validated by [`FeatureFlagRegistry::new`]
    /// (lowercase ascii, exactly the same shape `SettingDescriptor::key`
    /// requires). The corresponding stored-value setting lives at
    /// `"feature.{key}"` — see [`FeatureFlag::setting_key`].
    pub key: &'static str,
    /// The module whose license bit gates this flag (D-430's invariant).
    pub module: ModuleId,
    pub description: &'static str,
    /// Code default used only when no `setting` row exists for this
    /// flag's key yet (an admin has never touched it).
    pub default: bool,
    /// Other flag keys that must themselves evaluate on (deployment-scope)
    /// before this flag may be turned on deployment-wide. Enforced at write
    /// time by `attome-server::features_admin` via
    /// [`crate::feature_flag_store::validate_flag_dependencies`] — never at
    /// evaluation time, so a prerequisite disabled *after* a dependent flag
    /// was already enabled doesn't retroactively flip the dependent off from
    /// under an admin's feet; the write path is where the constraint is
    /// re-checked on every subsequent change.
    pub requires: &'static [&'static str],
    pub(crate) _sealed: Sealed,
}

impl FeatureFlag {
    pub(crate) fn new(
        key: &'static str,
        module: ModuleId,
        description: &'static str,
        default: bool,
        requires: &'static [&'static str],
    ) -> Self {
        Self {
            key,
            module,
            description,
            default,
            requires,
            _sealed: Sealed(()),
        }
    }

    /// The `setting` key this flag's stored policy value lives at
    /// (M02 `feature.*` namespace, M95/D-430).
    pub fn setting_key(&self) -> String {
        format!("feature.{}", self.key)
    }
}

/// The closed catalogue, built once at process start.
pub struct FeatureFlagRegistry {
    by_key: BTreeMap<&'static str, FeatureFlag>,
}

impl std::fmt::Debug for FeatureFlagRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FeatureFlagRegistry")
            .finish_non_exhaustive()
    }
}

impl FeatureFlagRegistry {
    pub fn new() -> Self {
        let mut by_key = BTreeMap::new();
        for flag in crate::feature_flag_catalog::all() {
            assert!(
                flag.key
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_')
                    && flag.key.matches('.').count() >= 1,
                "feature flag key {:?} must be lowercase ascii, snake_case, and namespaced as \
                 \"{{module}}.{{name}}\"",
                flag.key,
            );
            let key = flag.key;
            let previous = by_key.insert(key, flag);
            assert!(previous.is_none(), "duplicate feature flag key {key:?}");
        }

        // `requires` must name real, distinct flags — a dangling or
        // self-referential prerequisite is a registration bug, same
        // fail-at-boot posture as SettingRegistry's asserts.
        for (key, requires) in by_key.values().map(|f| (f.key, f.requires)) {
            for req in requires {
                assert!(req != &key, "feature flag {key:?} cannot require itself");
                assert!(
                    by_key.contains_key(req),
                    "feature flag {key:?} requires unknown flag {req:?}"
                );
            }
        }

        // Every flag must have a matching `SettingDescriptor` registered
        // under the `feature.*` namespace (`setting_catalog.rs`) — this is
        // what "extend the M02 settings store" means concretely: the flag
        // catalogue declares *shape*, the setting catalogue declares
        // *storage*, and the two must never drift apart.
        let settings = crate::setting_descriptor::registry();
        for flag in by_key.values() {
            let setting_key = flag.setting_key();
            assert!(
                settings.get(&setting_key).is_some(),
                "feature flag {:?} has no matching SettingDescriptor {:?} registered in \
                 setting_catalog.rs's feature_flag_settings()",
                flag.key,
                setting_key,
            );
        }

        Self { by_key }
    }

    pub fn get(&self, key: &str) -> Option<&FeatureFlag> {
        self.by_key.get(key)
    }

    pub fn iter(&self) -> impl Iterator<Item = &FeatureFlag> {
        self.by_key.values()
    }
}

impl Default for FeatureFlagRegistry {
    fn default() -> Self {
        Self::new()
    }
}

static REGISTRY: LazyLock<FeatureFlagRegistry> = LazyLock::new(FeatureFlagRegistry::new);

/// The process-wide closed catalogue. Cheap — a `LazyLock` deref.
pub fn registry() -> &'static FeatureFlagRegistry {
    &REGISTRY
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_builds_without_panicking() {
        let reg = FeatureFlagRegistry::new();
        assert!(
            reg.iter().count() >= 2,
            "expected at least the seeded catalogue flags"
        );
    }

    #[test]
    fn every_flag_has_a_matching_setting_descriptor() {
        let reg = registry();
        let settings = crate::setting_descriptor::registry();
        for flag in reg.iter() {
            assert!(
                settings.get(&flag.setting_key()).is_some(),
                "flag {:?} has no setting descriptor at {:?}",
                flag.key,
                flag.setting_key(),
            );
        }
    }
}
