//! Y4-T1: each engine's module manifest. An engine declares, beside its
//! model, the version it ships at, the platform versions it runs on and the
//! other modules it needs on; its module and its entities are the ones the
//! model already declares (`EngineModel::module_id`, `owned_entities`), so
//! they are not written twice. Boot refuses a deployment whose
//! switched-on module needs one that is off, and Module Management refuses to
//! make such a configuration.

use attome_modules::{ModuleSet, module_by_name};
use serde::Serialize;

/// The platform's own version, the one `platform` ranges are checked against.
pub const PLATFORM_VERSION: &str = env!("CARGO_PKG_VERSION");

/// What an engine declares (`EngineModel::manifest`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleManifest {
    /// The engine's version (its crate version).
    pub version: &'static str,
    /// The modules (names in `attome_modules::MODULE_MAP`) that must be on
    /// while this engine's module is on. The core module is always on and is
    /// never listed.
    pub depends_on: &'static [&'static str],
    /// The platform versions this engine runs on, as a semver requirement.
    pub platform: &'static str,
}

/// The platform range every built-in engine declares: the 0.x line it ships
/// in.
pub const BUILT_IN_PLATFORM: &str = ">=0.1.0, <1.0.0";

/// One registered engine's manifest, resolved: what the model declares plus
/// its module's name and its entities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EngineManifest {
    pub engine: &'static str,
    pub module: &'static str,
    pub version: &'static str,
    pub depends_on: &'static [&'static str],
    pub platform: &'static str,
    pub entities: &'static [&'static str],
}

impl EngineManifest {
    /// The manifest's own problems: an unknown dependency, a dependency on
    /// itself or on core, or a platform range that does not parse or does
    /// not admit [`PLATFORM_VERSION`].
    pub fn check(&self) -> Result<(), String> {
        for dep in self.depends_on {
            if module_by_name(dep).is_none() {
                return Err(format!(
                    "engine {} depends on unknown module {dep:?}",
                    self.engine
                ));
            }
            if *dep == self.module || *dep == "core" {
                return Err(format!(
                    "engine {} lists {dep:?} among its dependencies; a module never depends on itself or on core",
                    self.engine
                ));
            }
        }
        let range = semver::VersionReq::parse(self.platform).map_err(|e| {
            format!(
                "engine {}: platform range {:?} does not parse: {e}",
                self.engine, self.platform
            )
        })?;
        let platform = semver::Version::parse(PLATFORM_VERSION)
            .map_err(|e| format!("platform version {PLATFORM_VERSION:?}: {e}"))?;
        if !range.matches(&platform) {
            return Err(format!(
                "engine {} {} needs platform {}, this is {PLATFORM_VERSION}",
                self.engine, self.version, self.platform
            ));
        }
        Ok(())
    }
}

/// Refuses `modules` when a module that is on needs one that is off, naming
/// both, so boot can stop with it and Module Management can answer 422.
pub fn check_dependencies(manifests: &[EngineManifest], modules: &ModuleSet) -> Result<(), String> {
    for manifest in manifests {
        // An engine on a module outside `MODULE_MAP` (`custom`) is not checked.
        let Some(id) = module_by_name(manifest.module) else {
            continue;
        };
        if !modules.has(id) {
            continue;
        }
        for dep in manifest.depends_on {
            if module_by_name(dep).is_some_and(|dep_id| !modules.has(dep_id)) {
                return Err(format!(
                    "module {} is on but needs module {dep}, which is off (engine {})",
                    manifest.module, manifest.engine
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_modules::{MODULE_PROJECT, MODULE_SERVICE, ModuleId};

    fn without(set: ModuleSet, id: ModuleId) -> ModuleSet {
        let mut bits = set.bits();
        bits[id.word] &= !id.mask;
        ModuleSet::from_bits(bits)
    }

    fn service() -> EngineManifest {
        EngineManifest {
            engine: "attome-service",
            module: "service",
            version: "0.1.0",
            depends_on: &["project"],
            platform: BUILT_IN_PLATFORM,
            entities: &[],
        }
    }

    #[test]
    fn a_switched_on_module_needs_its_dependencies() {
        let manifests = [service()];
        assert!(check_dependencies(&manifests, &ModuleSet::all()).is_ok());
        let without_project = without(ModuleSet::all(), MODULE_PROJECT);
        let err = check_dependencies(&manifests, &without_project).unwrap_err();
        assert!(err.contains("service") && err.contains("project"), "{err}");
        // A module that is off needs nothing.
        let neither = without(without_project, MODULE_SERVICE);
        assert!(check_dependencies(&manifests, &neither).is_ok());
    }

    #[test]
    fn a_manifest_checks_its_own_fields() {
        assert!(service().check().is_ok());
        let unknown = EngineManifest {
            depends_on: &["nope"],
            ..service()
        };
        assert!(unknown.check().is_err());
        let itself = EngineManifest {
            depends_on: &["service"],
            ..service()
        };
        assert!(itself.check().is_err());
        let future = EngineManifest {
            platform: ">=9.0.0",
            ..service()
        };
        assert!(future.check().unwrap_err().contains("needs platform"));
        let garbage = EngineManifest {
            platform: "soon",
            ..service()
        };
        assert!(garbage.check().is_err());
    }
}
