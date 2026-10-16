//! `attome-modules`: which built-in modules a deployment has switched on.
//!
//! Every module is on unless the deployment's module configuration turns it
//! off; there are no seats, expiry dates or signed licences (the platform is
//! AGPL, V2-D473). The core module can never be turned off. A module that is
//! off is hidden: its routes answer as if they did not exist, its operations
//! are absent from the agent schema, and its screens leave the menu.
//!
//! [`ModuleSet`] is a 256-bit set, so a check is one array index and one AND.

/// This crate's advisory-lock namespace in the workspace registry
/// (`crates/apps/attome/tests/advisory_lock_namespaces.rs`). Reserved: no
/// lock uses it today, and an id is never reused or renumbered.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 27;

/// The bits of a [`ModuleSet`]: 256 modules, 32 bytes.
pub type ModuleBits = [u64; 4];

/// A module's position in the set. `PartialEq`/`Eq`/`Hash` compare identity
/// ("is this the same module"), never whether it is on: that is
/// [`ModuleSet::has`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ModuleId {
    pub word: usize,
    pub mask: u64,
}

impl ModuleId {
    /// Fails at compile time (every id is a `const`) when `id >= 256`.
    pub const fn new(id: usize) -> Self {
        assert!(id < 256, "module id must be < 256");
        Self {
            word: id / 64,
            mask: 1u64 << (id % 64),
        }
    }
}

/// The modules a deployment has on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModuleSet {
    bits: ModuleBits,
}

impl ModuleSet {
    /// Every module on: what a deployment runs with until its module
    /// configuration says otherwise.
    pub const fn all() -> Self {
        Self {
            bits: [u64::MAX; 4],
        }
    }

    /// Only the core module: the state before the configuration has been
    /// read, and a convenient fixture for tests.
    pub const fn core_only() -> Self {
        let mut bits = [0u64; 4];
        bits[MODULE_CORE.word] = MODULE_CORE.mask;
        Self { bits }
    }

    /// Exactly these modules, plus core, which is always on.
    pub fn from_bits(bits: ModuleBits) -> Self {
        let mut bits = bits;
        bits[MODULE_CORE.word] |= MODULE_CORE.mask;
        Self { bits }
    }

    pub const fn bits(&self) -> ModuleBits {
        self.bits
    }

    #[inline(always)]
    pub const fn has(&self, module: ModuleId) -> bool {
        self.bits[module.word] & module.mask != 0
    }

    #[inline(always)]
    pub fn require(&self, module: ModuleId) -> Result<(), ModuleError> {
        if self.has(module) {
            Ok(())
        } else {
            Err(ModuleError::ModuleOff)
        }
    }

    /// This set narrowed by the deployment's module configuration: `None` (no
    /// configuration) leaves it unchanged; `enabled = false` keeps only core;
    /// otherwise the set is intersected with `configured`. Configuration only
    /// ever removes modules, and core always survives.
    pub fn narrowed_by(&self, configuration: Option<(bool, ModuleBits)>) -> Self {
        let Some((enabled, configured)) = configuration else {
            return *self;
        };
        let mut allowed = if enabled { configured } else { [0u64; 4] };
        allowed[MODULE_CORE.word] |= MODULE_CORE.mask;
        let mut bits = self.bits;
        for (word, allow) in bits.iter_mut().zip(allowed) {
            *word &= allow;
        }
        Self { bits }
    }

    /// The names of the modules in this set, in [`MODULE_MAP`] order.
    pub fn names(&self) -> impl Iterator<Item = &'static str> + use<'_> {
        MODULE_MAP
            .iter()
            .filter(|(_, id)| self.has(*id))
            .map(|(name, _)| *name)
    }
}

impl Default for ModuleSet {
    fn default() -> Self {
        Self::all()
    }
}

/// A call into a module that is off. Surfaces as "not found", never as
/// "forbidden": a switched-off module does not exist for the caller.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ModuleError {
    #[error("module is not enabled")]
    ModuleOff,
}

// Module ids. Never reuse or renumber one: stored module configurations name
// them by bit. Retired ids: 1, 2, 5 and 18 (v1 modules that never gated
// anything), 20 (`license`, gone with licences) and 30 (`trd`, now its own
// product).
pub const MODULE_CORE: ModuleId = ModuleId::new(0);
pub const MODULE_WORKFLOW: ModuleId = ModuleId::new(3);
pub const MODULE_STATE: ModuleId = ModuleId::new(4);
pub const MODULE_AUDIT: ModuleId = ModuleId::new(6);
pub const MODULE_NOTIFICATION: ModuleId = ModuleId::new(7);
pub const MODULE_SEARCH: ModuleId = ModuleId::new(8);
pub const MODULE_REPORT: ModuleId = ModuleId::new(9);
pub const MODULE_DOCUMENT: ModuleId = ModuleId::new(10);
pub const MODULE_AI: ModuleId = ModuleId::new(11);
pub const MODULE_INTEGRATION: ModuleId = ModuleId::new(12);
pub const MODULE_LOCALIZATION: ModuleId = ModuleId::new(13);
pub const MODULE_VIEW: ModuleId = ModuleId::new(14);
pub const MODULE_CONFIG: ModuleId = ModuleId::new(15);
pub const MODULE_BOT: ModuleId = ModuleId::new(16);
pub const MODULE_AUTOMATION: ModuleId = ModuleId::new(17);
pub const MODULE_S2S: ModuleId = ModuleId::new(19);
pub const MODULE_CONTENT: ModuleId = ModuleId::new(21);
pub const MODULE_PROJECT: ModuleId = ModuleId::new(22);
pub const MODULE_SERVICE: ModuleId = ModuleId::new(23);
pub const MODULE_DASHBOARD: ModuleId = ModuleId::new(24);
pub const MODULE_GRC: ModuleId = ModuleId::new(25);
pub const MODULE_PROCESS: ModuleId = ModuleId::new(26);
pub const MODULE_DOCGEN: ModuleId = ModuleId::new(27);
pub const MODULE_PREDICT: ModuleId = ModuleId::new(28);
pub const MODULE_OMNICHANNEL: ModuleId = ModuleId::new(29);
pub const MODULE_PORTAL: ModuleId = ModuleId::new(31);
/// Sales: the engines behind the sales pack (D6, D21-D25).
pub const MODULE_SALES: ModuleId = ModuleId::new(32);
/// Call intelligence: transcripts, talk-time and topic analysis of sales calls (D22).
pub const MODULE_CALLINTEL: ModuleId = ModuleId::new(33);
/// Marketing: campaigns, email marketing, segments, journeys, forms and pages (E1-E31).
pub const MODULE_MARKETING: ModuleId = ModuleId::new(34);
/// Billing: invoicing, tax determination, payments and subscriptions (F3-F5).
pub const MODULE_BILLING: ModuleId = ModuleId::new(35);
/// Sales commissions and incentives (F10, V2-D409).
pub const MODULE_COMMISSION: ModuleId = ModuleId::new(36);
/// Partner relationship management (F9, V2-D400).
pub const MODULE_PARTNER: ModuleId = ModuleId::new(37);
/// Fulfilment: fulfilment orders, shipments and delivery (F6).
pub const MODULE_FULFILMENT: ModuleId = ModuleId::new(38);
/// G17 workforce management: planning groups, shifts, schedules, adherence.
pub const MODULE_WORKFORCE: ModuleId = ModuleId::new(39);
/// Contract lifecycle management engine (W1, V2-D298, V2-D313).
pub const MODULE_CONTRACT: ModuleId = ModuleId::new(40);
/// Offline: records on the device, sync and conflict resolution for the mobile app (B18).
pub const MODULE_OFFLINE: ModuleId = ModuleId::new(41);

/// Every module by its configuration name.
pub const MODULE_MAP: &[(&str, ModuleId)] = &[
    ("core", MODULE_CORE),
    ("workflow", MODULE_WORKFLOW),
    ("state", MODULE_STATE),
    ("audit", MODULE_AUDIT),
    ("notification", MODULE_NOTIFICATION),
    ("search", MODULE_SEARCH),
    ("report", MODULE_REPORT),
    ("document", MODULE_DOCUMENT),
    ("ai", MODULE_AI),
    ("integration", MODULE_INTEGRATION),
    ("localization", MODULE_LOCALIZATION),
    ("view", MODULE_VIEW),
    ("config", MODULE_CONFIG),
    ("bot", MODULE_BOT),
    ("automation", MODULE_AUTOMATION),
    ("s2s", MODULE_S2S),
    ("content", MODULE_CONTENT),
    ("project", MODULE_PROJECT),
    ("service", MODULE_SERVICE),
    ("dashboard", MODULE_DASHBOARD),
    ("grc", MODULE_GRC),
    ("process", MODULE_PROCESS),
    ("docgen", MODULE_DOCGEN),
    ("predict", MODULE_PREDICT),
    ("omnichannel", MODULE_OMNICHANNEL),
    ("portal", MODULE_PORTAL),
    ("sales", MODULE_SALES),
    ("callintel", MODULE_CALLINTEL),
    ("marketing", MODULE_MARKETING),
    ("billing", MODULE_BILLING),
    ("commission", MODULE_COMMISSION),
    ("partner", MODULE_PARTNER),
    ("fulfilment", MODULE_FULFILMENT),
    ("workforce", MODULE_WORKFORCE),
    ("contract", MODULE_CONTRACT),
    ("offline", MODULE_OFFLINE),
];

/// The module named `name` in [`MODULE_MAP`].
pub fn module_by_name(name: &str) -> Option<ModuleId> {
    MODULE_MAP
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, id)| *id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn ids_and_names_are_unique() {
        let mut ids = HashSet::new();
        let mut names = HashSet::new();
        for (name, id) in MODULE_MAP {
            assert!(ids.insert(*id), "module '{name}' reuses an id");
            assert!(names.insert(*name), "duplicate module name '{name}'");
        }
    }

    #[test]
    fn all_has_every_module_and_core_only_has_core() {
        for (_, id) in MODULE_MAP {
            assert!(ModuleSet::all().has(*id));
        }
        let core = ModuleSet::core_only();
        assert!(core.has(MODULE_CORE));
        assert!(!core.has(MODULE_AI));
        assert_eq!(core.require(MODULE_AI), Err(ModuleError::ModuleOff));
    }

    #[test]
    fn narrowing_never_drops_core_and_never_adds_a_module() {
        let all = ModuleSet::all();
        assert_eq!(all.narrowed_by(None), all);

        let off = all.narrowed_by(Some((false, [u64::MAX; 4])));
        assert!(off.has(MODULE_CORE));
        assert!(!off.has(MODULE_WORKFLOW));

        let mut only_ai = [0u64; 4];
        only_ai[MODULE_AI.word] |= MODULE_AI.mask;
        let narrowed = all.narrowed_by(Some((true, only_ai)));
        assert!(narrowed.has(MODULE_AI) && narrowed.has(MODULE_CORE));
        assert!(!narrowed.has(MODULE_SEARCH));

        let widened = ModuleSet::core_only().narrowed_by(Some((true, [u64::MAX; 4])));
        assert_eq!(widened, ModuleSet::core_only());
    }

    #[test]
    fn from_bits_always_includes_core_and_names_follow_the_map() {
        let set = ModuleSet::from_bits([0u64; 4]);
        assert_eq!(set.names().collect::<Vec<_>>(), vec!["core"]);
        assert_eq!(module_by_name("workflow"), Some(MODULE_WORKFLOW));
        assert_eq!(module_by_name("license"), None);
    }
}
