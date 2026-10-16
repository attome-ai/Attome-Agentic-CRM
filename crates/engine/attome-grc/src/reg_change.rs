//! Regulatory change (roadmap R12-T1), pure: a change to a regulation links
//! to the controls, requirements and policies it touches
//! (`grc_regulatory_change_link`), each link with its own impact. The
//! change's overall impact is the highest of its links', and the controls to
//! review are the distinct controls it links.

use std::collections::BTreeSet;

use uuid::Uuid;

/// The impact a change, or one of its links, has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Impact {
    None,
    Low,
    Medium,
    High,
}

impl Impact {
    /// The stored choice value, `None` for anything else.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// One `grc_regulatory_change_link` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeLink {
    pub control: Option<Uuid>,
    pub requirement: Option<Uuid>,
    pub policy: Option<Uuid>,
    /// `None` until someone assesses the link.
    pub impact: Option<Impact>,
}

/// What a regulatory change touches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeImpact {
    /// The highest assessed link impact; `None` while nothing is assessed.
    pub overall: Option<Impact>,
    /// Controls to review, each once, in id order.
    pub controls: Vec<Uuid>,
    /// Links that still need an impact.
    pub unassessed: usize,
}

/// Rolls a change's links up into its impact.
pub fn assess(links: &[ChangeLink]) -> ChangeImpact {
    let overall = links.iter().filter_map(|l| l.impact).max();
    let controls: BTreeSet<Uuid> = links.iter().filter_map(|l| l.control).collect();
    ChangeImpact {
        overall,
        controls: controls.into_iter().collect(),
        unassessed: links.iter().filter(|l| l.impact.is_none()).count(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(control: Option<u128>, impact: Option<Impact>) -> ChangeLink {
        ChangeLink {
            control: control.map(Uuid::from_u128),
            requirement: None,
            policy: None,
            impact,
        }
    }

    #[test]
    fn the_highest_link_impact_is_the_change_impact() {
        let r = assess(&[
            link(Some(2), Some(Impact::Low)),
            link(Some(1), Some(Impact::High)),
            link(Some(2), Some(Impact::Medium)),
            link(None, None),
        ]);
        assert_eq!(r.overall, Some(Impact::High));
        assert_eq!(r.controls, vec![Uuid::from_u128(1), Uuid::from_u128(2)]);
        assert_eq!(r.unassessed, 1);
    }

    #[test]
    fn nothing_assessed_has_no_overall_impact() {
        let r = assess(&[link(Some(1), None)]);
        assert_eq!(r.overall, None);
        assert_eq!(r.unassessed, 1);
        assert_eq!(Impact::parse("medium"), Some(Impact::Medium));
        assert_eq!(Impact::High.as_str(), "high");
        assert_eq!(Impact::parse("severe"), None);
    }
}
