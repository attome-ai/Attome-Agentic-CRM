//! D21 call lists and power dialer.

pub mod build;
pub mod claim;
pub mod hours;
pub mod outcome;
/// D21-T8: someone else's shared list needs `call_list.share`.
pub mod sharing;
/// D21-T7: a rep passes over a claimed member.
pub mod skip;
/// D21-T6: the dialer's telephone is J6.
pub mod telephony;
