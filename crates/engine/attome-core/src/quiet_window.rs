//! M12-T3: quiet windows, the hours heavy scheduled work waits out.
//!
//! The deployment setting `jobs.quiet_windows` lists windows in the
//! deployment's own time (`app.time_zone`), `[{"start": "08:00", "end":
//! "18:00"}]`; a window whose end is before its start runs past midnight.
//! While one is open, a schedule slot that would start heavy batch work
//! (a flow run over a view's records, a report delivery) is not claimed: it
//! stays due and starts once the window closes, as one run however many
//! slots passed. Light schedules and platform maintenance are not held.

use serde_json::Value;

use crate::EngineState;

/// The setting key.
pub const SETTING: &str = "jobs.quiet_windows";

/// Minutes after midnight of an `HH:MM` time.
pub fn minutes_of(hhmm: &str) -> Option<u16> {
    let (h, m) = hhmm.trim().split_once(':')?;
    let (h, m): (u16, u16) = (h.parse().ok()?, m.parse().ok()?);
    (h < 24 && m < 60).then_some(h * 60 + m)
}

/// The windows a setting value names, as (start, end) minutes; malformed
/// entries and empty windows are ignored.
pub fn windows_of(value: &Value) -> Vec<(u16, u16)> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|w| {
            let start = minutes_of(w.get("start")?.as_str()?)?;
            let end = minutes_of(w.get("end")?.as_str()?)?;
            (start != end).then_some((start, end))
        })
        .collect()
}

/// Whether `minute` (after midnight) falls in one of `windows`.
pub fn in_window(windows: &[(u16, u16)], minute: u16) -> bool {
    windows.iter().any(|&(start, end)| {
        if start < end {
            (start..end).contains(&minute)
        } else {
            minute >= start || minute < end
        }
    })
}

/// Whether a quiet window is open now, in the deployment's time.
pub fn quiet_now(state: &EngineState) -> bool {
    use chrono::Timelike;
    let Some(descriptor) = crate::setting_registry().get(SETTING) else {
        return false;
    };
    let windows = windows_of(&state.settings.load().resolve(descriptor, None, None).0);
    if windows.is_empty() {
        return false;
    }
    let now = crate::calendar::deployment_now(state.base.config.app.time_zone.as_deref());
    let minute = u16::try_from(now.hour() * 60 + now.minute()).unwrap_or(0);
    in_window(&windows, minute)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quiet_windows_cover_their_hours_and_wrap_past_midnight() {
        let windows = windows_of(&serde_json::json!([
            { "start": "08:00", "end": "18:00" },
            { "start": "23:00", "end": "01:30" },
            { "start": "bad", "end": "10:00" },
            { "start": "05:00", "end": "05:00" },
        ]));
        assert_eq!(windows, vec![(480, 1080), (1380, 90)]);
        assert!(in_window(&windows, 9 * 60));
        assert!(!in_window(&windows, 18 * 60), "the end is open");
        assert!(in_window(&windows, 23 * 60 + 30));
        assert!(in_window(&windows, 60));
        assert!(!in_window(&windows, 2 * 60));
        assert!(!in_window(&windows_of(&Value::Null), 600));
        assert_eq!(minutes_of("24:00"), None);
    }
}
