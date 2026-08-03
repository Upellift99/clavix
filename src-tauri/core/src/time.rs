//! Minimal UTC timestamp formatting.
//!
//! Password history entries carry a `lastUsedDate`, and it is the client
//! that stamps it — the server stores the history blob verbatim. That is
//! the only place we need to *produce* a date (every other date in the
//! app comes from the server as a string), which does not justify a date
//! crate in a codebase that handles vault keys: fewer dependencies in the
//! engine is the whole point of `clavix-core`.

use std::time::{SystemTime, UNIX_EPOCH};

/// Civil date from a day count since 1970-01-01, by Howard Hinnant's
/// `civil_from_days`. Proleptic Gregorian, valid far beyond any date
/// this app will see.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11], March-based
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `2026-08-03T14:22:31.000Z` — the shape Bitwarden clients write. The
/// millisecond field is always zero: second resolution is all a "when was
/// this password replaced" stamp needs.
pub fn iso8601_utc(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let rem = unix_secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.000Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60,
    )
}

/// Now, as an ISO-8601 UTC string. Falls back to the epoch if the system
/// clock predates 1970 — a stamp nobody can read beats a panic.
pub fn now_iso8601() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    iso8601_utc(secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_the_epoch() {
        assert_eq!(iso8601_utc(0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn formats_a_known_instant() {
        // 1 754 231 351 = 2025-08-03T14:29:11Z, checked against `date -u`.
        assert_eq!(iso8601_utc(1_754_231_351), "2025-08-03T14:29:11.000Z");
    }

    #[test]
    fn handles_a_leap_day() {
        // 2024-02-29T00:00:00Z
        assert_eq!(iso8601_utc(1_709_164_800), "2024-02-29T00:00:00.000Z");
    }

    #[test]
    fn rolls_over_at_midnight() {
        assert_eq!(iso8601_utc(86_399), "1970-01-01T23:59:59.000Z");
        assert_eq!(iso8601_utc(86_400), "1970-01-02T00:00:00.000Z");
    }

    #[test]
    fn now_is_well_formed_and_recent() {
        let now = now_iso8601();
        assert_eq!(now.len(), 24, "{now}");
        assert!(now.ends_with('Z'), "{now}");
        // The test suite will not be running before 2025 or after 2100.
        let year: i32 = now[..4].parse().expect("leading year");
        assert!((2025..2100).contains(&year), "{now}");
    }
}
