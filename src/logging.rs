//! Minimal timestamped logging for operational events.
//!
//! There is no external time crate (that would fight the all-arch / static-musl /
//! FROM-scratch build), so the UTC wall clock is formatted straight from
//! `SystemTime` with the standard civil-from-days algorithm. Runtime log lines go
//! through the `elog!` macro, which prefixes the timestamp; pre-run output (usage,
//! argument errors) stays on plain `eprintln!`.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current UTC time as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn now_utc() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    fmt_utc(secs)
}

/// Format Unix seconds as `YYYY-MM-DDTHH:MM:SSZ` (UTC).
fn fmt_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let tod = secs % 86_400;
    let (hh, mm, ss) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}-{mo:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 -> (year, month, day).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `eprintln!` with a leading UTC timestamp, for operational/runtime log lines.
#[macro_export]
macro_rules! elog {
    ($($arg:tt)*) => {
        eprintln!("{} {}", $crate::logging::now_utc(), format_args!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::fmt_utc;

    #[test]
    fn formats_known_instants() {
        assert_eq!(fmt_utc(0), "1970-01-01T00:00:00Z");
        // 1700000000 is 2023-11-14T22:13:20Z.
        assert_eq!(fmt_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        // A leap day: 1582934400 is 2020-02-29T00:00:00Z.
        assert_eq!(fmt_utc(1_582_934_400), "2020-02-29T00:00:00Z");
        // End-of-year rollover: 1609459199 is 2020-12-31T23:59:59Z.
        assert_eq!(fmt_utc(1_609_459_199), "2020-12-31T23:59:59Z");
    }
}
