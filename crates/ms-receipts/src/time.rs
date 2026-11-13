//! UTC time formatting and parsing for `ms log` and `ms stats`, without a date crate.

/// Milliseconds per day.
const DAY_MS: u64 = 86_400_000;

/// Days since 1970-01-01 → (year, month, day). Howard Hinnant's `civil_from_days`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// (year, month, day) → days since 1970-01-01.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = i64::from(if m > 2 { m - 3 } else { m + 9 });
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `2026-11-13T19:24:05Z`.
pub fn format_utc(unix_ms: u64) -> String {
    let secs = unix_ms / 1000;
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    let rem = secs % 86_400;
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// `2026-11-13`.
pub fn format_day(unix_ms: u64) -> String {
    let (y, m, d) = civil_from_days((unix_ms / DAY_MS) as i64);
    format!("{y:04}-{m:02}-{d:02}")
}

fn num(s: &str) -> Option<u32> {
    (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        .then(|| s.parse().ok())
        .flatten()
}

/// Parses a time for `--since` / `--until`, relative to `now_ms`:
/// `30m`, `2h`, `7d`, `45s` (that long ago), `YYYY-MM-DD` (UTC midnight) or
/// `YYYY-MM-DDTHH:MM:SSZ`.
pub fn parse_time(s: &str, now_ms: u64) -> Result<u64, String> {
    let bad = || {
        format!(
            "invalid time \"{}\". Use 30m, 2h, 7d, 2026-11-13 or 2026-11-13T09:30:00Z",
            s.escape_default()
        )
    };
    if let Some((n, unit)) = s.len().checked_sub(1).map(|i| s.split_at(i)) {
        let mult = match unit {
            "s" => Some(1_000u64),
            "m" => Some(60_000),
            "h" => Some(3_600_000),
            "d" => Some(DAY_MS),
            _ => None,
        };
        if let (Some(mult), Some(n)) = (mult, num(n)) {
            return Ok(now_ms.saturating_sub(u64::from(n).saturating_mul(mult)));
        }
    }
    let (date, clock) = match s.split_once('T') {
        Some((d, c)) => (d, Some(c.strip_suffix('Z').ok_or_else(bad)?)),
        None => (s, None),
    };
    let parts: Vec<&str> = date.split('-').collect();
    let [y, mo, d] = parts.as_slice() else {
        return Err(bad());
    };
    if y.len() != 4 || mo.len() != 2 || d.len() != 2 {
        return Err(bad());
    }
    let (y, mo, d) = (
        num(y).ok_or_else(bad)?,
        num(mo).ok_or_else(bad)?,
        num(d).ok_or_else(bad)?,
    );
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&mo) || d == 0 {
        return Err(bad());
    }
    let days = days_from_civil(i64::from(y), mo, d);
    // Reject 2026-02-30 and friends: the date must survive a round trip.
    if civil_from_days(days) != (i64::from(y), mo, d) {
        return Err(bad());
    }
    let mut ms = days as u64 * DAY_MS;
    if let Some(c) = clock {
        let hms: Vec<&str> = c.split(':').collect();
        let [h, mi, se] = hms.as_slice() else {
            return Err(bad());
        };
        if h.len() != 2 || mi.len() != 2 || se.len() != 2 {
            return Err(bad());
        }
        let (h, mi, se) = (
            num(h).ok_or_else(bad)?,
            num(mi).ok_or_else(bad)?,
            num(se).ok_or_else(bad)?,
        );
        if h > 23 || mi > 59 || se > 59 {
            return Err(bad());
        }
        ms += (u64::from(h) * 3600 + u64::from(mi) * 60 + u64::from(se)) * 1000;
    }
    Ok(ms)
}

/// Now, Unix milliseconds.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    // protects=UTC formatting and parsing agree, including leap days; fails_when=a date is off by
    // a day or an invalid date is accepted; no_claim=time zones other than UTC
    #[test]
    fn format_and_parse() {
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        let t = parse_time("2026-11-13T19:24:05Z", 0).unwrap();
        assert_eq!(format_utc(t + 999), "2026-11-13T19:24:05Z");
        assert_eq!(format_day(t), "2026-11-13");
        assert_eq!(
            format_utc(parse_time("2024-02-29", 0).unwrap()),
            "2024-02-29T00:00:00Z"
        );
        for bad in [
            "2026-02-30",
            "2025-02-29",
            "2026-13-01",
            "2026-1-01",
            "26-11-13",
            "2026-11-13T25:00:00Z",
            "2026-11-13T10:00:00",
            "yesterday",
            "",
            "-5m",
            "5x",
        ] {
            assert!(parse_time(bad, 0).is_err(), "{bad}");
        }
        assert_eq!(
            parse_time("2h", 10_000_000).unwrap(),
            10_000_000 - 7_200_000
        );
        assert_eq!(parse_time("7d", 1).unwrap(), 0);
        assert_eq!(parse_time("30m", 3_600_000).unwrap(), 1_800_000);
    }
}
