//! Stamps the build with its UTC time, `vYYYY.MM.DD.HHMMSS`, as `SIB_BUILD_VERSION`.
//! The standard library gives seconds since the Unix epoch; the calendar date is
//! worked out here, so the build needs no date crate.

use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let version = version(seconds);
    println!("cargo:rustc-env=SIB_BUILD_VERSION={version}");
}

fn version(unix_seconds: u64) -> String {
    let (year, month, day) = civil_from_days(unix_seconds / 86_400);
    let second_of_day = unix_seconds % 86_400;
    format!(
        "v{year:04}.{month:02}.{day:02}.{:02}{:02}{:02}",
        second_of_day / 3_600,
        second_of_day / 60 % 60,
        second_of_day % 60
    )
}

/// The proleptic Gregorian date of a day counted from 1970-01-01, by eras of
/// 400 years (146,097 days) that start on 1 March, so the leap day comes last.
fn civil_from_days(days_since_epoch: u64) -> (u64, u64, u64) {
    // Days from 0000-03-01 to 1970-01-01.
    let days = days_since_epoch + 719_468;
    let era = days / 146_097;
    let day_of_era = days % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    // Months counted from March: 0 is March, 11 is February.
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    (year, month, day)
}
