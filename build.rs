use chrono::{Datelike, Timelike, Utc};

fn main() {
    let now = Utc::now();
    let version = format!(
        "v{:04}.{:02}.{:02}.{:02}{:02}{:02}",
        now.year(),
        now.month(),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );
    println!("cargo:rustc-env=SIB_BUILD_VERSION={version}");
}
