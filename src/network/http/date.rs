use once_cell::sync::Lazy;
use std::cell::{Cell, UnsafeCell};
use std::sync::atomic::{AtomicU64, Ordering};

/// Current UNIX time in seconds, updated once per second.
static NOW_SEC: Lazy<AtomicU64> = Lazy::new(|| {
    AtomicU64::new(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
});

/// Start the background ticker that updates NOW_SEC.
/// MUST be called exactly once at program startup.
pub(crate) fn start_date_ticker() {
    may::go!(|| {
        let mut last_sec = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        NOW_SEC.store(last_sec, Ordering::Relaxed);

        loop {
            // Align to next second boundary.
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();

            let sleep_ms = 1_000u64.saturating_sub(now.subsec_millis() as u64);
            may::coroutine::sleep(std::time::Duration::from_millis(sleep_ms));

            // Common case: advance one second without another syscall.
            last_sec = last_sec.wrapping_add(1);

            // Periodic resync to avoid drift.
            if (last_sec & 0x3f) == 0 {
                last_sec = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
            }

            NOW_SEC.store(last_sec, Ordering::Relaxed);
        }
    });
}

struct TlDate {
    // last formatted second
    sec: Cell<u64>,

    // cached date parts (recomputed only when day changes)
    day: Cell<i64>, // days since epoch
    year: Cell<i32>,
    month: Cell<i32>, // 1..=12
    mday: Cell<i32>,  // 1..=31

    // 29-byte ASCII RFC7231 date buffer
    buf: UnsafeCell<[u8; 29]>,
}

impl TlDate {
    const fn new() -> Self {
        Self {
            sec: Cell::new(0),
            day: Cell::new(i64::MIN),
            year: Cell::new(1970),
            month: Cell::new(1),
            mday: Cell::new(1),
            buf: UnsafeCell::new(*b"Thu, 01 Jan 1970 00:00:00 GMT"),
        }
    }

    #[inline(always)]
    unsafe fn as_str(&self) -> &str {
        // Always ASCII, always 29 bytes.
        let bytes: &[u8; 29] = unsafe { &*self.buf.get() };
        unsafe { std::str::from_utf8_unchecked(bytes) }
    }

    #[inline(always)]
    unsafe fn write(&self, unix_sec: u64) {
        let days = (unix_sec / 86_400) as i64;

        // Cache civil date, recompute only when day changes.
        if self.day.get() != days {
            self.day.set(days);
            let (y, m, d) = civil_from_days(days);
            self.year.set(y);
            self.month.set(m);
            self.mday.set(d);
        }

        let year = self.year.get();
        let month = self.month.get();
        let day = self.mday.get();

        let (hh, mm, ss) = hms_from_sec(unix_sec);

        // 1970-01-01 was a Thursday. weekday: 0=Sun..6=Sat
        let weekday = ((days + 4).rem_euclid(7)) as usize;

        let buf = unsafe { &mut *self.buf.get() };

        // "Sun, 06 Nov 1994 08:49:37 GMT"
        buf[0..3].copy_from_slice(&WEEKDAY[weekday]);
        buf[3] = b',';
        buf[4] = b' ';

        write_2(buf, 5, day as u32);
        buf[7] = b' ';

        buf[8..11].copy_from_slice(&MONTH[(month - 1) as usize]);
        buf[11] = b' ';

        write_4(buf, 12, year as u32);
        buf[16] = b' ';

        write_2(buf, 17, hh as u32);
        buf[19] = b':';
        write_2(buf, 20, mm as u32);
        buf[22] = b':';
        write_2(buf, 23, ss as u32);

        buf[25] = b' ';
        buf[26] = b'G';
        buf[27] = b'M';
        buf[28] = b'T';
    }
}

thread_local! {
    static TL_DATE: TlDate = const { TlDate::new() };
}

const WEEKDAY: [[u8; 3]; 7] = [
    *b"Sun", *b"Mon", *b"Tue", *b"Wed", *b"Thu", *b"Fri", *b"Sat",
];

const MONTH: [[u8; 3]; 12] = [
    *b"Jan", *b"Feb", *b"Mar", *b"Apr", *b"May", *b"Jun", *b"Jul", *b"Aug", *b"Sep", *b"Oct",
    *b"Nov", *b"Dec",
];

#[inline(always)]
fn write_2(buf: &mut [u8; 29], idx: usize, v: u32) {
    let tens = (v / 10) as u8;
    let ones = (v % 10) as u8;
    buf[idx] = b'0' + tens;
    buf[idx + 1] = b'0' + ones;
}

#[inline(always)]
fn write_4(buf: &mut [u8; 29], idx: usize, v: u32) {
    buf[idx] = b'0' + ((v / 1000) % 10) as u8;
    buf[idx + 1] = b'0' + ((v / 100) % 10) as u8;
    buf[idx + 2] = b'0' + ((v / 10) % 10) as u8;
    buf[idx + 3] = b'0' + (v % 10) as u8;
}

#[inline(always)]
fn hms_from_sec(unix_sec: u64) -> (u8, u8, u8) {
    // Seconds of day
    let sod = (unix_sec % 86_400) as u32;

    // Slightly fewer ops than repeated div/mod chains.
    let mins = sod / 60;
    let ss = (sod - mins * 60) as u8;
    let hh = (mins / 60) as u8;
    let mm = (mins - (hh as u32) * 60) as u8;

    (hh, mm, ss)
}

/// Convert days since Unix epoch (1970-01-01) to (year, month, day) in UTC.
/// month is 1..=12
#[inline(always)]
fn civil_from_days(days_since_epoch: i64) -> (i32, i32, i32) {
    // Howard Hinnant's civil_from_days, adjusted for Unix epoch.
    // We work in days since 1970-01-01; algorithm expects days since 0000-03-01-ish,
    // so we shift by 719468 (days from 0000-03-01 to 1970-01-01).
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = mp + if mp < 10 { 3 } else { -9 }; // [1, 12]
    let year = (y + if m <= 2 { 1 } else { 0 }) as i32;

    (year, m as i32, d as i32)
}

#[inline]
pub fn current_date_str() -> &'static str {
    TL_DATE.with(|tl| {
        let now = NOW_SEC.load(Ordering::Relaxed);

        if tl.sec.get() != now {
            tl.sec.set(now);
            unsafe {
                tl.write(now);
            }
        }

        let s: &str = unsafe { tl.as_str() };

        // SAFETY:
        //
        // The returned &str points to a thread-local fixed-size ASCII buffer.
        // The buffer may be rewritten on later calls to `current_date_str()` on
        // the same OS thread, but never concurrently, because it is thread-local.
        //
        // Do not hold it across coroutine yield points or
        // across another call to `current_date_str()` on the same thread.
        unsafe { std::mem::transmute::<&str, &'static str>(s) }
    })
}
