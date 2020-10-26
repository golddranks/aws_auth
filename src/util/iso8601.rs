use std::time::{SystemTime, UNIX_EPOCH};

pub const YYYYMMDD: [u8; 8] = *b"00000000";
pub const BASIC_FORMAT_SEC_UTC: [u8; 16] = *b"00000000T000000Z";

pub trait FormatTime {
    fn write_yyyymmdd(&self, buf: &mut [u8; 8]);

    /// ISO 8602 Basic format is a format that doesn't have separators
    /// between the fields: YYYYMMDDTHHMMSSZ
    fn write_iso8602_basic_seconds_utc(&self, buf: &mut [u8; 16]);
}

impl FormatTime for SystemTime {
    fn write_yyyymmdd(&self, buf: &mut [u8; 8]) {
        let duration_since_epoch = self
            .duration_since(UNIX_EPOCH)
            .expect("not supporting printing timestamps before the UNIX epoch");
        let secs_since_epoch = duration_since_epoch.as_secs();

        if secs_since_epoch >= 253402300800 {
            panic!("not supporting printing timestamps after year 9999");
        }

        let (year, month, mday) = date_calc(secs_since_epoch);

        buf[0] = b'0' + (year / 1000) as u8;
        buf[1] = b'0' + (year / 100 % 10) as u8;
        buf[2] = b'0' + (year / 10 % 10) as u8;
        buf[3] = b'0' + (year % 10) as u8;
        buf[4] = b'0' + (month / 10) as u8;
        buf[5] = b'0' + (month % 10) as u8;
        buf[6] = b'0' + (mday / 10) as u8;
        buf[7] = b'0' + (mday % 10) as u8;
    }

    fn write_iso8602_basic_seconds_utc(&self, buf: &mut [u8; 16]) {
        let duration_since_epoch = self
            .duration_since(UNIX_EPOCH)
            .expect("not supporting printing timestamps before the UNIX epoch");
        let secs_since_epoch = duration_since_epoch.as_secs();

        if secs_since_epoch >= 253402300800 {
            panic!("not supporting printing timestamps after year 9999");
        }

        let (year, month, mday) = date_calc(secs_since_epoch);
        let secs_of_day = secs_since_epoch % 86400;

        buf[0] = b'0' + (year / 1000) as u8;
        buf[1] = b'0' + (year / 100 % 10) as u8;
        buf[2] = b'0' + (year / 10 % 10) as u8;
        buf[3] = b'0' + (year % 10) as u8;
        buf[4] = b'0' + (month / 10) as u8;
        buf[5] = b'0' + (month % 10) as u8;
        buf[6] = b'0' + (mday / 10) as u8;
        buf[7] = b'0' + (mday % 10) as u8;
        buf[8] = b'T';
        buf[9] = b'0' + (secs_of_day / 3600 / 10) as u8;
        buf[10] = b'0' + (secs_of_day / 3600 % 10) as u8;
        buf[11] = b'0' + (secs_of_day / 60 / 10 % 6) as u8;
        buf[12] = b'0' + (secs_of_day / 60 % 10) as u8;
        buf[13] = b'0' + (secs_of_day / 10 % 6) as u8;
        buf[14] = b'0' + (secs_of_day % 10) as u8;
        buf[15] = b'Z';
    }
}

fn date_calc(secs_since_epoch: u64) -> (i64, i32, i64) {
    // The calculation logic is adapted from humantime crate by Paul Colomiets
    // https://crates.io/crates/humantime (MIT/Apache-2.0 licensed)

    /* 2000-03-01 (mod 400 year, immediately after feb29 */
    const LEAPOCH: i64 = 11017;
    const DAYS_PER_400Y: i64 = 365 * 400 + 97;
    const DAYS_PER_100Y: i64 = 365 * 100 + 24;
    const DAYS_PER_4Y: i64 = 365 * 4 + 1;

    let days = (secs_since_epoch / 86400) as i64 - LEAPOCH;

    let mut qc_cycles = days / DAYS_PER_400Y;
    let mut remdays = days % DAYS_PER_400Y;

    if remdays < 0 {
        remdays += DAYS_PER_400Y;
        qc_cycles -= 1;
    }

    let mut c_cycles = remdays / DAYS_PER_100Y;
    if c_cycles == 4 {
        c_cycles -= 1;
    }
    remdays -= c_cycles * DAYS_PER_100Y;

    let mut q_cycles = remdays / DAYS_PER_4Y;
    if q_cycles == 25 {
        q_cycles -= 1;
    }
    remdays -= q_cycles * DAYS_PER_4Y;

    let mut remyears = remdays / 365;
    if remyears == 4 {
        remyears -= 1;
    }
    remdays -= remyears * 365;

    let mut year = 2000 + remyears + 4 * q_cycles + 100 * c_cycles + 400 * qc_cycles;

    let months = [31, 30, 31, 30, 31, 31, 30, 31, 30, 31, 31, 29];
    let mut mon = 0;
    for mon_len in months.iter() {
        mon += 1;
        if remdays < *mon_len {
            break;
        }
        remdays -= *mon_len;
    }
    let mday = remdays + 1;
    let mon = if mon + 2 > 12 {
        year += 1;
        mon - 10
    } else {
        mon + 2
    };

    (year, mon, mday)
}
