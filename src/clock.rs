//! Unified high-precision timestamp: the core of the correlator.
//! Every sample from every layer (CPU/RAM/GPU/Disk/Net) carries both:
//! - `wall_ns`: CLOCK_REALTIME in nanoseconds (for cross-node correlation)
//! - `mono_ns`: CLOCK_MONOTONIC in nanoseconds (drift-free deltas on one node)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedTimestamp {
    /// CLOCK_REALTIME, ns since UNIX epoch. Cross-node join key (NTP-synced).
    pub wall_ns: u64,
    /// CLOCK_MONOTONIC, ns since boot. Reliable interval math.
    pub mono_ns: u64,
    /// Human readable wall time.
    pub wall_iso: String,
}

fn clock_ns(clock: libc::clockid_t) -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime with valid clock id + valid pointer.
    let rc = unsafe { libc::clock_gettime(clock, &mut ts) };
    if rc != 0 {
        return 0;
    }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

impl UnifiedTimestamp {
    pub fn now() -> Self {
        let wall_ns = clock_ns(libc::CLOCK_REALTIME);
        let mono_ns = clock_ns(libc::CLOCK_MONOTONIC);
        let dt: DateTime<Utc> =
            DateTime::from_timestamp_nanos(wall_ns as i64).to_utc();
        Self {
            wall_ns,
            mono_ns,
            wall_iso: dt.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
        }
    }
}
