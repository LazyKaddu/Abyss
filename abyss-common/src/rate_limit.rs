//! Rate-limiter types for the `abyss-tide` module.
//!
//! ## Map Layout
//!
//! | Map Name           | Map Type     | Key             | Value             | Purpose                         |
//! |--------------------|-------------|-----------------|-------------------|---------------------------------|
//! | `RATE_LIMIT_STATE` | `LruHashMap` | `RateLimitKey`  | `RateLimitValue`  | Per-IP token bucket state       |
//! | `RATE_LIMIT_CFG`   | `Array`      | `u32(0)`        | `RateLimitConfig` | Global rate-limit configuration |

/// Maximum number of tracked IPs in the LRU map before eviction.
pub const MAX_TRACKED_IPS: u32 = 65_536;

/// Map key for the per-IP rate-limiting LRU HashMap.
///
/// Currently IPv4 only (32-bit source address). The struct is sized
/// to allow future expansion to IPv6 by replacing `src_addr` with
/// a 16-byte array without changing the map definition pattern.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RateLimitKey {
    /// Source IPv4 address in network byte order.
    pub src_addr: u32,
}

/// Map value storing per-IP token bucket state.
///
/// The kernel module updates this on every packet from a tracked IP.
/// When `tokens` reaches zero, subsequent packets are dropped until
/// the refill interval elapses.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct RateLimitValue {
    /// Remaining tokens in the bucket. Decremented per packet.
    pub tokens: u64,
    /// Timestamp (ns) of the last token refill (`bpf_ktime_get_ns()`).
    pub last_refill_ns: u64,
}

/// Global rate-limiter configuration, pushed from user-space into
/// a single-entry `Array` map.
///
/// User-space writes this once (or on config reload). The kernel
/// module reads it on every packet to know the current thresholds.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RateLimitConfig {
    /// Maximum packets per second allowed per source IP.
    /// Bucket capacity = this value.
    pub max_pps: u64,
    /// Token refill interval in nanoseconds.
    /// Tokens are fully replenished every `refill_interval_ns`.
    /// Default: 1_000_000_000 (1 second).
    pub refill_interval_ns: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_pps: 1000,
            refill_interval_ns: 1_000_000_000, // 1 second
        }
    }
}

// ---------------------------------------------------------------------------
// Pod implementations (user-space only)
// ---------------------------------------------------------------------------
#[cfg(feature = "user")]
unsafe impl aya::Pod for RateLimitKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RateLimitValue {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RateLimitConfig {}

// ---------------------------------------------------------------------------
// Layout assertions
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn rate_limit_key_layout() {
        assert_eq!(mem::size_of::<RateLimitKey>(), 4);
        assert_eq!(mem::align_of::<RateLimitKey>(), 4);
    }

    #[test]
    fn rate_limit_value_layout() {
        // tokens(8) + last_refill_ns(8) = 16
        assert_eq!(mem::size_of::<RateLimitValue>(), 16);
        assert_eq!(mem::align_of::<RateLimitValue>(), 8);
    }

    #[test]
    fn rate_limit_config_layout() {
        // max_pps(8) + refill_interval_ns(8) = 16
        assert_eq!(mem::size_of::<RateLimitConfig>(), 16);
        assert_eq!(mem::align_of::<RateLimitConfig>(), 8);
    }

    #[test]
    fn default_config_values() {
        let cfg = RateLimitConfig::default();
        assert_eq!(cfg.max_pps, 1000);
        assert_eq!(cfg.refill_interval_ns, 1_000_000_000);
    }
}
