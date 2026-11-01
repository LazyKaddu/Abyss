//! Telemetry types shared between kernel and user space.
//!
//! ## Map Layout
//!
//! | Map Name          | Map Type      | Key      | Value            | Purpose                    |
//! |-------------------|---------------|----------|------------------|----------------------------|
//! | `PACKET_COUNTERS` | `PerCpuArray` | `u32(0)` | `PacketCounters` | Aggregated stats per CPU   |
//! | `PACKET_EVENTS`   | `RingBuf`     | —        | `PacketEvent`    | Per-packet event stream    |

/// Aggregated packet counters stored in a `PerCpuArray` map.
///
/// Each CPU core maintains its own copy (lock-free). User-space sums
/// all per-CPU values to get the global totals.
///
/// Map: `PACKET_COUNTERS` — `PerCpuArray<PacketCounters>` with a single
///       entry at index 0.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PacketCounters {
    /// Total packets that passed through the dispatcher.
    pub packets_passed: u64,
    /// Total packets dropped by any module (rate-limit, DPI, etc).
    pub packets_dropped: u64,
    /// Total bytes processed (sum of all packet lengths).
    pub bytes_total: u64,
    /// Packets dropped specifically by the rate limiter (abyss-tide).
    pub packets_dropped_rate_limit: u64,
    /// Packets dropped specifically by DPI inspection (abyss-gaze).
    pub packets_dropped_dpi: u64,
}

/// The XDP verdict applied to a packet, encoded as a `u8` for compact storage.
///
/// Maps to the kernel's XDP action constants but stored as our own enum
/// for type safety in the shared contract.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XdpVerdict {
    /// Packet was allowed through (`XDP_PASS`).
    Pass = 0,
    /// Packet was silently discarded (`XDP_DROP`).
    Drop = 1,
    /// Packet was sent back out the same interface (`XDP_TX`).
    Tx = 2,
    /// Packet was redirected to another interface (`XDP_REDIRECT`).
    Redirect = 3,
    /// Packet processing was aborted due to an error (`XDP_ABORTED`).
    Aborted = 4,
}

impl Default for XdpVerdict {
    fn default() -> Self {
        Self::Pass
    }
}

/// A per-packet event streamed to user-space via a `RingBuf` map.
///
/// This provides real-time visibility into individual packet decisions.
/// User-space reads these events asynchronously for live dashboards,
/// logging, or alerting.
///
/// Map: `PACKET_EVENTS` — `RingBuf` (256 KB default).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PacketEvent {
    /// Source IPv4 address (network byte order).
    pub src_addr: u32,
    /// Destination IPv4 address (network byte order).
    pub dst_addr: u32,
    /// Source port (network byte order). 0 for non-TCP/UDP protocols.
    pub src_port: u16,
    /// Destination port (network byte order). 0 for non-TCP/UDP protocols.
    pub dst_port: u16,
    /// IP protocol number (6 = TCP, 17 = UDP, 1 = ICMP, etc).
    pub protocol: u8,
    /// Which XDP verdict was applied.
    pub verdict: XdpVerdict,
    /// Explicit padding to maintain 4-byte alignment.
    pub _pad: [u8; 2],
    /// Total packet length in bytes (from L2 header to end).
    pub packet_len: u32,
    /// Kernel timestamp in nanoseconds (`bpf_ktime_get_ns()`).
    pub timestamp_ns: u64,
}

// ---------------------------------------------------------------------------
// Pod implementations (user-space only)
// ---------------------------------------------------------------------------
#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketCounters {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketEvent {}

// ---------------------------------------------------------------------------
// Layout assertions — catch padding bugs at compile / test time
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn packet_counters_layout() {
        // 5 fields × 8 bytes each = 40 bytes, no padding needed
        assert_eq!(mem::size_of::<PacketCounters>(), 40);
        assert_eq!(mem::align_of::<PacketCounters>(), 8);
    }

    #[test]
    fn packet_event_layout() {
        // src_addr(4) + dst_addr(4) + src_port(2) + dst_port(2) +
        // protocol(1) + verdict(1) + _pad(2) + packet_len(4) + timestamp_ns(8)
        // = 28 bytes of fields + 4 bytes trailing padding (8-byte alignment) = 32
        assert_eq!(mem::size_of::<PacketEvent>(), 32);
        assert_eq!(mem::align_of::<PacketEvent>(), 8);
    }

    #[test]
    fn xdp_verdict_size() {
        assert_eq!(mem::size_of::<XdpVerdict>(), 1);
    }
}
