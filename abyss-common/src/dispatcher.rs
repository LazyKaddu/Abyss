//! Dispatcher and module management types for `abyss-core`.
//!
//! ## Map Layout
//!
//! | Map Name        | Map Type    | Key              | Value          | Purpose                         |
//! |-----------------|-------------|------------------|----------------|---------------------------------|
//! | `MODULE_SLOTS`  | `ProgArray` | `u32` (slot idx) | fd (auto)      | Tail call jump table            |
//! | `MODULE_STATUS` | `Array`     | `u32` (slot idx) | `ModuleStatus` | Per-module health/enabled state |

/// Well-known slot indices in the `PROG_ARRAY` tail-call map.
///
/// Each module is assigned a fixed slot. The Root Dispatcher uses these
/// indices with `bpf_tail_call()` to jump to the correct module.
///
/// **Invariant**: These indices must stay stable across releases.
/// Adding new modules means appending new slots — never reordering.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleSlot {
    /// Slot 0: Rate Limiter (`abyss-tide`)
    RateLimiter = 0,
    /// Slot 1: Deep Packet Inspection (`abyss-gaze`)
    Dpi = 1,
}

impl ModuleSlot {
    /// Total number of defined module slots.
    /// Used to size the `PROG_ARRAY` and `MODULE_STATUS` maps.
    pub const COUNT: u32 = 2;
}

/// Per-module status flags stored in an `Array` map.
///
/// User-space sets `enabled` to control whether the dispatcher
/// will tail-call into this module. The kernel checks this flag
/// before every `bpf_tail_call()`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ModuleStatus {
    /// Whether this module is active. 0 = disabled, 1 = enabled.
    /// Using `u32` instead of `bool` for eBPF map compatibility.
    pub enabled: u32,
    /// Explicit padding to align `packets_processed` to 8 bytes.
    pub _pad: u32,
    /// Monotonic counter of packets processed by this module.
    pub packets_processed: u64,
    /// Monotonic counter of packets dropped by this module.
    pub packets_dropped: u64,
}

// ---------------------------------------------------------------------------
// Pod implementations (user-space only)
// ---------------------------------------------------------------------------
#[cfg(feature = "user")]
unsafe impl aya::Pod for ModuleStatus {}

// ---------------------------------------------------------------------------
// Layout assertions
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn module_slot_values() {
        assert_eq!(ModuleSlot::RateLimiter as u32, 0);
        assert_eq!(ModuleSlot::Dpi as u32, 1);
        assert_eq!(ModuleSlot::COUNT, 2);
    }

    #[test]
    fn module_status_layout() {
        // enabled(4) + _pad(4) + packets_processed(8) + packets_dropped(8) = 24
        assert_eq!(mem::size_of::<ModuleStatus>(), 24);
        assert_eq!(mem::align_of::<ModuleStatus>(), 8);
    }

    #[test]
    fn module_status_default() {
        let status = ModuleStatus::default();
        assert_eq!(status.enabled, 0);
        assert_eq!(status.packets_processed, 0);
        assert_eq!(status.packets_dropped, 0);
    }
}
