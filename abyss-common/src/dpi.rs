//! Deep Packet Inspection (DPI) types for the `abyss-gaze` module.
//!
//! ## Design: Pre-processed Signatures
//!
//! Instead of storing raw string signatures in the kernel (which would require
//! complex variable-length string matching loops that are hard to verify),
//! user-space pre-processes signature rules into fixed-size byte chunks:
//!
//! 1. User-space loads signature rules (e.g., `"GET /etc/passwd"`, SQL injection patterns)
//! 2. Each rule is converted into one or more fixed-width [`DpiSignature`] entries
//! 3. The entries are pushed into a kernel `HashMap` map
//! 4. The kernel module performs fixed-offset byte comparison against packet payloads
//!
//! ## Map Layout
//!
//! | Map Name         | Map Type  | Key    | Value          | Purpose                    |
//! |------------------|-----------|--------|----------------|----------------------------|
//! | `DPI_SIGNATURES` | `HashMap` | `u32`  | `DpiSignature` | Indexed signature patterns |

/// Maximum length of a single signature pattern in bytes.
///
/// Chosen to be large enough for common attack patterns while
/// staying within eBPF stack limits (512 bytes total).
pub const MAX_SIGNATURE_LEN: usize = 32;

/// Maximum number of signature entries in the DPI map.
pub const MAX_SIGNATURES: u32 = 256;

/// Action to take when a DPI signature matches.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DpiAction {
    /// Drop the packet silently (`XDP_DROP`).
    Drop = 0,
    /// Allow the packet but log the match event.
    Alert = 1,
}

impl Default for DpiAction {
    fn default() -> Self {
        Self::Drop
    }
}

/// A single DPI signature entry stored in the kernel `HashMap` map.
///
/// User-space pre-processes full signature rules into these fixed-width
/// byte chunks. The kernel module reads the pattern bytes and performs
/// a fixed-length comparison against the packet payload at the configured
/// offset from the start of the L4 (TCP/UDP) payload.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DpiSignature {
    /// The fixed-size byte pattern to match against.
    /// Only the first `pattern_len` bytes are significant.
    pub pattern: [u8; MAX_SIGNATURE_LEN],
    /// Actual length of the pattern (1..=MAX_SIGNATURE_LEN).
    pub pattern_len: u8,
    /// Action to take on match.
    pub action: DpiAction,
    /// Explicit padding for alignment.
    pub _pad: [u8; 2],
    /// Byte offset from the start of the L4 payload where matching begins.
    /// 0 means scan from the very first byte of the payload.
    pub payload_offset: u32,
}

impl Default for DpiSignature {
    fn default() -> Self {
        Self {
            pattern: [0u8; MAX_SIGNATURE_LEN],
            pattern_len: 0,
            action: DpiAction::Drop,
            _pad: [0; 2],
            payload_offset: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Pod implementations (user-space only)
// ---------------------------------------------------------------------------
#[cfg(feature = "user")]
unsafe impl aya::Pod for DpiSignature {}

// ---------------------------------------------------------------------------
// Layout assertions
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn dpi_signature_layout() {
        // pattern(32) + pattern_len(1) + action(1) + _pad(2) + payload_offset(4) = 40
        assert_eq!(mem::size_of::<DpiSignature>(), 40);
        assert_eq!(mem::align_of::<DpiSignature>(), 4);
    }

    #[test]
    fn dpi_action_size() {
        assert_eq!(mem::size_of::<DpiAction>(), 1);
    }

    #[test]
    fn default_signature_is_zeroed() {
        let sig = DpiSignature::default();
        assert_eq!(sig.pattern_len, 0);
        assert_eq!(sig.payload_offset, 0);
        assert_eq!(sig.action, DpiAction::Drop);
        assert!(sig.pattern.iter().all(|&b| b == 0));
    }
}
