//! Pure, zero-allocation DPI signature matching and payload scanning engine for `abyss-gaze`.
//!
//! Enforces bounded loop depths and constant scan windows to guarantee 100% verifier
//! safety on bare-metal eBPF targets without triggering verifier path explosion.

use abyss_common::dpi::{DpiSignature, MAX_SIGNATURE_LEN};

/// Maximum depth in bytes from the start of the payload to scan for unanchored patterns.
pub const MAX_SCAN_WINDOW: usize = 64;

/// Maximum number of active rules evaluated per packet.
pub const MAX_ACTIVE_RULES: u32 = 32;

/// Evaluates a single signature pattern against the packet application payload.
///
/// # Arguments
/// - `packet_start`: Memory address of packet beginning (`ctx.data()`).
/// - `packet_end`: Memory address of packet end (`ctx.data_end()`).
/// - `payload_offset`: Offset from `packet_start` to the start of the application payload.
/// - `payload_len`: Total bytes in application payload (`packet_end - (packet_start + payload_offset)`).
/// - `sig`: The DPI signature specification (pattern, length, offset, action).
///
/// # Returns
/// - `true` if the pattern matches within packet boundaries.
/// - `false` otherwise.
#[inline(always)]
pub fn match_signature(
    packet_start: usize,
    packet_end: usize,
    payload_offset: usize,
    payload_len: usize,
    sig: &DpiSignature,
) -> bool {
    let pattern_len = sig.pattern_len as usize;
    if pattern_len == 0 || pattern_len > MAX_SIGNATURE_LEN {
        return false;
    }

    let offset = sig.payload_offset as usize;
    let scan_start = payload_offset + offset;

    // Boundary guard: ensure the pattern can fit within packet boundaries
    if packet_start + scan_start + pattern_len > packet_end {
        return false;
    }

    if offset > 0 {
        // Anchored matching at explicit payload_offset
        for j in 0..MAX_SIGNATURE_LEN {
            if j >= pattern_len {
                break;
            }
            if packet_start + scan_start + j + 1 > packet_end {
                return false;
            }
            let byte = unsafe { *((packet_start + scan_start + j) as *const u8) };
            if byte != sig.pattern[j] {
                return false;
            }
        }
        return true;
    }

    // Sliding-window search starting from payload_offset == 0
    let remaining = payload_len.saturating_sub(offset);
    if remaining < pattern_len {
        return false;
    }

    let window = if remaining > MAX_SCAN_WINDOW {
        MAX_SCAN_WINDOW
    } else {
        remaining
    };

    if window < pattern_len {
        return false;
    }

    let max_idx = window - pattern_len;

    for i in 0..MAX_SCAN_WINDOW {
        if i > max_idx {
            break;
        }

        if packet_start + scan_start + i + pattern_len > packet_end {
            break;
        }

        // Fast-path first byte filter
        let first_byte = unsafe { *((packet_start + scan_start + i) as *const u8) };
        if first_byte == sig.pattern[0] {
            let mut matched = true;
            for j in 1..MAX_SIGNATURE_LEN {
                if j >= pattern_len {
                    break;
                }
                let b = unsafe { *((packet_start + scan_start + i + j) as *const u8) };
                if b != sig.pattern[j] {
                    matched = false;
                    break;
                }
            }
            if matched {
                return true;
            }
        }
    }

    false
}
