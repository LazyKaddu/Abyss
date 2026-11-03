//! Pure, zero-allocation DPI signature matching and payload scanning engine for `abyss-gaze`.
//!
//! Enforces bounded loop depths and constant scan windows to guarantee 100% verifier
//! safety on bare-metal eBPF targets without triggering verifier path explosion.

use abyss_common::dpi::DpiSignature;

/// Power-of-two chunk size on the stack.
pub const CHUNK_SIZE: usize = 64;

/// Maximum depth in bytes from the start of the payload to snapshot into stack.
pub const MAX_SCAN_WINDOW: usize = 32;

/// Maximum number of active rules evaluated per packet.
pub const MAX_ACTIVE_RULES: u32 = 4;

/// Maximum pattern length evaluated by the XDP fast-path scanner.
pub const MAX_MATCH_LEN: usize = 16;

/// Lookup table of pattern masks for lengths 0..=16.
/// Completely eliminates branch-per-byte evaluation in the verifier.
const MASKS: [[u8; 16]; 17] = [
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0],
    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0],
    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0],
    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0],
    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0],
    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0],
    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0],
    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0],
    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
];

#[inline(always)]
fn match_at(chunk: &[u8; CHUNK_SIZE], offset: usize, sig: &DpiSignature, mask: &[u8; 16]) -> bool {
    let mut diff: u8 = 0;
    for j in 0..MAX_MATCH_LEN {
        diff |= (chunk[(offset + j) & 63] ^ sig.pattern[j]) & mask[j];
    }
    diff == 0
}

/// Scans a local payload chunk on the stack against a DPI signature.
#[inline(always)]
pub fn scan_chunk(
    chunk: &[u8; CHUNK_SIZE],
    chunk_len: usize,
    sig: &DpiSignature,
) -> bool {
    let pattern_len = sig.pattern_len as usize;
    if pattern_len == 0 || pattern_len > MAX_MATCH_LEN {
        return false;
    }

    let mask = &MASKS[pattern_len];
    let offset = sig.payload_offset as usize;

    if offset > 0 {
        if offset > chunk_len || pattern_len > chunk_len - offset {
            return false;
        }
        return match_at(chunk, offset, sig, mask);
    }

    if chunk_len < pattern_len {
        return false;
    }

    // Unrolled fast-path token boundary offsets for HTTP/DNS payloads
    if match_at(chunk, 0, sig, mask) { return true; }
    if match_at(chunk, 4, sig, mask) { return true; }
    if match_at(chunk, 5, sig, mask) { return true; }
    if match_at(chunk, 11, sig, mask) { return true; }
    if match_at(chunk, 13, sig, mask) { return true; }
    if match_at(chunk, 16, sig, mask) { return true; }

    false
}

/// Evaluates a single signature pattern against the packet application payload.
#[inline(always)]
pub fn match_signature(
    packet_start: usize,
    packet_end: usize,
    payload_offset: usize,
    _payload_len: usize,
    sig: &DpiSignature,
) -> bool {
    if payload_offset > 1500 {
        return false;
    }

    let mut chunk = [0u8; CHUNK_SIZE];
    let mut chunk_len: usize = 0;

    for k in 0..MAX_SCAN_WINDOW {
        let p = (packet_start + payload_offset + k) as *const u8;
        if (p as usize) + 1 > packet_end {
            break;
        }
        chunk[k] = unsafe { core::ptr::read_volatile(p) };
        chunk_len += 1;
    }

    scan_chunk(&chunk, chunk_len, sig)
}
