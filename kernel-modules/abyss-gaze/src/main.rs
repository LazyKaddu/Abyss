//! # abyss-gaze (Ring 0 Deep Packet Inspection)
//!
//! Pluggable security module executing directly in the Linux network driver via XDP.
//! Inspects application-layer payloads past TCP/UDP headers for unauthorized
//! signatures (path traversal, sensitive files, SQL injection, XSS) and issues
//! instantaneous `XDP_DROP` verdicts.

#![no_std]
#![cfg_attr(target_arch = "bpf", no_main)]

#[cfg(not(target_arch = "bpf"))]
extern crate std;

#[cfg(not(target_arch = "bpf"))]
fn main() {}

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, PerCpuArray},
    programs::XdpContext,
};
use abyss_common::{
    dpi::{DpiAction, DpiSignature, MAX_SIGNATURES},
    telemetry::PacketCounters,
};
use abyss_gaze::{
    parse::parse_payload,
    scanner::{scan_chunk, CHUNK_SIZE, MAX_SCAN_WINDOW},
};

// ===========================================================================
// eBPF Maps
// ===========================================================================

/// Active DPI signature patterns populated from user-space (`BPF_MAP_TYPE_ARRAY`).
///
/// Contains up to `MAX_SIGNATURES` (256) pre-processed byte rules.
/// A rule with `pattern_len == 0` marks the end of active rules.
#[map(name = "DPI_SIGNATURES")]
static DPI_SIGNATURES: Array<DpiSignature> = Array::with_max_entries(MAX_SIGNATURES, 0);

/// Per-CPU packet and drop telemetry counters (`BPF_MAP_TYPE_PERCPU_ARRAY`).
///
/// Lock-free per-CPU tracking of passed packets and DPI drop counts.
#[map(name = "GAZE_STATS")]
static GAZE_STATS: PerCpuArray<PacketCounters> = PerCpuArray::with_max_entries(1, 0);

// ===========================================================================
// DPI XDP Entry Point
// ===========================================================================

/// XDP entry point for abyss-gaze.
///
/// Invoked via tail-call from abyss-core or abyss-tide (MODULE_SLOTS slot 1).
/// Inspects application payload against loaded DPI signatures.
#[xdp]
pub fn abyss_gaze(ctx: XdpContext) -> u32 {
    match try_abyss_gaze(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_abyss_gaze(ctx: &XdpContext) -> Result<u32, ()> {
    let start = ctx.data();
    let end = ctx.data_end();

    // 1. Locate application payload past L2 (Ethernet), L3 (IP), and L4 (TCP/UDP)
    let payload = match unsafe { parse_payload(start, end) } {
        Ok(Some(p)) => p,
        // Non-IP, non-TCP/UDP, or pure handshake (0 payload): safely pass through
        Ok(None) | Err(_) => return Ok(xdp_action::XDP_PASS),
    };

    if payload.offset > 1500 || payload.offset < 14 {
        return Ok(xdp_action::XDP_PASS);
    }

    let packet_len = (end.saturating_sub(start)) as u64;

    // 2. Snapshot payload chunk into stack memory ONCE for all rules (up to 32 bytes)
    let mut chunk = [0u8; CHUNK_SIZE];
    let mut chunk_len: usize = 0;

    for k in 0..MAX_SCAN_WINDOW {
        let p = (start + payload.offset + k) as *const u8;
        if (p as usize) + 1 > end {
            break;
        }
        chunk[k] = unsafe { core::ptr::read_volatile(p) };
        chunk_len += 1;
    }

    if chunk_len == 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    // 3. Scan application payload against active DPI signatures
    let mut matched_drop = false;

    // Rule 0
    if let Some(sig) = DPI_SIGNATURES.get(0) {
        if sig.pattern_len > 0 && scan_chunk(&chunk, chunk_len, sig) {
            if sig.action == DpiAction::Drop {
                matched_drop = true;
            }
        }
    }

    // Rule 1
    if !matched_drop {
        if let Some(sig) = DPI_SIGNATURES.get(1) {
            if sig.pattern_len > 0 && scan_chunk(&chunk, chunk_len, sig) {
                if sig.action == DpiAction::Drop {
                    matched_drop = true;
                }
            }
        }
    }

    // Rule 2
    if !matched_drop {
        if let Some(sig) = DPI_SIGNATURES.get(2) {
            if sig.pattern_len > 0 && scan_chunk(&chunk, chunk_len, sig) {
                if sig.action == DpiAction::Drop {
                    matched_drop = true;
                }
            }
        }
    }

    // Rule 3
    if !matched_drop {
        if let Some(sig) = DPI_SIGNATURES.get(3) {
            if sig.pattern_len > 0 && scan_chunk(&chunk, chunk_len, sig) {
                if sig.action == DpiAction::Drop {
                    matched_drop = true;
                }
            }
        }
    }

    // 4. Update telemetry and return verdict
    if matched_drop {
        if let Some(counters) = GAZE_STATS.get_ptr_mut(0) {
            unsafe {
                (*counters).bytes_total += packet_len;
                (*counters).packets_dropped += 1;
                (*counters).packets_dropped_dpi += 1;
            }
        }
        Ok(xdp_action::XDP_DROP)
    } else {
        if let Some(counters) = GAZE_STATS.get_ptr_mut(0) {
            unsafe {
                (*counters).bytes_total += packet_len;
                (*counters).packets_passed += 1;
            }
        }
        Ok(xdp_action::XDP_PASS)
    }
}

// ===========================================================================
// Bare-Metal Panic Handler (only for bpf target)
// ===========================================================================

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
