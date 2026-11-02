//! # abyss-core (Ring 0 Root Dispatcher)
//!
//! The primary XDP ingress program attached directly to the Network Interface Card (NIC) driver.
//!
//! ## Responsibilities:
//! 1. Zero-copy packet parsing of Ethernet, IPv4, and IPv6 headers with explicit bounds checking.
//! 2. Route incoming traffic to security modules (`abyss-tide`, `abyss-gaze`) via `bpf_tail_call()`.
//! 3. Maintain high-throughput, lock-free per-CPU packet and byte counters (`PACKET_COUNTERS`).
//!
//! ## Step 2 Baseline:
//! In this step, the program parses packets safely and passes all traffic (`XDP_PASS`) to establish
//! a stable, verified baseline for the user-space loader.

#![no_std]
#![cfg_attr(target_arch = "bpf", no_main)]

#[cfg(not(target_arch = "bpf"))]
extern crate std;

#[cfg(not(target_arch = "bpf"))]
fn main() {}

mod parse;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, PerCpuArray, ProgramArray},
    programs::XdpContext,
};
use abyss_common::dispatcher::{ModuleSlot, ModuleStatus};
use abyss_common::telemetry::PacketCounters;
use parse::parse_packet;

// ===========================================================================
// eBPF Maps
// ===========================================================================

/// Jump table for eBPF tail calls (`BPF_MAP_TYPE_PROG_ARRAY`).
///
/// Holds file descriptors of loaded security modules:
/// - Slot 0: Rate Limiter (`abyss-tide`)
/// - Slot 1: Deep Packet Inspection (`abyss-gaze`)
#[map(name = "MODULE_SLOTS")]
static MODULE_SLOTS: ProgramArray = ProgramArray::with_max_entries(ModuleSlot::COUNT, 0);

/// Per-module runtime status flags and counters (`BPF_MAP_TYPE_ARRAY`).
///
/// User-space dynamically enables or disables modules at runtime.
/// The kernel checks `enabled` status before performing tail calls.
#[map(name = "MODULE_STATUS")]
static MODULE_STATUS: Array<ModuleStatus> = Array::with_max_entries(ModuleSlot::COUNT, 0);

/// Per-CPU packet and byte telemetry counters (`BPF_MAP_TYPE_PERCPU_ARRAY`).
///
/// Lock-free line-rate counting per CPU core to prevent cache-line bouncing.
/// User-space reads and sums all core values into global totals.
#[map(name = "PACKET_COUNTERS")]
static PACKET_COUNTERS: PerCpuArray<PacketCounters> = PerCpuArray::with_max_entries(1, 0);

// ===========================================================================
// Root Dispatcher XDP Entry Point
// ===========================================================================

/// Primary XDP hook attached directly to the NIC driver.
///
/// Evaluates incoming frames, parses network headers, updates telemetry,
/// and routes packets to downstream modules via the tail-call table.
#[xdp]
pub fn abyss_dispatcher(ctx: XdpContext) -> u32 {
    match try_abyss_dispatcher(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

/// Fallible inner handler with strict verifier bounds safety.
#[inline(always)]
fn try_abyss_dispatcher(ctx: &XdpContext) -> Result<u32, ()> {
    let start = ctx.data();
    let end = ctx.data_end();

    // 1. Parse Ethernet and IP headers safely with bounds checking
    let _parsed = unsafe { parse_packet(start, end)? };

    // 2. Record packet statistics in per-CPU telemetry map (lock-free)
    let packet_len = (end.saturating_sub(start)) as u64;
    if let Some(counters) = PACKET_COUNTERS.get_ptr_mut(0) {
        unsafe {
            (*counters).packets_passed += 1;
            (*counters).bytes_total += packet_len;
        }
    }

    // 3. Step 2 Baseline: Pass all traffic safely (XDP_PASS)
    // Downstream steps will engage bpf_tail_call into MODULE_SLOTS
    Ok(xdp_action::XDP_PASS)
}

// ===========================================================================
// Bare-Metal Panic Handler (only for bpf target)
// ===========================================================================

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
