//! # abyss-tide (Ring 0 Stateful Rate Limiter)
//!
//! Pluggable security module executing directly in the Linux network driver via XDP.
//! Implements a token bucket rate limiter tracking per-source-IP state using
//! an LRU hash map (`BPF_MAP_TYPE_LRU_HASH`) with bounded 64-bit saturating math.

#![no_std]
#![cfg_attr(target_arch = "bpf", no_main)]

#[cfg(not(target_arch = "bpf"))]
extern crate std;

#[cfg(not(target_arch = "bpf"))]
fn main() {}

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::{Array, LruHashMap, PerCpuArray, ProgramArray},
    programs::XdpContext,
};
use abyss_common::{
    dispatcher::{ModuleSlot, ModuleStatus},
    rate_limit::{RateLimitConfig, RateLimitKey, RateLimitValue, MAX_TRACKED_IPS},
    telemetry::PacketCounters,
};
use abyss_tide::{bucket::evaluate_token_bucket, parse::parse_ipv4_src};

// ===========================================================================
// eBPF Maps
// ===========================================================================

/// Downstream jump table for module pipeline chaining (`BPF_MAP_TYPE_PROG_ARRAY`).
#[map(name = "MODULE_SLOTS")]
static MODULE_SLOTS: ProgramArray = ProgramArray::with_max_entries(ModuleSlot::COUNT, 0);

/// Per-module runtime status flags (`BPF_MAP_TYPE_ARRAY`).
#[map(name = "MODULE_STATUS")]
static MODULE_STATUS: Array<ModuleStatus> = Array::with_max_entries(ModuleSlot::COUNT, 0);

/// Per-IP token bucket state tracking (`BPF_MAP_TYPE_LRU_HASH`).
///
/// Automatically evicts least recently seen IPs when capacity is reached (65,536 entries).
#[map(name = "RATE_LIMIT_STATE")]
static RATE_LIMIT_STATE: LruHashMap<RateLimitKey, RateLimitValue> =
    LruHashMap::with_max_entries(MAX_TRACKED_IPS, 0);

/// Global rate limiter configuration (`BPF_MAP_TYPE_ARRAY`).
///
/// Single entry at index 0, configured dynamically from user-space.
#[map(name = "RATE_LIMIT_CFG")]
static RATE_LIMIT_CFG: Array<RateLimitConfig> = Array::with_max_entries(1, 0);

/// Per-CPU packet counters for telemetry (`BPF_MAP_TYPE_PERCPU_ARRAY`).
///
/// Module telemetry counters (packets passed, dropped, rate limit drops).
#[map(name = "TIDE_STATS")]
static TIDE_STATS: PerCpuArray<PacketCounters> = PerCpuArray::with_max_entries(1, 0);

// ===========================================================================
// Rate Limiter XDP Entry Point
// ===========================================================================

/// XDP entry point for abyss-tide.
///
/// Invoked via tail-call from abyss-core (MODULE_SLOTS slot 0).
/// Evaluates IPv4 source address against token bucket rate limits.
#[xdp]
pub fn abyss_tide(ctx: XdpContext) -> u32 {
    match try_abyss_tide(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_abyss_tide(ctx: &XdpContext) -> Result<u32, ()> {
    let start = ctx.data();
    let end = ctx.data_end();

    // 1. Parse IPv4 source address; if non-IPv4 or malformed, pass packet
    let src_ip = match unsafe { parse_ipv4_src(start, end) } {
        Ok(Some(ip)) => ip,
        Ok(None) => return Ok(xdp_action::XDP_PASS), // Non-IPv4 bypasses rate limiter
        Err(_) => return Ok(xdp_action::XDP_PASS),   // Truncated/malformed, let core/stack handle
    };

    // 2. Fetch rate limiter configuration (default fallback if unconfigured)
    let default_cfg = RateLimitConfig {
        max_pps: 1000,
        refill_interval_ns: 1_000_000_000,
    };
    let cfg = RATE_LIMIT_CFG.get(0).unwrap_or(&default_cfg);

    // 3. Query current monotonic kernel time in nanoseconds
    let now_ns = unsafe { bpf_ktime_get_ns() };

    let key = RateLimitKey { src_addr: src_ip };

    // 4. Lookup or initialize rate limit state in LRU hash map
    let allowed = match RATE_LIMIT_STATE.get_ptr_mut(&key) {
        Some(state_ptr) => {
            let state = unsafe { &mut *state_ptr };
            evaluate_token_bucket(state, now_ns, cfg)
        }
        None => {
            // New IP observed: create initial bucket with max_tokens - 1 (1 token consumed)
            let max_tokens = if cfg.max_pps == 0 { 1000 } else { cfg.max_pps };
            let initial_state = RateLimitValue {
                tokens: max_tokens.saturating_sub(1),
                last_refill_ns: now_ns,
            };
            let _ = RATE_LIMIT_STATE.insert(&key, &initial_state, 0);
            true
        }
    };

    // 5. Update module telemetry counters
    let packet_len = (end.saturating_sub(start)) as u64;
    if let Some(counters) = TIDE_STATS.get_ptr_mut(0) {
        unsafe {
            (*counters).bytes_total += packet_len;
            if allowed {
                (*counters).packets_passed += 1;
            } else {
                (*counters).packets_dropped += 1;
                (*counters).packets_dropped_rate_limit += 1;
            }
        }
    }

    if allowed {
        // If downstream Deep Packet Inspection (Slot 1) is enabled, chain into abyss-gaze
        if let Some(status) = MODULE_STATUS.get(ModuleSlot::Dpi as u32) {
            if status.enabled != 0 {
                unsafe {
                    MODULE_SLOTS.tail_call(ctx, ModuleSlot::Dpi as u32);
                }
                // Only falls through if Slot 1 is unpopulated or invocation failed
            }
        }
        Ok(xdp_action::XDP_PASS)
    } else {
        Ok(xdp_action::XDP_DROP)
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
