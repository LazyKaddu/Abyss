//! Pure Token Bucket algorithm for `abyss-tide`.
//!
//! Uses bounded 64-bit saturating arithmetic to ensure 100% verifier safety
//! on bare-metal `#![no_std]` eBPF targets (preventing unresolved `__udivti3` symbols).

use abyss_common::rate_limit::{RateLimitConfig, RateLimitValue};

/// Evaluates and updates the token bucket state against the current timestamp.
///
/// # Arguments
/// - `state`: Mutable reference to the per-IP token bucket state.
/// - `now_ns`: Current kernel timestamp in nanoseconds (e.g. from `bpf_ktime_get_ns()`).
/// - `cfg`: Global rate limiter configuration (`max_pps`, `refill_interval_ns`).
///
/// # Returns
/// - `true`: Packet is compliant, token consumed (`XDP_PASS`).
/// - `false`: Threshold exceeded, bucket empty (`XDP_DROP`).
#[inline(always)]
pub fn evaluate_token_bucket(
    state: &mut RateLimitValue,
    now_ns: u64,
    cfg: &RateLimitConfig,
) -> bool {
    let max_tokens = if cfg.max_pps == 0 { 1000 } else { cfg.max_pps };
    let refill_interval_ns = if cfg.refill_interval_ns == 0 {
        1_000_000_000
    } else {
        cfg.refill_interval_ns
    };

    let elapsed_ns = now_ns.saturating_sub(state.last_refill_ns);

    if elapsed_ns >= refill_interval_ns {
        // Full refill interval elapsed: restore full token budget
        state.tokens = max_tokens;
        state.last_refill_ns = now_ns;
    } else if elapsed_ns > 0 {
        // Fractional refill: compute tokens earned in the elapsed interval.
        // Because elapsed_ns < refill_interval_ns, (elapsed_ns * max_tokens)
        // is strictly bounded and will never overflow u64.
        // We use wrapping_mul to avoid LLVM emitting compiler-rt 128-bit `__multi3` helper calls.
        let tokens_to_add = elapsed_ns.wrapping_mul(max_tokens) / refill_interval_ns;
        if tokens_to_add > 0 {
            state.tokens = core::cmp::min(max_tokens, state.tokens.saturating_add(tokens_to_add));
            let advance_ns = tokens_to_add.wrapping_mul(refill_interval_ns) / max_tokens;
            state.last_refill_ns = state.last_refill_ns.saturating_add(advance_ns);
        }
    }

    // Try to consume 1 token for this packet
    if state.tokens > 0 {
        state.tokens -= 1;
        true
    } else {
        false
    }
}
