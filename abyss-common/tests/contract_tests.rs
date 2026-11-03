//! Integration tests for the abyss-common shared contract.
//!
//! Validates:
//! 1. Exact field offsets (C ABI memory layout) to prevent Ring 0 / User Space divergence.
//! 2. Byte serialization / round-trip safety (Aya Pod compliance).
//! 3. Domain simulation (token bucket logic, DPI offset matching, dispatcher indexing).

use abyss_common::*;
use core::mem::{align_of, offset_of, size_of};

// ===========================================================================
// 1. C-ABI Memory Layout & Exact Field Offsets
// ===========================================================================

#[test]
fn test_packet_counters_offsets_and_alignment() {
    assert_eq!(size_of::<PacketCounters>(), 48);
    assert_eq!(align_of::<PacketCounters>(), 8);

    assert_eq!(offset_of!(PacketCounters, packets_passed), 0);
    assert_eq!(offset_of!(PacketCounters, packets_dropped), 8);
    assert_eq!(offset_of!(PacketCounters, bytes_total), 16);
    assert_eq!(offset_of!(PacketCounters, packets_dropped_rate_limit), 24);
    assert_eq!(offset_of!(PacketCounters, packets_dropped_dpi), 32);
    assert_eq!(offset_of!(PacketCounters, packets_dropped_blocked), 40);
}

#[test]
fn test_packet_event_offsets_and_alignment() {
    assert_eq!(size_of::<PacketEvent>(), 32);
    assert_eq!(align_of::<PacketEvent>(), 8);

    assert_eq!(offset_of!(PacketEvent, src_addr), 0);
    assert_eq!(offset_of!(PacketEvent, dst_addr), 4);
    assert_eq!(offset_of!(PacketEvent, src_port), 8);
    assert_eq!(offset_of!(PacketEvent, dst_port), 10);
    assert_eq!(offset_of!(PacketEvent, protocol), 12);
    assert_eq!(offset_of!(PacketEvent, verdict), 13);
    assert_eq!(offset_of!(PacketEvent, _pad), 14);
    assert_eq!(offset_of!(PacketEvent, packet_len), 16);
    assert_eq!(offset_of!(PacketEvent, timestamp_ns), 24);
}

#[test]
fn test_rate_limit_key_offsets_and_alignment() {
    assert_eq!(size_of::<RateLimitKey>(), 4);
    assert_eq!(align_of::<RateLimitKey>(), 4);

    assert_eq!(offset_of!(RateLimitKey, src_addr), 0);
}

#[test]
fn test_rate_limit_value_offsets_and_alignment() {
    assert_eq!(size_of::<RateLimitValue>(), 16);
    assert_eq!(align_of::<RateLimitValue>(), 8);

    assert_eq!(offset_of!(RateLimitValue, tokens), 0);
    assert_eq!(offset_of!(RateLimitValue, last_refill_ns), 8);
}

#[test]
fn test_rate_limit_config_offsets_and_alignment() {
    assert_eq!(size_of::<RateLimitConfig>(), 16);
    assert_eq!(align_of::<RateLimitConfig>(), 8);

    assert_eq!(offset_of!(RateLimitConfig, max_pps), 0);
    assert_eq!(offset_of!(RateLimitConfig, refill_interval_ns), 8);
}

#[test]
fn test_dpi_signature_offsets_and_alignment() {
    assert_eq!(size_of::<DpiSignature>(), 40);
    assert_eq!(align_of::<DpiSignature>(), 4);

    assert_eq!(offset_of!(DpiSignature, pattern), 0);
    assert_eq!(offset_of!(DpiSignature, pattern_len), 32);
    assert_eq!(offset_of!(DpiSignature, action), 33);
    assert_eq!(offset_of!(DpiSignature, _pad), 34);
    assert_eq!(offset_of!(DpiSignature, payload_offset), 36);
}

#[test]
fn test_module_status_offsets_and_alignment() {
    assert_eq!(size_of::<ModuleStatus>(), 24);
    assert_eq!(align_of::<ModuleStatus>(), 8);

    assert_eq!(offset_of!(ModuleStatus, enabled), 0);
    assert_eq!(offset_of!(ModuleStatus, _pad), 4);
    assert_eq!(offset_of!(ModuleStatus, packets_processed), 8);
    assert_eq!(offset_of!(ModuleStatus, packets_dropped), 16);
}

// ===========================================================================
// 2. Binary Roundtrip / Raw Memory Safety (Simulating eBPF map reading)
// ===========================================================================

#[test]
fn test_packet_counters_raw_bytes_roundtrip() {
    let original = PacketCounters {
        packets_passed: 1_000_000,
        packets_dropped: 42_000,
        bytes_total: 150_000_000,
        packets_dropped_rate_limit: 40_000,
        packets_dropped_dpi: 1_000,
        packets_dropped_blocked: 1_000,
    };

    let bytes: [u8; size_of::<PacketCounters>()] = unsafe { core::mem::transmute(original) };
    let reconstructed: PacketCounters = unsafe { core::mem::transmute(bytes) };

    assert_eq!(reconstructed.packets_passed, 1_000_000);
    assert_eq!(reconstructed.packets_dropped, 42_000);
    assert_eq!(reconstructed.bytes_total, 150_000_000);
    assert_eq!(reconstructed.packets_dropped_rate_limit, 40_000);
    assert_eq!(reconstructed.packets_dropped_dpi, 1_000);
    assert_eq!(reconstructed.packets_dropped_blocked, 1_000);
}

#[test]
fn test_packet_event_raw_bytes_roundtrip() {
    let original = PacketEvent {
        src_addr: 0x01020304, // 1.2.3.4
        dst_addr: 0x05060708, // 5.6.7.8
        src_port: 8080,
        dst_port: 443,
        protocol: 6, // TCP
        verdict: XdpVerdict::Drop,
        _pad: [0; 2],
        packet_len: 1514,
        timestamp_ns: 123_456_789_000,
    };

    let bytes: [u8; size_of::<PacketEvent>()] = unsafe { core::mem::transmute(original) };
    let reconstructed: PacketEvent = unsafe { core::mem::transmute(bytes) };

    assert_eq!(reconstructed.src_addr, 0x01020304);
    assert_eq!(reconstructed.dst_addr, 0x05060708);
    assert_eq!(reconstructed.src_port, 8080);
    assert_eq!(reconstructed.dst_port, 443);
    assert_eq!(reconstructed.protocol, 6);
    assert_eq!(reconstructed.verdict, XdpVerdict::Drop);
    assert_eq!(reconstructed.packet_len, 1514);
    assert_eq!(reconstructed.timestamp_ns, 123_456_789_000);
}

// ===========================================================================
// 3. Domain Simulation & Behavioral Tests
// ===========================================================================

#[test]
fn test_token_bucket_rate_limiter_simulation() {
    let config = RateLimitConfig {
        max_pps: 100,
        refill_interval_ns: 1_000_000_000, // 1 second
    };

    let mut state = RateLimitValue {
        tokens: config.max_pps,
        last_refill_ns: 0,
    };

    // Simulate consuming tokens
    for _ in 0..100 {
        assert!(state.tokens > 0, "should have tokens available");
        state.tokens -= 1;
    }
    assert_eq!(state.tokens, 0, "bucket should be empty");

    // Simulate 500ms elapsed (half refill interval)
    let current_ns = 500_000_000;
    let elapsed = current_ns - state.last_refill_ns;
    let tokens_to_add = (elapsed * config.max_pps) / config.refill_interval_ns;
    state.tokens = (state.tokens + tokens_to_add).min(config.max_pps);
    state.last_refill_ns = current_ns;

    assert_eq!(state.tokens, 50, "should have refilled 50 tokens at 500ms");
}

#[test]
fn test_dpi_payload_matching_simulation() {
    let mut sig = DpiSignature {
        pattern: [0; MAX_SIGNATURE_LEN],
        pattern_len: 4,
        action: DpiAction::Drop,
        _pad: [0; 2],
        payload_offset: 0,
    };
    // Match "POST" at offset 0
    sig.pattern[0..4].copy_from_slice(b"POST");

    // Simulated packet payloads:
    let malformed_packet = b"POST /api/v1/exploit HTTP/1.1\r\n";
    let benign_packet = b"GET /index.html HTTP/1.1\r\n";

    // Matching logic that kernel abyss-gaze executes
    let matches_malformed = {
        let offset = sig.payload_offset as usize;
        let len = sig.pattern_len as usize;
        malformed_packet.len() >= offset + len
            && &malformed_packet[offset..offset + len] == &sig.pattern[..len]
    };
    assert!(matches_malformed, "DPI should have matched POST");

    let matches_benign = {
        let offset = sig.payload_offset as usize;
        let len = sig.pattern_len as usize;
        benign_packet.len() >= offset + len
            && &benign_packet[offset..offset + len] == &sig.pattern[..len]
    };
    assert!(!matches_benign, "DPI should NOT have matched GET");
}

#[test]
fn test_dispatcher_slot_table() {
    let mut module_table = [ModuleStatus::default(); ModuleSlot::COUNT as usize];

    // Configure RateLimiter in slot 0
    module_table[ModuleSlot::RateLimiter as usize] = ModuleStatus {
        enabled: 1,
        _pad: 0,
        packets_processed: 500,
        packets_dropped: 12,
    };

    // Configure DPI in slot 1
    module_table[ModuleSlot::Dpi as usize] = ModuleStatus {
        enabled: 1,
        _pad: 0,
        packets_processed: 488,
        packets_dropped: 3,
    };

    assert_eq!(module_table[0].packets_processed, 500);
    assert_eq!(module_table[1].packets_processed, 488);
    assert_eq!(module_table[0].enabled, 1);
    assert_eq!(module_table[1].enabled, 1);
}
