//! Unit and integration tests for `abyss-tide`.

use abyss_common::rate_limit::{RateLimitConfig, RateLimitValue};
use abyss_tide::bucket::evaluate_token_bucket;
use abyss_tide::parse::parse_ipv4_src;

// ===========================================================================
// Token Bucket Algorithm Tests
// ===========================================================================

#[test]
fn test_token_bucket_initial_burst_and_exhaustion() {
    let cfg = RateLimitConfig {
        max_pps: 10,
        refill_interval_ns: 1_000_000_000, // 1 second
    };

    let mut state = RateLimitValue {
        tokens: cfg.max_pps,
        last_refill_ns: 1_000_000,
    };

    // First 10 packets at the exact same timestamp should all be allowed
    for i in 0..10 {
        let allowed = evaluate_token_bucket(&mut state, 1_000_000, &cfg);
        assert!(
            allowed,
            "Packet {} should be allowed within burst capacity",
            i + 1
        );
    }

    assert_eq!(state.tokens, 0, "Bucket must be exhausted after 10 packets");

    // The 11th packet at the same timestamp must be DROPPED
    let dropped = evaluate_token_bucket(&mut state, 1_000_000, &cfg);
    assert!(!dropped, "11th packet must exceed rate limit and be dropped");
}

#[test]
fn test_token_bucket_partial_refill() {
    let cfg = RateLimitConfig {
        max_pps: 100,
        refill_interval_ns: 1_000_000_000, // 1 second
    };

    let mut state = RateLimitValue {
        tokens: 0,
        last_refill_ns: 100_000_000,
    };

    // 500ms elapsed (half interval) -> should replenish 50 tokens
    let now_ns = 600_000_000;
    let allowed = evaluate_token_bucket(&mut state, now_ns, &cfg);
    assert!(allowed, "First packet after 500ms refill must be allowed");
    assert_eq!(
        state.tokens, 49,
        "50 refilled tokens minus 1 consumed = 49 remaining"
    );
}

#[test]
fn test_token_bucket_full_refill() {
    let cfg = RateLimitConfig {
        max_pps: 50,
        refill_interval_ns: 1_000_000_000,
    };

    let mut state = RateLimitValue {
        tokens: 0,
        last_refill_ns: 10_000,
    };

    // Full 1 second elapsed -> bucket resets to capacity
    let now_ns = 10_000 + 1_000_000_000;
    let allowed = evaluate_token_bucket(&mut state, now_ns, &cfg);
    assert!(allowed, "Packet after full refill must be allowed");
    assert_eq!(
        state.tokens, 49,
        "Capacity 50 minus 1 consumed = 49 remaining"
    );
    assert_eq!(state.last_refill_ns, now_ns);
}

#[test]
fn test_token_bucket_large_elapsed_no_overflow() {
    let cfg = RateLimitConfig {
        max_pps: 1000,
        refill_interval_ns: 1_000_000_000,
    };

    let mut state = RateLimitValue {
        tokens: 0,
        last_refill_ns: 1_000_000,
    };

    // 10,000 seconds later (10 trillion ns)
    let now_ns = 1_000_000 + (10_000 * 1_000_000_000);
    let allowed = evaluate_token_bucket(&mut state, now_ns, &cfg);
    assert!(allowed);
    assert_eq!(
        state.tokens, 999,
        "Tokens capped at max_pps (1000) minus 1 consumed"
    );
}

#[test]
fn test_token_bucket_zero_elapsed_and_jitter() {
    let cfg = RateLimitConfig {
        max_pps: 5,
        refill_interval_ns: 1_000_000_000,
    };

    let mut state = RateLimitValue {
        tokens: 2,
        last_refill_ns: 500_000_000,
    };

    // Timestamp before last_refill_ns (e.g. clock jitter)
    let past_ns = 400_000_000;
    let allowed = evaluate_token_bucket(&mut state, past_ns, &cfg);
    assert!(allowed);
    assert_eq!(state.tokens, 1, "Consumed 1 token without underflow");
}

// ===========================================================================
// Packet Parsing Tests
// ===========================================================================

fn build_synthetic_ipv4_packet(src_ip: [u8; 4], dst_ip: [u8; 4]) -> [u8; 34] {
    let mut packet = [0u8; 34];

    // Ethernet Header (14 bytes)
    // Dst MAC: 00:11:22:33:44:55
    packet[0..6].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    // Src MAC: 66:77:88:99:aa:bb
    packet[6..12].copy_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]);
    // EtherType: IPv4 (0x0800)
    packet[12..14].copy_from_slice(&[0x08, 0x00]);

    // IPv4 Header (20 bytes)
    packet[14] = 0x45; // Version 4, IHL 5 (20 bytes)
    packet[15] = 0x00; // DSCP / ECN
    packet[16..18].copy_from_slice(&20u16.to_be_bytes()); // Total length
    packet[18..20].copy_from_slice(&1u16.to_be_bytes()); // Identification
    packet[20..22].copy_from_slice(&0u16.to_be_bytes()); // Flags / Fragment
    packet[22] = 64; // TTL
    packet[23] = 6; // Protocol: TCP
    packet[24..26].copy_from_slice(&0u16.to_be_bytes()); // Checksum
    packet[26..30].copy_from_slice(&src_ip);
    packet[30..34].copy_from_slice(&dst_ip);

    packet
}

#[test]
fn test_parse_valid_ipv4_src() {
    let packet = build_synthetic_ipv4_packet([192, 168, 1, 100], [10, 0, 0, 1]);
    let start = packet.as_ptr() as usize;
    let end = start + packet.len();

    let result = unsafe { parse_ipv4_src(start, end) };
    assert_eq!(
        result,
        Ok(Some(0xC0A80164)),
        "Must correctly parse 192.168.1.100 (0xC0A80164)"
    );
}

#[test]
fn test_parse_non_ipv4_arp() {
    let mut packet = [0u8; 28];
    // EtherType: ARP (0x0806)
    packet[12..14].copy_from_slice(&[0x08, 0x06]);
    let start = packet.as_ptr() as usize;
    let end = start + packet.len();

    let result = unsafe { parse_ipv4_src(start, end) };
    assert_eq!(result, Ok(None), "Non-IPv4 frame must return Ok(None)");
}

#[test]
fn test_parse_truncated_packet() {
    let packet = [0u8; 10]; // Smaller than Ethernet header (14 bytes)
    let start = packet.as_ptr() as usize;
    let end = start + packet.len();

    let result = unsafe { parse_ipv4_src(start, end) };
    assert!(result.is_err(), "Truncated packet must return Err(())");
}
