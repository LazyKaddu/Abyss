//! Unit and integration tests for `abyss-gaze` packet parser and signature scanner.

use abyss_common::dpi::{DpiAction, DpiSignature, MAX_SIGNATURE_LEN};
use abyss_gaze::{parse::parse_payload, scanner::match_signature};
use network_types::ip::IpProto;

// ===========================================================================
// Helper: Synthetic Packet Generators
// ===========================================================================

/// Builds a synthetic IPv4 TCP packet with the given payload.
fn build_synthetic_ipv4_tcp_packet(payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();

    // 1. Ethernet Header (14 bytes)
    packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Dst MAC
    packet.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]); // Src MAC
    packet.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

    // 2. IPv4 Header (20 bytes, no options)
    let ip_total_len = (20 + 20 + payload.len()) as u16;
    packet.push(0x45); // Version 4, IHL 5 (20 bytes)
    packet.push(0x00); // DSCP / ECN
    packet.extend_from_slice(&ip_total_len.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x01]); // Identification
    packet.extend_from_slice(&[0x00, 0x00]); // Flags / Fragment
    packet.push(64); // TTL
    packet.push(6); // Protocol: TCP (IpProto::Tcp)
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum
    packet.extend_from_slice(&[192, 168, 1, 100]); // Src IP: 192.168.1.100
    packet.extend_from_slice(&[10, 0, 0, 1]); // Dst IP: 10.0.0.1

    // 3. TCP Header (20 bytes, no options, doff = 5)
    packet.extend_from_slice(&8080u16.to_be_bytes()); // Src Port: 8080
    packet.extend_from_slice(&80u16.to_be_bytes()); // Dst Port: 80
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Seq num
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Ack num
    // Data Offset: 5 words (20 bytes) in high 4 bits; flags in low bits
    packet.push(0x50); // doff = 5 (20 bytes)
    packet.push(0x18); // Flags: PSH, ACK
    packet.extend_from_slice(&65535u16.to_be_bytes()); // Window
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum
    packet.extend_from_slice(&[0x00, 0x00]); // Urgent pointer

    // 4. Application Payload
    packet.extend_from_slice(payload);

    packet
}

/// Builds a synthetic IPv4 UDP packet with the given payload.
fn build_synthetic_ipv4_udp_packet(payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();

    // 1. Ethernet Header (14 bytes)
    packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    packet.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]);
    packet.extend_from_slice(&[0x08, 0x00]); // IPv4

    // 2. IPv4 Header (20 bytes)
    let ip_total_len = (20 + 8 + payload.len()) as u16;
    packet.push(0x45);
    packet.push(0x00);
    packet.extend_from_slice(&ip_total_len.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x01]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.push(64);
    packet.push(17); // Protocol: UDP (IpProto::Udp)
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[192, 168, 1, 50]);
    packet.extend_from_slice(&[10, 0, 0, 1]);

    // 3. UDP Header (8 bytes)
    let udp_len = (8 + payload.len()) as u16;
    packet.extend_from_slice(&5353u16.to_be_bytes()); // Src Port
    packet.extend_from_slice(&53u16.to_be_bytes()); // Dst Port: DNS (53)
    packet.extend_from_slice(&udp_len.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum

    // 4. Payload
    packet.extend_from_slice(payload);

    packet
}

/// Builds a synthetic IPv6 TCP packet with the given payload.
fn build_synthetic_ipv6_tcp_packet(payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();

    // 1. Ethernet Header (14 bytes)
    packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    packet.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]);
    packet.extend_from_slice(&[0x86, 0xDD]); // EtherType: IPv6 (0x86DD)

    // 2. IPv6 Header (40 bytes)
    packet.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // Version 6, Traffic Class 0, Flow Label 0
    let payload_len = (20 + payload.len()) as u16;
    packet.extend_from_slice(&payload_len.to_be_bytes());
    packet.push(6); // Next Header: TCP
    packet.push(64); // Hop Limit
    packet.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // Src IPv6
    packet.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]); // Dst IPv6

    // 3. TCP Header (20 bytes)
    packet.extend_from_slice(&9000u16.to_be_bytes()); // Src Port
    packet.extend_from_slice(&443u16.to_be_bytes()); // Dst Port
    packet.extend_from_slice(&[0, 0, 0, 1]);
    packet.extend_from_slice(&[0, 0, 0, 0]);
    packet.push(0x50); // doff = 5 (20 bytes)
    packet.push(0x18); // PSH, ACK
    packet.extend_from_slice(&65535u16.to_be_bytes());
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&[0, 0]);

    // 4. Payload
    packet.extend_from_slice(payload);

    packet
}

fn create_test_signature(pattern: &[u8], offset: u32, action: DpiAction) -> DpiSignature {
    let mut sig = DpiSignature {
        pattern: [0u8; MAX_SIGNATURE_LEN],
        pattern_len: pattern.len() as u8,
        action,
        _pad: [0; 2],
        payload_offset: offset,
    };
    sig.pattern[..pattern.len()].copy_from_slice(pattern);
    sig
}

// ===========================================================================
// Parser Tests
// ===========================================================================

#[test]
fn test_parse_valid_ipv4_tcp_payload() {
    let payload = b"GET /index.html HTTP/1.1\r\n";
    let packet = build_synthetic_ipv4_tcp_packet(payload);

    let start = packet.as_ptr() as usize;
    let end = start + packet.len();

    let info = unsafe { parse_payload(start, end) }
        .expect("Valid packet parsing must succeed")
        .expect("Must find application payload");

    assert_eq!(info.ip_proto, IpProto::Tcp);
    assert_eq!(info.src_port, 8080);
    assert_eq!(info.dst_port, 80);
    assert_eq!(info.len, payload.len());
    assert_eq!(info.offset, 14 + 20 + 20); // Eth(14) + IPv4(20) + TCP(20) = 54
}

#[test]
fn test_parse_valid_ipv4_udp_payload() {
    let payload = b"\x12\x34\x01\x00\x00\x01\x00\x00"; // DNS query sample
    let packet = build_synthetic_ipv4_udp_packet(payload);

    let start = packet.as_ptr() as usize;
    let end = start + packet.len();

    let info = unsafe { parse_payload(start, end) }
        .expect("Valid UDP packet must succeed")
        .expect("Must find UDP payload");

    assert_eq!(info.ip_proto, IpProto::Udp);
    assert_eq!(info.src_port, 5353);
    assert_eq!(info.dst_port, 53);
    assert_eq!(info.len, payload.len());
    assert_eq!(info.offset, 14 + 20 + 8); // Eth(14) + IPv4(20) + UDP(8) = 42
}

#[test]
fn test_parse_valid_ipv6_tcp_payload() {
    let payload = b"POST /api/v1/upload HTTP/1.1\r\n";
    let packet = build_synthetic_ipv6_tcp_packet(payload);

    let start = packet.as_ptr() as usize;
    let end = start + packet.len();

    let info = unsafe { parse_payload(start, end) }
        .expect("Valid IPv6 TCP packet must succeed")
        .expect("Must find IPv6 TCP payload");

    assert_eq!(info.ip_proto, IpProto::Tcp);
    assert_eq!(info.src_port, 9000);
    assert_eq!(info.dst_port, 443);
    assert_eq!(info.len, payload.len());
    assert_eq!(info.offset, 14 + 40 + 20); // Eth(14) + IPv6(40) + TCP(20) = 74
}

#[test]
fn test_parse_tcp_zero_payload_handshake() {
    // Pure TCP SYN / ACK without payload
    let packet = build_synthetic_ipv4_tcp_packet(&[]);

    let start = packet.as_ptr() as usize;
    let end = start + packet.len();

    let result = unsafe { parse_payload(start, end) };
    assert_eq!(
        result,
        Ok(None),
        "TCP packet with 0 payload must safely return Ok(None)"
    );
}

#[test]
fn test_parse_truncated_packet() {
    let packet = [0u8; 30]; // Truncated: less than Eth + IP + TCP (54 bytes)
    let start = packet.as_ptr() as usize;
    let end = start + packet.len();

    let result = unsafe { parse_payload(start, end) };
    assert!(result.is_err(), "Truncated packet must return Err(())");
}

// ===========================================================================
// Signature Scanner Tests
// ===========================================================================

#[test]
fn test_scanner_detects_directory_traversal() {
    let attack_payload = b"GET /../../etc/passwd HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let packet = build_synthetic_ipv4_tcp_packet(attack_payload);

    let start = packet.as_ptr() as usize;
    let end = start + packet.len();

    let info = unsafe { parse_payload(start, end) }.unwrap().unwrap();

    let sig = create_test_signature(b"../..", 0, DpiAction::Drop);
    let matched = match_signature(start, end, info.offset, info.len, &sig);
    assert!(matched, "DPI scanner must detect '../..' path traversal");
}

#[test]
fn test_scanner_detects_sensitive_file_request() {
    let attack_payload = b"GET /etc/passwd HTTP/1.1\r\nHost: vulnerable.test\r\n\r\n";
    let packet = build_synthetic_ipv4_tcp_packet(attack_payload);

    let start = packet.as_ptr() as usize;
    let end = start + packet.len();

    let info = unsafe { parse_payload(start, end) }.unwrap().unwrap();

    let sig = create_test_signature(b"/etc/passwd", 0, DpiAction::Drop);
    let matched = match_signature(start, end, info.offset, info.len, &sig);
    assert!(matched, "DPI scanner must detect '/etc/passwd' request");
}

#[test]
fn test_scanner_detects_sql_injection() {
    let attack_payload = b"GET /items?id=1 UNION SELECT 1,2 HTTP/1.1\r\n";
    let packet = build_synthetic_ipv4_tcp_packet(attack_payload);

    let start = packet.as_ptr() as usize;
    let end = start + packet.len();

    let info = unsafe { parse_payload(start, end) }.unwrap().unwrap();

    let sig = create_test_signature(b"UNION SELECT", 0, DpiAction::Drop);
    let matched = match_signature(start, end, info.offset, info.len, &sig);
    assert!(matched, "DPI scanner must detect 'UNION SELECT' SQLi");
}

#[test]
fn test_scanner_allows_benign_traffic() {
    let benign_payload = b"GET /index.html HTTP/1.1\r\nHost: secure.org\r\n\r\n";
    let packet = build_synthetic_ipv4_tcp_packet(benign_payload);

    let start = packet.as_ptr() as usize;
    let end = start + packet.len();

    let info = unsafe { parse_payload(start, end) }.unwrap().unwrap();

    let sig_traversal = create_test_signature(b"../..", 0, DpiAction::Drop);
    let sig_sqli = create_test_signature(b"UNION SELECT", 0, DpiAction::Drop);
    let sig_passwd = create_test_signature(b"/etc/passwd", 0, DpiAction::Drop);

    assert!(!match_signature(start, end, info.offset, info.len, &sig_traversal));
    assert!(!match_signature(start, end, info.offset, info.len, &sig_sqli));
    assert!(!match_signature(start, end, info.offset, info.len, &sig_passwd));
}

#[test]
fn test_scanner_anchored_matching() {
    let payload = b"POST /api/v1/auth HTTP/1.1\r\n";
    let packet = build_synthetic_ipv4_tcp_packet(payload);

    let start = packet.as_ptr() as usize;
    let end = start + packet.len();

    let info = unsafe { parse_payload(start, end) }.unwrap().unwrap();

    // Match "POST" anchored at offset 0
    let sig_post = create_test_signature(b"POST", 0, DpiAction::Drop);
    assert!(match_signature(start, end, info.offset, info.len, &sig_post));

    // Match "auth" anchored at offset 13 ("/api/v1/auth" has 'auth' at index 13)
    let sig_auth = create_test_signature(b"auth", 13, DpiAction::Drop);
    assert!(match_signature(start, end, info.offset, info.len, &sig_auth));

    // Incorrect anchor: "POST" at offset 5 should NOT match
    let sig_bad_anchor = create_test_signature(b"POST", 5, DpiAction::Drop);
    assert!(!match_signature(start, end, info.offset, info.len, &sig_bad_anchor));
}

#[test]
fn test_scanner_udp_payload() {
    let attack_payload = b"DNS_QUERY: /etc/passwd request";
    let packet = build_synthetic_ipv4_udp_packet(attack_payload);

    let start = packet.as_ptr() as usize;
    let end = start + packet.len();

    let info = unsafe { parse_payload(start, end) }.unwrap().unwrap();

    let sig = create_test_signature(b"/etc/passwd", 0, DpiAction::Drop);
    assert!(match_signature(start, end, info.offset, info.len, &sig));
}
