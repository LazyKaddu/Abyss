//! Integration tests for the abyss-core packet parser.
//!
//! Validates:
//! 1. Ethernet (L2) EtherType classification (IPv4, IPv6, ARP).
//! 2. IPv4 (L3) header parsing, IHL bounds checking, and IP options handling.
//! 3. IPv6 (L3) header parsing, next_hdr protocol resolution, and address extraction.
//! 4. Truncated packet rejection and memory safety.

use abyss_core::parse::parse_packet;
use network_types::{
    eth::EtherType,
    ip::IpProto,
};

/// Constructs a minimal valid Ethernet + IPv4 TCP packet buffer.
fn make_ipv4_tcp_packet(ihl_bytes: usize) -> [u8; 64] {
    let mut buf = [0u8; 64];
    // Ethernet Header: dst MAC [0..6], src MAC [6..12], EtherType = 0x0800 (IPv4)
    buf[12] = 0x08;
    buf[13] = 0x00;

    // IPv4 Header at offset 14:
    // vihl = version 4 (upper 4 bits) + ihl in 32-bit words (lower 4 bits)
    let ihl_words = (ihl_bytes / 4) as u8;
    buf[14] = (4 << 4) | (ihl_words & 0x0F);
    buf[15] = 0x00; // TOS
    buf[16] = 0x00; // Total length high
    buf[17] = 50;   // Total length low
    buf[23] = 6;    // Protocol = TCP (6)

    // Source IP: 192.168.1.100 (0xC0A80164)
    buf[26] = 192;
    buf[27] = 168;
    buf[28] = 1;
    buf[29] = 100;

    // Dest IP: 10.0.0.1 (0x0A000001)
    buf[30] = 10;
    buf[31] = 0;
    buf[32] = 0;
    buf[33] = 1;

    buf
}

/// Constructs a minimal valid Ethernet + IPv6 UDP packet buffer.
fn make_ipv6_udp_packet() -> [u8; 64] {
    let mut buf = [0u8; 64];
    // Ethernet Header: EtherType = 0x86DD (IPv6)
    buf[12] = 0x86;
    buf[13] = 0xDD;

    // IPv6 Header at offset 14 (40 bytes):
    // Version 6 (upper 4 bits of vcf[0])
    buf[14] = 0x60;
    // Payload length = 10
    buf[18] = 0x00;
    buf[19] = 0x0A;
    // Next header = UDP (17)
    buf[20] = 17;
    // Hop limit = 64
    buf[21] = 64;

    // Source IPv6: 2001:db8::1
    buf[22] = 0x20;
    buf[23] = 0x01;
    buf[24] = 0x0D;
    buf[25] = 0xB8;
    buf[37] = 0x01;

    // Dest IPv6: 2001:db8::2
    buf[38] = 0x20;
    buf[39] = 0x01;
    buf[40] = 0x0D;
    buf[41] = 0xB8;
    buf[53] = 0x02;

    buf
}

#[test]
fn test_parse_valid_ipv4_tcp() {
    let packet = make_ipv4_tcp_packet(20);
    let start = packet.as_ptr() as usize;
    let end = start + packet.len();

    let result = unsafe { parse_packet(start, end) };
    assert!(result.is_ok());
    let parsed = result.unwrap().expect("should parse IPv4 packet");

    assert_eq!(parsed.ether_type, EtherType::Ipv4);
    assert_eq!(parsed.ip_proto, IpProto::Tcp);
    assert_eq!(parsed.l4_offset, 14 + 20); // 34
    assert!(!parsed.is_ipv6);
    assert_eq!(parsed.src_v4, 0xC0A80164);
    assert_eq!(parsed.dst_v4, 0x0A000001);
}

#[test]
fn test_parse_valid_ipv4_with_options() {
    // IHL = 24 bytes (has 4 bytes of IP options)
    let packet = make_ipv4_tcp_packet(24);
    let start = packet.as_ptr() as usize;
    let end = start + packet.len();

    let result = unsafe { parse_packet(start, end) };
    assert!(result.is_ok());
    let parsed = result.unwrap().expect("should parse IPv4 with options");

    assert_eq!(parsed.ether_type, EtherType::Ipv4);
    assert_eq!(parsed.ip_proto, IpProto::Tcp);
    assert_eq!(parsed.l4_offset, 14 + 24); // 38
}

#[test]
fn test_parse_valid_ipv6_udp() {
    let packet = make_ipv6_udp_packet();
    let start = packet.as_ptr() as usize;
    let end = start + packet.len();

    let result = unsafe { parse_packet(start, end) };
    assert!(result.is_ok());
    let parsed = result.unwrap().expect("should parse IPv6 packet");

    assert_eq!(parsed.ether_type, EtherType::Ipv6);
    assert_eq!(parsed.ip_proto, IpProto::Udp);
    assert_eq!(parsed.l4_offset, 14 + 40); // 54
    assert!(parsed.is_ipv6);
    assert_eq!(parsed.src_v6[0..4], [0x20, 0x01, 0x0D, 0xB8]);
    assert_eq!(parsed.dst_v6[0..4], [0x20, 0x01, 0x0D, 0xB8]);
}

#[test]
fn test_parse_non_ip_packet_arp() {
    let mut packet = [0u8; 42];
    // EtherType = 0x0806 (ARP)
    packet[12] = 0x08;
    packet[13] = 0x06;

    let start = packet.as_ptr() as usize;
    let end = start + packet.len();

    let result = unsafe { parse_packet(start, end) };
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), None, "ARP frame should return None");
}

#[test]
fn test_truncated_ethernet_header() {
    let packet = [0u8; 10]; // Smaller than EthHdr::LEN (14)
    let start = packet.as_ptr() as usize;
    let end = start + packet.len();

    let result = unsafe { parse_packet(start, end) };
    assert!(result.is_err(), "Packet shorter than EthHdr must fail bounds check");
}

#[test]
fn test_truncated_ipv4_header() {
    let packet = make_ipv4_tcp_packet(20);
    let start = packet.as_ptr() as usize;
    // Truncate end to 25 bytes (EthHdr 14 + only 11 bytes of IPv4 header)
    let end = start + 25;

    let result = unsafe { parse_packet(start, end) };
    assert!(result.is_err(), "Truncated IPv4 header must fail bounds check");
}

#[test]
fn test_invalid_ihl_too_small() {
    let mut packet = make_ipv4_tcp_packet(20);
    // Set IHL to 3 words (12 bytes, invalid for IPv4)
    packet[14] = (4 << 4) | 3;

    let start = packet.as_ptr() as usize;
    let end = start + packet.len();

    let result = unsafe { parse_packet(start, end) };
    assert!(result.is_err(), "IHL < 20 bytes must be rejected");
}
