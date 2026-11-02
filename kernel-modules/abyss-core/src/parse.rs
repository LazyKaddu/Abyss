//! Packet parsing engine for `abyss-core`.
//!
//! Provides zero-copy, bounds-checked parsing of Ethernet (L2),
//! IPv4 (L3), and IPv6 (L3) packet headers.
//!
//! # Verifier Safety
//! The Linux kernel eBPF verifier strictly requires that every memory access
//! into packet memory is bounded by explicit comparisons against the end of packet data.
//! The [`ptr_at`] helper enforces this invariant (`start + offset + size <= end`).

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
};

/// Summary of protocol classification and header offsets extracted from a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParsedPacket {
    /// Layer 2 encapsulated protocol (IPv4, IPv6, etc.).
    pub ether_type: EtherType,
    /// Layer 3 IP protocol (TCP, UDP, ICMP, etc.).
    pub ip_proto: IpProto,
    /// Byte offset from packet start where Layer 4 (TCP/UDP/payload) begins.
    pub l4_offset: usize,
    /// True if IPv6, false if IPv4.
    pub is_ipv6: bool,
    /// Source IPv4 address (host byte order), or 0 if IPv6/non-IP.
    pub src_v4: u32,
    /// Destination IPv4 address (host byte order), or 0 if IPv6/non-IP.
    pub dst_v4: u32,
    /// Source IPv6 address (16 bytes), or [0; 16] if IPv4/non-IP.
    pub src_v6: [u8; 16],
    /// Destination IPv6 address (16 bytes), or [0; 16] if IPv4/non-IP.
    pub dst_v6: [u8; 16],
}

impl Default for ParsedPacket {
    fn default() -> Self {
        Self {
            ether_type: EtherType::Ipv4,
            ip_proto: IpProto::Tcp,
            l4_offset: 0,
            is_ipv6: false,
            src_v4: 0,
            dst_v4: 0,
            src_v6: [0; 16],
            dst_v6: [0; 16],
        }
    }
}

/// Safely returns a typed pointer to packet data at a given offset if within bounds.
///
/// # Verifier Safety
/// Explicitly ensures `start + offset + size_of::<T>() <= end`.
/// If the requested span exceeds the packet boundary, returns `Err(())`.
#[inline(always)]
pub unsafe fn ptr_at<T>(start: usize, end: usize, offset: usize) -> Result<*const T, ()> {
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

/// Parses Ethernet and L3 (IPv4 / IPv6) headers using raw packet boundary pointers.
///
/// # Returns
/// - `Ok(Some(ParsedPacket))` if packet is valid IPv4 or IPv6 with all headers within bounds.
/// - `Ok(None)` if packet is non-IP (e.g. ARP, 802.1Q) and should be passed safely.
/// - `Err(())` if packet is truncated or malformed according to bounds checks.
#[inline(always)]
pub unsafe fn parse_packet(start: usize, end: usize) -> Result<Option<ParsedPacket>, ()> {
    // 1. Layer 2: Parse Ethernet Header (14 bytes)
    let ethhdr: *const EthHdr = unsafe { ptr_at::<EthHdr>(start, end, 0)? };
    let ether_type = unsafe { (*ethhdr).ether_type() }.map_err(|_| ())?;

    match ether_type {
        EtherType::Ipv4 => {
            // 2. Layer 3: Parse IPv4 Header
            let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at::<Ipv4Hdr>(start, end, EthHdr::LEN)? };
            let ip_proto = unsafe { (*ipv4hdr).proto() }.map_err(|_| ())?;

            // Validate IHL (Internet Header Length) in bytes
            let ihl = unsafe { (*ipv4hdr).ihl() } as usize;
            if ihl < mem::size_of::<Ipv4Hdr>() {
                return Err(());
            }

            // Verify entire IPv4 header (including IP options) fits within packet bounds
            if start + EthHdr::LEN + ihl > end {
                return Err(());
            }

            let l4_offset = EthHdr::LEN + ihl;
            let src_v4 = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });
            let dst_v4 = u32::from_be_bytes(unsafe { (*ipv4hdr).dst_addr });

            Ok(Some(ParsedPacket {
                ether_type: EtherType::Ipv4,
                ip_proto,
                l4_offset,
                is_ipv6: false,
                src_v4,
                dst_v4,
                src_v6: [0; 16],
                dst_v6: [0; 16],
            }))
        }
        EtherType::Ipv6 => {
            // 2. Layer 3: Parse IPv6 Header (fixed 40 bytes)
            let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at::<Ipv6Hdr>(start, end, EthHdr::LEN)? };
            let ip_proto = unsafe { (*ipv6hdr).next_hdr() }.map_err(|_| ())?;
            let l4_offset = EthHdr::LEN + mem::size_of::<Ipv6Hdr>();

            let src_v6 = unsafe { (*ipv6hdr).src_addr };
            let dst_v6 = unsafe { (*ipv6hdr).dst_addr };

            Ok(Some(ParsedPacket {
                ether_type: EtherType::Ipv6,
                ip_proto,
                l4_offset,
                is_ipv6: true,
                src_v4: 0,
                dst_v4: 0,
                src_v6,
                dst_v6,
            }))
        }
        _ => {
            // Valid Ethernet frame but non-IP (e.g. ARP, VLAN)
            Ok(None)
        }
    }
}

