//! Zero-copy, verifier-safe L4 application payload parsing for `abyss-gaze`.
//!
//! Traverses Layer 2 (Ethernet), Layer 3 (IPv4 / IPv6), and Layer 4 (TCP / UDP)
//! headers with explicit bounds checking to identify the application payload boundaries.

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

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

/// Metadata and boundary information for an extracted application-layer payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayloadInfo {
    /// Byte offset from packet `start` where the application payload begins.
    pub offset: usize,
    /// Total length in bytes of the application payload within packet boundaries.
    pub len: usize,
    /// Transport protocol (TCP or UDP).
    pub ip_proto: IpProto,
    /// Source transport port (host byte order).
    pub src_port: u16,
    /// Destination transport port (host byte order).
    pub dst_port: u16,
}

/// Parses Ethernet, IP (v4/v6), and L4 (TCP/UDP) headers to locate application payload.
///
/// # Returns
/// - `Ok(Some(PayloadInfo))` if packet is TCP or UDP containing at least 1 byte of application payload.
/// - `Ok(None)` if packet is non-IP, non-TCP/UDP, or has zero application payload (e.g. pure SYN/ACK).
/// - `Err(())` if packet is truncated or malformed according to bounds checks.
#[inline(always)]
pub unsafe fn parse_payload(start: usize, end: usize) -> Result<Option<PayloadInfo>, ()> {
    // 1. Layer 2: Parse Ethernet Header (14 bytes)
    let ethhdr: *const EthHdr = unsafe { ptr_at::<EthHdr>(start, end, 0)? };
    let ether_type = unsafe { (*ethhdr).ether_type() }.map_err(|_| ())?;

    // 2. Layer 3: Parse IPv4 or IPv6 Header
    let (l4_offset, ip_proto) = match ether_type {
        EtherType::Ipv4 => {
            let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at::<Ipv4Hdr>(start, end, EthHdr::LEN)? };
            let ihl = unsafe { (*ipv4hdr).ihl() } as usize;
            if ihl < mem::size_of::<Ipv4Hdr>() {
                return Err(());
            }
            if start + EthHdr::LEN + ihl > end {
                return Err(());
            }
            let proto = unsafe { (*ipv4hdr).proto() }.map_err(|_| ())?;
            (EthHdr::LEN + ihl, proto)
        }

        EtherType::Ipv6 => {
            let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at::<Ipv6Hdr>(start, end, EthHdr::LEN)? };
            let ip_hdr_len = mem::size_of::<Ipv6Hdr>();
            if start + EthHdr::LEN + ip_hdr_len > end {
                return Err(());
            }
            let proto = unsafe { (*ipv6hdr).next_hdr() }.map_err(|_| ())?;
            (EthHdr::LEN + ip_hdr_len, proto)
        }
        _ => return Ok(None), // Non-IP frame (e.g. ARP, VLAN)
    };

    // 3. Layer 4: Parse TCP or UDP Header
    let (payload_offset, src_port, dst_port) = match ip_proto {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = unsafe { ptr_at::<TcpHdr>(start, end, l4_offset)? };
            let doff = unsafe { (*tcphdr).doff() } as usize;
            if doff < 5 {
                return Err(());
            }
            let tcp_hdr_len = doff * 4;
            if start + l4_offset + tcp_hdr_len > end {
                return Err(());
            }
            let src = u16::from_be_bytes(unsafe { (*tcphdr).source });
            let dst = u16::from_be_bytes(unsafe { (*tcphdr).dest });
            (l4_offset + tcp_hdr_len, src, dst)
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = unsafe { ptr_at::<UdpHdr>(start, end, l4_offset)? };
            if start + l4_offset + UdpHdr::LEN > end {
                return Err(());
            }
            let src = unsafe { (*udphdr).src_port() };
            let dst = unsafe { (*udphdr).dst_port() };
            (l4_offset + UdpHdr::LEN, src, dst)
        }
        _ => return Ok(None), // Non-TCP/UDP protocol (e.g. ICMP, IGMP)
    };

    // 4. Compute Payload Length
    if start + payload_offset >= end {
        return Ok(None); // Header only, no L7 payload (e.g. TCP SYN/ACK/FIN)
    }

    let payload_len = end - (start + payload_offset);
    if payload_len == 0 {
        return Ok(None);
    }

    Ok(Some(PayloadInfo {
        offset: payload_offset,
        len: payload_len,
        ip_proto,
        src_port,
        dst_port,
    }))
}
