//! Packet parsing utilities for `abyss-tide`.
//!
//! Provides zero-copy, verifier-safe bounds-checked extraction of the
//! IPv4 source address for rate-limiting decisions.

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
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

/// Parses Ethernet and IPv4 headers to extract the source IPv4 address.
///
/// # Returns
/// - `Ok(Some(src_addr))` if packet is valid IPv4 within packet bounds.
/// - `Ok(None)` if packet is non-IPv4 (e.g. ARP, IPv6, 802.1Q) and should bypass rate limiting.
/// - `Err(())` if packet is truncated or malformed according to bounds checks.
#[inline(always)]
pub unsafe fn parse_ipv4_src(start: usize, end: usize) -> Result<Option<u32>, ()> {
    // 1. Parse Ethernet Header (14 bytes)
    let ethhdr: *const EthHdr = unsafe { ptr_at::<EthHdr>(start, end, 0)? };
    let ether_type = unsafe { (*ethhdr).ether_type() }.map_err(|_| ())?;

    if ether_type != EtherType::Ipv4 {
        return Ok(None);
    }

    // 2. Parse IPv4 Header
    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at::<Ipv4Hdr>(start, end, EthHdr::LEN)? };

    // Validate IHL (Internet Header Length) in bytes
    let ihl = unsafe { (*ipv4hdr).ihl() } as usize;
    if ihl < mem::size_of::<Ipv4Hdr>() {
        return Err(());
    }

    // Verify entire IPv4 header (including options) fits within packet bounds
    if start + EthHdr::LEN + ihl > end {
        return Err(());
    }

    // Extract IPv4 source address in network byte order as a u32
    let src_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });
    Ok(Some(src_addr))
}
