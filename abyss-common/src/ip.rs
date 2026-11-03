//! IPv4 parsing and formatting utilities for `#![no_std]` and user-space.

/// Converts a dotted-quad IPv4 string slice (e.g. `"192.168.1.1"`) to a `u32` (big-endian/network representation).
pub fn parse_ipv4_addr(s: &str) -> Result<u32, ()> {
    let bytes = s.as_bytes();
    let mut octets = [0u8; 4];
    let mut octet_idx = 0;
    let mut current: u16 = 0;
    let mut has_digits = false;

    for &b in bytes {
        if b == b'.' {
            if !has_digits || octet_idx >= 3 || current > 255 {
                return Err(());
            }
            octets[octet_idx] = current as u8;
            octet_idx += 1;
            current = 0;
            has_digits = false;
        } else if b.is_ascii_digit() {
            current = current.checked_mul(10).ok_or(())?.checked_add((b - b'0') as u16).ok_or(())?;
            has_digits = true;
        } else {
            return Err(());
        }
    }

    if !has_digits || octet_idx != 3 || current > 255 {
        return Err(());
    }
    octets[3] = current as u8;

    Ok(u32::from_be_bytes(octets))
}

/// Converts a `u32` representation of an IPv4 address into its 4 octets `[u8; 4]`.
#[inline(always)]
pub fn u32_to_octets(ip: u32) -> [u8; 4] {
    ip.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_valid() {
        assert_eq!(parse_ipv4_addr("127.0.0.1"), Ok(0x7F000001));
        assert_eq!(parse_ipv4_addr("192.168.1.1"), Ok(0xC0A80101));
        assert_eq!(parse_ipv4_addr("0.0.0.0"), Ok(0x00000000));
        assert_eq!(parse_ipv4_addr("255.255.255.255"), Ok(0xFFFFFFFF));
    }

    #[test]
    fn test_parse_ipv4_invalid() {
        assert!(parse_ipv4_addr("").is_err());
        assert!(parse_ipv4_addr("1.2.3").is_err());
        assert!(parse_ipv4_addr("1.2.3.4.5").is_err());
        assert!(parse_ipv4_addr("256.0.0.1").is_err());
        assert!(parse_ipv4_addr("1.2.3.a").is_err());
        assert!(parse_ipv4_addr("1..2.3").is_err());
    }

    #[test]
    fn test_u32_to_octets() {
        assert_eq!(u32_to_octets(0xC0A80101), [192, 168, 1, 1]);
    }
}

