//! FR-023 destination policy (coordinator-owned, frozen; CR-022).
//!
//! Shared by every backend: the Linux egress proxy, the Windows firewall
//! rules and the report. Only public unicast addresses are allowed; an
//! IPv4-mapped, IPv4-compatible or NAT64 IPv6 address is judged by the IPv4
//! address it carries, so a DNS answer cannot smuggle a local address.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// True when a sandboxed script may connect to `ip`.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_public(v4),
        IpAddr::V6(v6) => v6_public(v6),
    }
}

fn v4_public(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || a == 0
        || (a == 100 && (64..128).contains(&b)) // CGNAT 100.64/10
        || (a == 192 && b == 0 && c == 0) // IETF 192.0.0/24
        || (a == 198 && (b == 18 || b == 19)) // benchmarking 198.18/15
        || a >= 240) // reserved 240/4
}

fn v6_public(ip: Ipv6Addr) -> bool {
    if let Some(v4) = embedded_v4(ip) {
        return v4_public(v4);
    }
    let s = ip.segments();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00 // unique local fc00::/7 (incl. fd00:ec2::254)
        || (s[0] & 0xffc0) == 0xfe80 // link local fe80::/10
        || (s[0] & 0xffc0) == 0xfec0 // site local fec0::/10 (deprecated)
        || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
        || (s[0] & 0xe000) != 0x2000) // only global unicast 2000::/3 is public
}

/// IPv4 carried inside an IPv6 address: mapped `::ffff:a.b.c.d`, compatible
/// `::a.b.c.d`, or NAT64 `64:ff9b::a.b.c.d`.
fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = ip.segments();
    let tail = Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8);
    let mapped = s[..5] == [0; 5] && s[5] == 0xffff;
    let compatible = s[..6] == [0; 6] && !ip.is_loopback() && !ip.is_unspecified();
    let nat64 = s[..6] == [0x64, 0xff9b, 0, 0, 0, 0];
    (mapped || compatible || nat64).then_some(tail)
}

#[cfg(test)]
mod tests {
    use super::is_public;

    fn ok(s: &str) -> bool {
        is_public(s.parse().unwrap())
    }

    #[test]
    fn only_public_unicast_is_allowed() {
        for allowed in [
            "104.16.0.35",
            "8.8.8.8",
            "2606:4700::6810:2223",
            "2001:4860:4860::8888",
        ] {
            assert!(ok(allowed), "{allowed}");
        }
        for refused in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.10",
            "100.64.0.1",
            "169.254.169.254",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.251",
            "192.0.2.1",
            "198.18.0.1",
            "240.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd00:ec2::254",
            "ff02::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::a9fe:a9fe",
            "::7f00:1",
        ] {
            assert!(!ok(refused), "{refused}");
        }
        assert!(ok("::ffff:8.8.8.8"));
    }
}
