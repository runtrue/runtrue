use std::net::IpAddr;

pub(crate) fn forbidden_address(address: IpAddr, deny_private_ranges: bool) -> bool {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            let always_denied = octets == [255, 255, 255, 255]
                || octets[0] == 0
                || (224..=255).contains(&octets[0]);
            always_denied || deny_private_ranges && !global_ipv4(octets)
        }
        IpAddr::V6(address) => {
            let segments = address.segments();
            let always_denied = address.is_unspecified() || address.is_multicast();
            always_denied || deny_private_ranges && !global_ipv6(segments)
        }
    }
}

fn global_ipv4(octets: [u8; 4]) -> bool {
    !(octets[0] == 10
        || octets[0] == 127
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 169 && octets[1] == 254)
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113))
}

fn global_ipv6(segments: [u16; 8]) -> bool {
    // Restrict private-deny mode to ordinary 2000::/3 global unicast and
    // exclude the documentation prefix 2001:db8::/32.
    segments[0] & 0xe000 == 0x2000 && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
}
