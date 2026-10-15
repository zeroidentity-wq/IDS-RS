// =============================================================================
// detector/whitelist.rs - IP-uri si subretele excluse din detectie
// =============================================================================

use std::net::IpAddr;

/// Intrare in whitelist: IP individual sau subnet CIDR.
///
/// Parsata din string-urile din config.toml la constructia Detector-ului.
/// Matching-ul CIDR se face prin bitmask: (ip & mask) == (network & mask).
#[derive(Debug, Clone)]
pub(super) enum WhitelistEntry {
    /// IP individual (ex: "10.0.1.10").
    Single(IpAddr),
    /// Subnet CIDR IPv4 (ex: "10.0.2.0/24"). Stocam adresa de retea si masca.
    CidrV4(u32, u32),
    /// Subnet CIDR IPv6 (ex: "fd00::/64"). Stocam adresa de retea si masca.
    CidrV6(u128, u128),
}

impl WhitelistEntry {
    /// Parseaza un string din config.toml intr-o intrare whitelist.
    /// Formatul validat deja in config.rs::validate().
    fn parse(entry: &str) -> Option<Self> {
        if entry.contains('/') {
            let parts: Vec<&str> = entry.splitn(2, '/').collect();
            let ip: IpAddr = parts[0].parse().ok()?;
            let prefix: u8 = parts[1].parse().ok()?;
            match ip {
                IpAddr::V4(addr) => {
                    let mask = if prefix == 0 {
                        0u32
                    } else {
                        !0u32 << (32 - prefix)
                    };
                    let network = u32::from(addr) & mask;
                    Some(WhitelistEntry::CidrV4(network, mask))
                }
                IpAddr::V6(addr) => {
                    let mask = if prefix == 0 {
                        0u128
                    } else {
                        !0u128 << (128 - prefix)
                    };
                    let network = u128::from(addr) & mask;
                    Some(WhitelistEntry::CidrV6(network, mask))
                }
            }
        } else {
            let ip: IpAddr = entry.parse().ok()?;
            Some(WhitelistEntry::Single(ip))
        }
    }

    /// Verifica daca un IP se potriveste cu aceasta intrare.
    pub(super) fn matches(&self, ip: &IpAddr) -> bool {
        match self {
            WhitelistEntry::Single(wl_ip) => wl_ip == ip,
            WhitelistEntry::CidrV4(network, mask) => {
                if let IpAddr::V4(addr) = ip {
                    (u32::from(*addr) & mask) == *network
                } else {
                    false
                }
            }
            WhitelistEntry::CidrV6(network, mask) => {
                if let IpAddr::V6(addr) = ip {
                    (u128::from(*addr) & mask) == *network
                } else {
                    false
                }
            }
        }
    }
}

/// Parseaza lista din config.toml; intrarile invalide (deja respinse de
/// validarea config-ului) sunt ignorate.
pub(super) fn parse_whitelist(entries: &[String]) -> Vec<WhitelistEntry> {
    entries
        .iter()
        .filter_map(|entry| WhitelistEntry::parse(entry))
        .collect()
}
