use std::io::{self, BufRead};
use std::net::IpAddr;

pub const MAX_IPBAN_ENTRIES: usize = 250_000;

/// Immutable exact-IP lookup independent of the expiring ban registry.
#[derive(Default)]
pub struct IpBanSet {
    ipv4: Vec<u32>,
    ipv6: Vec<u128>,
}

impl IpBanSet {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip.to_canonical() {
            IpAddr::V4(ip) => self.ipv4.binary_search(&u32::from(ip)).is_ok(),
            IpAddr::V6(ip) => self.ipv6.binary_search(&u128::from(ip)).is_ok(),
        }
    }

    pub fn len(&self) -> usize {
        self.ipv4.len() + self.ipv6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Accept one exact address per line and optional `#` comments. A malformed
    /// non-comment line invalidates the entire update, preserving the old set.
    pub fn parse(reader: impl BufRead) -> io::Result<Self> {
        let mut result = Self::default();
        for line in reader.lines() {
            let line = line?;
            let value = line.split('#').next().unwrap_or("").trim();
            if value.is_empty() {
                continue;
            }
            let ip: IpAddr = value
                .parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid ipban address"))?;
            match ip.to_canonical() {
                IpAddr::V4(ip) => result.ipv4.push(u32::from(ip)),
                IpAddr::V6(ip) => result.ipv6.push(u128::from(ip)),
            }
            if result.len() > MAX_IPBAN_ENTRIES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ipban entry limit exceeded",
                ));
            }
        }
        result.ipv4.sort_unstable();
        result.ipv4.dedup();
        result.ipv6.sort_unstable();
        result.ipv6.dedup();
        if result.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "empty ipban list",
            ));
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_comments_deduplicates_and_rejects_partial_lists() {
        let list = IpBanSet::parse(
            b"# header\n1.2.3.4 # country and ASN\n1.2.3.4\n2001:db8::1 # v6\n".as_slice(),
        )
        .unwrap();
        assert_eq!(list.len(), 2);
        assert!(list.contains("1.2.3.4".parse().unwrap()));
        assert!(list.contains("2001:db8::1".parse().unwrap()));
        assert!(!list.contains("1.2.3.5".parse().unwrap()));
        for input in [
            "# only comments\n",
            "1.2.3.4\nnot-an-ip\n",
            "1.2.3.4 extra\n",
        ] {
            assert!(IpBanSet::parse(input.as_bytes()).is_err());
        }
    }

    #[test]
    fn hundred_thousand_ipv4_addresses_fit_in_a_compact_lookup() {
        use std::fmt::Write;
        let mut feed = String::new();
        for value in 0..100_000u32 {
            writeln!(
                &mut feed,
                "10.{}.{}.{}",
                value >> 16,
                value >> 8 & 255,
                value & 255
            )
            .unwrap();
        }
        let set = IpBanSet::parse(feed.as_bytes()).unwrap();
        assert_eq!(set.len(), 100_000);
        assert!(set.contains("10.1.134.159".parse().unwrap()));
        assert!(!set.contains("10.1.134.160".parse().unwrap()));
        assert!(set.ipv4.capacity() * std::mem::size_of::<u32>() < 1024 * 1024);
    }
}
