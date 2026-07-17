use std::collections::HashMap;
use std::net::Ipv4Addr;

use serde::Serialize;

use arp_common::Event;

#[derive(Debug, Clone, Serialize)]
pub struct SpoofAlert {
    pub ip: String,
    pub previous_mac: String,
    pub new_mac: String,
    pub change_count: u32,
}

#[derive(Debug)]
struct MacEntry {
    mac: [u8; 6],
    change_count: u32,
}

/// Maximum number of IP entries tracked to prevent memory exhaustion.
/// An attacker flooding unique IPs could otherwise grow the table indefinitely.
const MAX_TABLE_ENTRIES: usize = 65536;

pub struct ArpTable {
    entries: HashMap<Ipv4Addr, MacEntry>,
    threshold: u32,
    whitelist: HashMap<Ipv4Addr, [u8; 6]>,
}

impl ArpTable {
    pub fn new(threshold: u32, whitelist: HashMap<Ipv4Addr, [u8; 6]>) -> Self {
        Self {
            entries: HashMap::new(),
            threshold,
            whitelist,
        }
    }

    pub fn check_event(&mut self, event: &Event) -> Option<SpoofAlert> {
        let ip = Ipv4Addr::from(event.ar_sip);
        let mac = event.ar_sha;

        // Skip whitelisted entries
        if let Some(trusted_mac) = self.whitelist.get(&ip) {
            if *trusted_mac == mac {
                return None;
            }
            // Whitelisted IP with wrong MAC — always alert
            return Some(SpoofAlert {
                ip: ip.to_string(),
                previous_mac: format_mac(trusted_mac),
                new_mac: format_mac(&mac),
                change_count: 1,
            });
        }

        match self.entries.get_mut(&ip) {
            Some(entry) => {
                if entry.mac != mac {
                    let previous_mac = format_mac(&entry.mac);
                    entry.mac = mac;
                    entry.change_count += 1;

                    if entry.change_count >= self.threshold {
                        return Some(SpoofAlert {
                            ip: ip.to_string(),
                            previous_mac,
                            new_mac: format_mac(&mac),
                            change_count: entry.change_count,
                        });
                    }
                }
                None
            }
            None => {
                // Evict oldest entry if table is full (prevent memory exhaustion)
                if self.entries.len() >= MAX_TABLE_ENTRIES {
                    if let Some(&oldest_ip) = self.entries.keys().next() {
                        self.entries.remove(&oldest_ip);
                    }
                }
                self.entries.insert(
                    ip,
                    MacEntry {
                        mac,
                        change_count: 0,
                    },
                );
                None
            }
        }
    }
}

fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(ip: [u8; 4], mac: [u8; 6]) -> Event {
        Event {
            ar_op: 2, // Reply
            ar_sha: mac,
            ar_sip: ip,
            ar_tha: [0xff; 6],
            ar_tip: [192, 168, 1, 100],
        }
    }

    #[test]
    fn test_first_seen_no_alert() {
        let mut table = ArpTable::new(1, HashMap::new());
        let event = make_event([192, 168, 1, 1], [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
        assert!(table.check_event(&event).is_none());
    }

    #[test]
    fn test_same_mac_no_alert() {
        let mut table = ArpTable::new(1, HashMap::new());
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01];
        let event = make_event([192, 168, 1, 1], mac);
        table.check_event(&event);
        assert!(table.check_event(&event).is_none());
    }

    #[test]
    fn test_mac_change_triggers_alert() {
        let mut table = ArpTable::new(1, HashMap::new());
        let ip = [192, 168, 1, 1];
        let mac1 = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01];
        let mac2 = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

        table.check_event(&make_event(ip, mac1));
        let alert = table.check_event(&make_event(ip, mac2));

        assert!(alert.is_some());
        let a = alert.unwrap();
        assert_eq!(a.ip, "192.168.1.1");
        assert_eq!(a.previous_mac, "aa:bb:cc:dd:ee:01");
        assert_eq!(a.new_mac, "11:22:33:44:55:66");
    }

    #[test]
    fn test_threshold_higher_than_one() {
        let mut table = ArpTable::new(2, HashMap::new());
        let ip = [192, 168, 1, 1];
        let mac1 = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01];
        let mac2 = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let mac3 = [0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc];

        table.check_event(&make_event(ip, mac1));
        // First change: count=1, threshold=2 → no alert
        assert!(table.check_event(&make_event(ip, mac2)).is_none());
        // Second change: count=2, threshold=2 → alert
        let alert = table.check_event(&make_event(ip, mac3));
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().change_count, 2);
    }

    #[test]
    fn test_whitelist_trusted_mac_no_alert() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let trusted_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01];
        let mut whitelist = HashMap::new();
        whitelist.insert(ip, trusted_mac);

        let mut table = ArpTable::new(1, whitelist);
        let event = make_event([192, 168, 1, 1], trusted_mac);
        assert!(table.check_event(&event).is_none());
    }

    #[test]
    fn test_whitelist_wrong_mac_alerts() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let trusted_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01];
        let mut whitelist = HashMap::new();
        whitelist.insert(ip, trusted_mac);

        let mut table = ArpTable::new(1, whitelist);
        let evil_mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let alert = table.check_event(&make_event([192, 168, 1, 1], evil_mac));
        assert!(alert.is_some());
    }
}
