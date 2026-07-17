mod detection;

use std::collections::HashMap;
use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use aya::maps::RingBuf;
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::{include_bytes_aligned, Ebpf};
use aya_log::EbpfLogger;
use clap::Parser;
use serde::Serialize;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::signal;
use tracing::{debug, error, info, warn};

use arp_common::Event;
use detection::{ArpTable, SpoofAlert};

#[derive(Debug, Parser)]
#[command(name = "arp-monitor", about = "eBPF-powered ARP traffic monitor with spoofing detection")]
struct Opt {
    /// Network interface to attach to
    #[arg(short, long, default_value = "eth0")]
    iface: String,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Output events as JSON
    #[arg(long)]
    json: bool,

    /// Trusted IP-MAC pairs (format: IP=MAC, e.g. 192.168.1.1=aa:bb:cc:dd:ee:ff)
    #[arg(long, value_name = "IP=MAC")]
    whitelist: Vec<String>,

    /// Number of MAC changes for the same IP before alerting (default: 1)
    #[arg(long, default_value = "1")]
    spoof_threshold: u32,
}

#[derive(Serialize)]
struct ArpEvent {
    timestamp: String,
    opcode: &'static str,
    sender_mac: String,
    sender_ip: String,
    target_mac: String,
    target_ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    alert: Option<SpoofAlert>,
}

fn opcode_to_text(opcode: u16) -> &'static str {
    match opcode {
        1 => "Request",
        2 => "Reply",
        3 => "RARP-Request",
        4 => "RARP-Reply",
        _ => "Unknown",
    }
}

fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn format_ip(ip: &[u8; 4]) -> String {
    Ipv4Addr::from(*ip).to_string()
}

fn parse_whitelist(entries: &[String]) -> Result<HashMap<Ipv4Addr, [u8; 6]>> {
    let mut map = HashMap::new();
    for entry in entries {
        let parts: Vec<&str> = entry.splitn(2, '=').collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid whitelist entry '{}'. Expected format: IP=MAC", entry);
        }
        let ip: Ipv4Addr = parts[0]
            .parse()
            .with_context(|| format!("Invalid IP in whitelist: {}", parts[0]))?;
        let mac = parse_mac(parts[1])
            .with_context(|| format!("Invalid MAC in whitelist: {}", parts[1]))?;
        map.insert(ip, mac);
    }
    Ok(map)
}

fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        anyhow::bail!("MAC address must have 6 octets separated by ':'");
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)
            .with_context(|| format!("Invalid hex octet: {}", part))?;
    }
    Ok(mac)
}

fn bump_memlock_rlimit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("Failed to remove memlock rlimit (ret={}), may fail on older kernels", ret);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();

    // Initialize tracing
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| {
                    if opt.verbose {
                        "arp=debug".into()
                    } else {
                        "arp=info".into()
                    }
                }),
        );

    if opt.json {
        subscriber.json().init();
    } else {
        subscriber.init();
    }

    info!(interface = %opt.iface, "Starting ARP monitor");

    // Parse whitelist
    let whitelist = parse_whitelist(&opt.whitelist)
        .context("Failed to parse whitelist")?;
    if !whitelist.is_empty() {
        info!(count = whitelist.len(), "Loaded trusted IP-MAC entries");
    }

    // Initialize ARP spoofing detection table
    let mut arp_table = ArpTable::new(opt.spoof_threshold, whitelist);

    bump_memlock_rlimit();

    // Load eBPF program
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/arp"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/arp"
    ))?;

    match EbpfLogger::init(&mut bpf) {
        Ok(logger) => {
            // aya-log 0.3: EbpfLogger::init returns the logger fd.
            // Spawn async flusher using AsyncFd for efficient polling.
            let async_fd = AsyncFd::with_interest(logger, Interest::READABLE)
                .expect("Failed to create AsyncFd for eBPF logger");
            tokio::task::spawn(async move {
                let mut async_fd = async_fd;
                loop {
                    let mut guard = async_fd.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
        Err(e) => {
            warn!("Failed to initialize eBPF logger: {}", e);
        }
    }

    // Attach TC classifier
    let _ = tc::qdisc_add_clsact(&opt.iface);
    let program: &mut SchedClassifier = bpf
        .program_mut("arp")
        .context("eBPF program 'arp' not found")?
        .try_into()?;
    program.load()?;

    program
        .attach(&opt.iface, TcAttachType::Egress)
        .context("Failed to attach TC egress")?;
    program
        .attach(&opt.iface, TcAttachType::Ingress)
        .context("Failed to attach TC ingress")?;

    info!(interface = %opt.iface, "eBPF program attached (TC ingress + egress)");

    // Open ring buffer
    let mut ring_buf = RingBuf::try_from(
        bpf.map_mut("RINGBUF")
            .context("Ring buffer map 'RINGBUF' not found")?,
    )
    .context("Failed to create RingBuf")?;

    if !opt.json {
        println!(
            "{:<12} {:<10} {:<20} {:<18} {:<20} {:<18}",
            "TIME", "TYPE", "SENDER MAC", "SENDER IP", "TARGET MAC", "TARGET IP"
        );
    }

    info!("Monitoring ARP traffic. Press Ctrl+C to stop.");

    // Event loop with graceful shutdown
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Received Ctrl+C, shutting down...");
                break;
            }
            _ = tokio::task::yield_now() => {
                while let Some(event_data) = ring_buf.next() {
                    let data = &*event_data;
                    if data.len() < std::mem::size_of::<Event>() {
                        warn!(len = data.len(), "Received undersized event");
                        continue;
                    }

                    // Safety: we verified length >= size_of::<Event>() above.
                    // Event is #[repr(C)] with only primitive fields, so any bit
                    // pattern is valid and alignment of 1-byte arrays is always met.
                    // The ring buffer guarantees 8-byte alignment for reserved entries.
                    let event: &Event = unsafe {
                        let ptr = data.as_ptr() as *const Event;
                        debug_assert!(ptr.is_aligned(), "Event pointer misaligned");
                        &*ptr
                    };

                    let ts = chrono::Local::now().format("%H:%M:%S").to_string();
                    let sender_mac = format_mac(&event.ar_sha);
                    let sender_ip = format_ip(&event.ar_sip);
                    let target_mac = format_mac(&event.ar_tha);
                    let target_ip = format_ip(&event.ar_tip);

                    // ARP spoofing detection
                    let alert = arp_table.check_event(event);
                    if let Some(ref a) = alert {
                        error!(
                            ip = %a.ip,
                            previous_mac = %a.previous_mac,
                            new_mac = %a.new_mac,
                            changes = a.change_count,
                            "ARP SPOOFING DETECTED"
                        );
                    }

                    if opt.json {
                        let arp_event = ArpEvent {
                            timestamp: ts,
                            opcode: opcode_to_text(event.ar_op),
                            sender_mac,
                            sender_ip,
                            target_mac,
                            target_ip,
                            alert,
                        };
                        if let Ok(json) = serde_json::to_string(&arp_event) {
                            println!("{}", json);
                        }
                    } else {
                        let alert_marker = if alert.is_some() { " ⚠ SPOOF" } else { "" };
                        println!(
                            "{:<12} {:<10} {:<20} {:<18} {:<20} {:<18}{}",
                            ts,
                            opcode_to_text(event.ar_op),
                            format_mac(&event.ar_sha),
                            format_ip(&event.ar_sip),
                            format_mac(&event.ar_tha),
                            format_ip(&event.ar_tip),
                            alert_marker,
                        );
                    }
                }
                // Yield to avoid busy-spinning
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            }
        }
    }

    info!("ARP monitor stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_to_text() {
        assert_eq!(opcode_to_text(1), "Request");
        assert_eq!(opcode_to_text(2), "Reply");
        assert_eq!(opcode_to_text(3), "RARP-Request");
        assert_eq!(opcode_to_text(4), "RARP-Reply");
        assert_eq!(opcode_to_text(99), "Unknown");
    }

    #[test]
    fn test_format_mac() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        assert_eq!(format_mac(&mac), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_format_ip() {
        let ip = [192, 168, 1, 1];
        assert_eq!(format_ip(&ip), "192.168.1.1");
    }

    #[test]
    fn test_parse_mac_valid() {
        let mac = parse_mac("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_parse_mac_invalid() {
        assert!(parse_mac("invalid").is_err());
        assert!(parse_mac("aa:bb:cc:dd:ee").is_err());
        assert!(parse_mac("gg:bb:cc:dd:ee:ff").is_err());
    }

    #[test]
    fn test_parse_whitelist_valid() {
        let entries = vec!["192.168.1.1=aa:bb:cc:dd:ee:ff".to_string()];
        let map = parse_whitelist(&entries).unwrap();
        assert_eq!(map.len(), 1);
        let ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
        assert_eq!(map[&ip], [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_parse_whitelist_invalid_format() {
        let entries = vec!["bad-entry".to_string()];
        assert!(parse_whitelist(&entries).is_err());
    }
}
