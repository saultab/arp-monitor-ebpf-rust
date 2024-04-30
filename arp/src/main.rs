use std::fs::File;
use std::ops::Deref;
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::{include_bytes_aligned, Ebpf};
use aya::maps::{RingBuf};
use aya::programs::tc::TcOptions;
use aya_log::EbpfLogger;
use clap::Parser;
use log::{warn, debug};
use chrono::{Local};
use std::io::Write;

fn opcode_to_text(opcode: u16) -> &'static str {
    match opcode {
        1 => "Request",
        2 => "Reply",
        _ => "Unknown",
    }
}

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
        let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/arp"
    ))?;
    #[cfg(not(debug_assertions))]
        let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/arp"
    ))?;
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&opt.iface);
    let program: &mut SchedClassifier = bpf.program_mut("arp").unwrap().try_into()?;
    program.load()?;

    let op1 = TcOptions {
        priority: 65535,
        handle: 0,
    };

    let op2 = TcOptions {
        priority: 65535,
        handle: 0,
    };

    program.attach_with_options(&opt.iface, TcAttachType::Egress, op1)?;
    program.attach_with_options(&opt.iface, TcAttachType::Ingress, op2)?;

    /* Process events */
    println!("TIME\t\tTYPE\t\tSENDER MAC\t\tSENDER IP\t\tTARGET MAC\t\tTARGET IP");

    let mut ring_buf = RingBuf::try_from(bpf.map_mut("RINGBUF").unwrap()).unwrap();
    // Open file
    let ts = Local::now().format("%d-%m-%Y %H:%M:%S").to_string();
    let filename = format!("arp - {}.txt", ts);
    let mut file = File::create(filename)?;

    writeln!(file,"TIME\t\tTYPE\t\tSENDER MAC\t\tSENDER IP\t\tTARGET MAC\t\tTARGET IP")?;

    loop {
        while let Some(event) = ring_buf.next() {
            // TODO
            // let e :Event= event.try_into().unwrap();

            let ts = Local::now().format("%H:%M:%S");
            let ptr = event.deref();

            println!("{:<8}\t{:<8}\t\
                    {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\t\
                    {}.{}.{}.{}\t\t\
                    {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\t\
                    {}.{}.{}.{}",
                     ts, opcode_to_text(ptr[0] as u16),
                     ptr[2], ptr[3], ptr[4], ptr[5], ptr[6], ptr[7],
                     ptr[8], ptr[9], ptr[10], ptr[11],
                     ptr[12], ptr[13], ptr[14], ptr[15], ptr[16], ptr[17],
                     ptr[18], ptr[19], ptr[20], ptr[21]);

            // Write on file
            writeln!(file,
                "{:<8}\t{:<8}\t\
                 {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\t\
                 {}.{}.{}.{}\t\t\
                 {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\t\
                 {}.{}.{}.{}",
                 ts,
                 opcode_to_text(ptr[0] as u16),
                 ptr[2], ptr[3], ptr[4], ptr[5], ptr[6], ptr[7],
                 ptr[8], ptr[9], ptr[10], ptr[11],
                 ptr[12], ptr[13], ptr[14], ptr[15], ptr[16], ptr[17],
                 ptr[18], ptr[19], ptr[20], ptr[21])?;
        }
    }

    // info!("Waiting for Ctrl-C...");
    // signal::ctrl_c().await?;
    // info!("Exiting...");
    //
    // Ok(())
}
