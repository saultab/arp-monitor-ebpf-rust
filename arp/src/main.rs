use std::ops::Deref;
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::{include_bytes_aligned, Ebpf};
use aya::maps::RingBuf;
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn, debug};
use arp_common::Event;
use chrono::{Local};
//use tokio::signal;

struct PollFd<T>(T);

fn poll_fd<T>(t: T) -> PollFd<T> { PollFd(t) }

impl<T> PollFd<T> {
    fn readable(&mut self) -> Guard<'_, T> { Guard(self) }
}

struct Guard<'a, T>(&'a mut PollFd<T>);

impl<T> Guard<'_, T> {
    fn inner_mut(&mut self) -> &mut T {
        let Guard(PollFd(t)) = self;
        t
    }
    fn clear_ready(&mut self) {}
}

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
        let mut bpf = Bpf::load(include_bytes_aligned!(
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
    program.attach(&opt.iface, TcAttachType::Egress)?;

    /* Process events */
    println!("TIME\t\tTYPE\t\tSENDER MAC\t\tSENDER IP\t\tTARGET MAC\t\tTARGET IP");

    let mut ring_buf = RingBuf::try_from(bpf.map_mut("RINGBUF").unwrap()).unwrap();
    let mut poll = poll_fd(ring_buf);
    loop {
        let mut guard = poll.readable();
        let ring_buf = guard.inner_mut();
        while let Some(event) = ring_buf.next() {
            println!("Event:");
            println!("{:?}",event.deref());

            //let e :Event= event.try_into().unwrap();
            // let ts = Local::now().format("%H:%M:%S");
            //
            // println!("{:<8}\t{:<8}\t\
            //         {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\t\
            //         {}.{}.{}.{}\t\
            //         {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\t\
            //         {}.{}.{}.{}",
            //          ts, opcode_to_text(e.ar_op),
            //          e.ar_sha[0], e.ar_sha[1], e.ar_sha[2], e.ar_sha[3], e.ar_sha[4], e.ar_sha[5],
            //          e.ar_sip[0], e.ar_sip[1], e.ar_sip[2], e.ar_sip[3],
            //          e.ar_tha[0], e.ar_tha[1], e.ar_tha[2], e.ar_tha[3], e.ar_tha[4], e.ar_tha[5],
            //          e.ar_tip[0], e.ar_tip[1], e.ar_tip[2], e.ar_tip[3]
            // );
        }
        guard.clear_ready();
    }


    // info!("Waiting for Ctrl-C...");
    // signal::ctrl_c().await?;
    // info!("Exiting...");
    //
    // Ok(())
}
