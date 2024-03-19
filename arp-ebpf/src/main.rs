#![no_std]
#![no_main]

use aya_ebpf::{maps::RingBuf, macros::{classifier,map}, bindings::{TC_ACT_OK,TC_ACT_SHOT}, programs::TcContext};
use aya_log_ebpf::info;
use core::mem;
use arp_common::Event;
use network_types::{
    eth::{EthHdr, EtherType}
};

#[allow(dead_code)]
struct ArpHdr {
    ar_hrd: u16,            // format of hardware address
    ar_pro: u16,            // format of protocol address
    ar_hln: u8,             // length of hardware address
    ar_pln: u8,             // length of protocol address
    ar_op: u16,             // ARP opcode (command)
    ar_sha: [u8; 6],        // sender hardware address
    ar_sip: [u8; 4],        // sender IP address
    ar_tha: [u8; 6],        // target hardware address
    ar_tip: [u8; 4],        // target IP address
}

#[map]
static RINGBUF: RingBuf = RingBuf::with_byte_size(256 * 1024, 0); // 256 KB

#[inline(always)]
// Here we define ptr_at to ensure that packet access is always bound checked.
fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[classifier]
pub fn arp(ctx: TcContext) -> i32 {
    match try_arp(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

fn try_arp(ctx: TcContext) -> Result<i32, ()> {
    //info!(&ctx, "received a packet");

    // Use match per gestire correttamente il Result
    let ethhdr: *const EthHdr = match ptr_at(&ctx, 0) {
        Ok(ptr) => ptr,
        Err(()) => return Ok(TC_ACT_OK)
    };

    // Select only Arp
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Arp => {}
        _ => return Ok(TC_ACT_OK),
    }

    let arp: ArpHdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;

    /* Reserve the packet to the ring buffer */
    if let Some(mut buf) = RINGBUF.reserve::<Event>(0) {

        /* Copy fields from packet to the event struct */
        let e: Event = Event{
            ar_op: arp.ar_op,
            ar_sha: arp.ar_sha,
            ar_sip: arp.ar_sip,
            ar_tha: arp.ar_tha,
            ar_tip:arp.ar_tip,
        };

        /* Submit the packet to the ring buffer */
        buf.write(e);
        buf.submit(0);
    }

    Ok(TC_ACT_OK)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
