#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    macros::{classifier, map},
    maps::RingBuf,
    programs::TcContext,
};
use core::mem;

use arp_common::{ArpHdr, Event};
use network_types::eth::{EthHdr, EtherType};

#[map]
static RINGBUF: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[inline(always)]
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
        Err(_) => TC_ACT_OK,
    }
}

fn try_arp(ctx: TcContext) -> Result<i32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;

    // Only process ARP packets
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Arp => {}
        _ => return Ok(TC_ACT_OK),
    }

    let arp: ArpHdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;

    if let Some(mut buf) = RINGBUF.reserve::<Event>(0) {
        let e = Event {
            ar_op: u16::from_be(arp.ar_op),
            ar_sha: arp.ar_sha,
            ar_sip: arp.ar_sip,
            ar_tha: arp.ar_tha,
            ar_tip: arp.ar_tip,
        };
        buf.write(e);
        buf.submit(0);
    }

    Ok(TC_ACT_OK)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}