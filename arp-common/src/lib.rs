#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Event {
    pub ar_op: u16,
    pub ar_sha: [u8; 6],
    pub ar_sip: [u8; 4],
    pub ar_tha: [u8; 6],
    pub ar_tip: [u8; 4],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Event {}

#[repr(C)]
pub struct ArpHdr {
    pub ar_hrd: u16,
    pub ar_pro: u16,
    pub ar_hln: u8,
    pub ar_pln: u8,
    pub ar_op: u16,
    pub ar_sha: [u8; 6],
    pub ar_sip: [u8; 4],
    pub ar_tha: [u8; 6],
    pub ar_tip: [u8; 4],
}
