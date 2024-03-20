#![no_std]
#[repr(C)]
pub struct Event {
    pub ar_op: u16,         // ARP opcode (command)
    pub ar_sha: [u8; 6],    // sender hardware address
    pub ar_sip: [u8; 4],    // sender IP address
    pub ar_tha: [u8; 6],    // target hardware address
    pub ar_tip: [u8; 4]     // target IP address
}

#[repr(C)]
pub struct ArpHdr {
    pub ar_hrd: u16,        // format of hardware address
    pub ar_pro: u16,        // format of protocol address
    pub ar_hln: u8,         // length of hardware address
    pub ar_pln: u8,         // length of protocol address
    pub ar_op: u16,         // ARP opcode (command)
    pub ar_sha: [u8; 6],    // sender hardware address
    pub ar_sip: [u8; 4],    // sender IP address
    pub ar_tha: [u8; 6],    // target hardware address
    pub ar_tip: [u8; 4],    // target IP address
}
