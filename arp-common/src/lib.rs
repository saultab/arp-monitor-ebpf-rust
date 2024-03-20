#![no_std]
//#[repr(C)]
pub struct Event {
    pub ar_op: u16,         // ARP opcode (command)
    pub ar_sha: [u8; 6],    // sender hardware address
    pub ar_sip: [u8; 4],    // sender IP address
    pub ar_tha: [u8; 6],    // target hardware address
    pub ar_tip: [u8; 4]     // target IP address
}