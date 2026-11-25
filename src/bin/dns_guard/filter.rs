//! Fixed eBPF socket-address filter. The first 32-bit load reads user_port
//! (network-order u16 in a u32). Ordinary traffic exits before any map lookup.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Insn {
    pub op: u8,
    pub regs: u8,
    pub off: i16,
    pub imm: i32,
}

const fn insn(op: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
    let regs = if cfg!(target_endian = "little") {
        dst | src << 4
    } else {
        dst << 4 | src
    };
    Insn { op, regs, off, imm }
}

pub fn program(map: i32) -> [Insn; 16] {
    [
        insn(0x61, 2, 1, 24, 0),                      // r2 = ctx->user_port
        insn(0x15, 2, 0, 1, 53_u16.to_be() as i32),   // DNS -> lookup
        insn(0x55, 2, 0, 11, 853_u16.to_be() as i32), // everything else -> allow
        insn(0x62, 10, 0, -4, 0),                     // stack[-4] = key 0
        insn(0xbf, 2, 10, 0, 0),                      // r2 = frame pointer
        insn(0x07, 2, 0, 0, -4),                      // r2 = &key
        insn(0x18, 1, 1, 0, map),                     // r1 = shared array map
        insn(0, 0, 0, 0, 0),                          // second half of LD_IMM64
        insn(0x85, 0, 0, 0, 1),                       // bpf_map_lookup_elem
        insn(0x15, 0, 0, 4, 0),                       // null -> allow
        insn(0x61, 0, 0, 0, 0),                       // r0 = shared enabled flag
        insn(0x15, 0, 0, 2, 0),                       // disabled -> allow
        insn(0xb7, 0, 0, 0, 0),                       // active -> deny
        insn(0x95, 0, 0, 0, 0),
        insn(0xb7, 0, 0, 0, 1),
        insn(0x95, 0, 0, 0, 0),
    ]
}
