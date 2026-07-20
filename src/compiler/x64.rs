use crate::compiler::codegen::*;
use std::collections::HashMap;

struct Fixup {
    offset: u64,
    label: String,
}

struct Encoder {
    code: Vec<u8>,
    labels: HashMap<String, u64>,
    fixups: Vec<Fixup>,
    externs: Vec<String>,
}

impl Encoder {
    fn new(externs: &[String]) -> Self {
        Self {
            code: Vec::new(),
            labels: HashMap::new(),
            fixups: Vec::new(),
            externs: externs.to_vec(),
        }
    }

    fn u8(&mut self, b: u8) { self.code.push(b); }

    fn u32(&mut self, v: u32) { self.code.extend_from_slice(&v.to_le_bytes()); }

    fn u64(&mut self, v: u64) { self.code.extend_from_slice(&v.to_le_bytes()); }

    fn rex_w(&mut self) { self.u8(0x48); }

    fn rex_wb(&mut self) { self.u8(0x49); } // REX.W + B (extended r/m)

    fn modrm(&mut self, mode: u8, reg: u8, rm: u8) {
        self.u8((mode << 6) | ((reg & 7) << 3) | (rm & 7));
    }

    fn disp32(&mut self, v: i32) { self.u32(v as u32); }

    /// Map our `Register` enum value to the x86-64 architectural register
    /// number used in opcodes and modRM fields.  The x86 encoding order
    /// (0–7) is: RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, which differs
    /// from the Declaration order of the `Register` enum.  Extended
    /// registers R8–R15 (8–15) happen to match their enum values.
    fn x86_reg_num(reg: Register) -> u8 {
        //                    RAX RBX RCX RDX RSI RDI RBP RSP R8  R9  R10 R11 R12 R13 R14 R15
        const X86_MAP: [u8; 16] = [0,  3,  1,  2,  6,  7,  5,  4,  8,  9, 10, 11, 12, 13, 14, 15];
        X86_MAP[reg as usize]
    }

    fn reg_opcode(&mut self, reg: Register, op: u8) {
        let r = Self::x86_reg_num(reg);
        if r >= 8 { self.rex_wb(); } else { self.rex_w(); }
        self.u8(op + (r & 7));
    }

    /// Emit the REX prefix for a 64-bit operation on two registers.
    /// Sets REX.W and conditionally REX.R / REX.B based on whether
    /// dest (modRM.reg) or src (modRM.r/m) is an extended register (8+).
    fn rex_w_for_regs(&mut self, dest: Register, src: Register) {
        let d = Self::x86_reg_num(dest);
        let s = Self::x86_reg_num(src);
        let mut rex = 0x48u8; // REX.W
        if d >= 8 { rex |= 0x04; } // REX.R
        if s >= 8 { rex |= 0x01; } // REX.B
        self.u8(rex);
    }

    fn reg_to_reg(&mut self, opcode: u8, dest: Register, src: Register) {
        self.rex_w_for_regs(dest, src);
        self.u8(opcode);
        self.modrm(3, Self::x86_reg_num(dest), Self::x86_reg_num(src));
    }

    fn imm_to_reg(&mut self, dest: Register, val: i64) {
        self.reg_opcode(dest, 0xB8);
        self.u64(val as u64);
    }

    fn reg_to_mem_rbp(&mut self, reg: Register, disp: i64) {
        let r = Self::x86_reg_num(reg);
        if r >= 8 { self.rex_wb(); } else { self.rex_w(); }
        self.u8(0x89);
        if disp >= -128 && disp <= 127 {
            self.modrm(1, r, 5);
            self.u8(disp as u8);
        } else {
            self.modrm(2, r, 5);
            self.disp32(disp as i32);
        }
    }

    fn mem_rbp_to_reg(&mut self, reg: Register, disp: i64) {
        let r = Self::x86_reg_num(reg);
        if r >= 8 { self.rex_wb(); } else { self.rex_w(); }
        self.u8(0x8B);
        if disp >= -128 && disp <= 127 {
            self.modrm(1, r, 5);
            self.u8(disp as u8);
        } else {
            self.modrm(2, r, 5);
            self.disp32(disp as i32);
        }
    }

    fn push_reg(&mut self, reg: Register) {
        let r = Self::x86_reg_num(reg);
        if r >= 8 { self.u8(0x41); }
        self.u8(0x50 + (r & 7));
    }

    fn pop_reg(&mut self, reg: Register) {
        let r = Self::x86_reg_num(reg);
        if r >= 8 { self.u8(0x41); }
        self.u8(0x58 + (r & 7));
    }

    fn setcc(&mut self, cond: &Conditional) {
        self.u8(0x0F);
        let b = match cond {
            Conditional::E  => 0x94, Conditional::NE => 0x95,
            Conditional::L  => 0x9C, Conditional::LE => 0x9E,
            Conditional::G  => 0x9F, Conditional::GE => 0x9D,
        };
        self.u8(b);
        self.modrm(3, 0, 0); // al
    }

    fn movzx_al_to_rax(&mut self) {
        self.rex_w();
        self.u8(0x0F); self.u8(0xB6);
        self.modrm(3, 0, 0);
    }

    fn sub_rsp(&mut self, val: i64) {
        if val >= -128 && val <= 127 {
            self.rex_w(); self.u8(0x83); self.modrm(3, 5, 4); self.u8(val as u8);
        } else {
            self.rex_w(); self.u8(0x81); self.modrm(3, 5, 4); self.disp32(val as i32);
        }
    }

    fn add_rsp(&mut self, val: i64) {
        if val >= -128 && val <= 127 {
            self.rex_w(); self.u8(0x83); self.modrm(3, 0, 4); self.u8(val as u8);
        } else {
            self.rex_w(); self.u8(0x81); self.modrm(3, 0, 4); self.disp32(val as i32);
        }
    }

    fn lea_rip_rel(&mut self, reg: Register) {
        let r = Self::x86_reg_num(reg);
        if r >= 8 { self.rex_wb(); } else { self.rex_w(); }
        self.u8(0x8D); self.modrm(0, r, 5);
    }

    fn add_fixup(&mut self, label: &str) -> u64 {
        let offset = self.code.len() as u64;
        self.disp32(0);
        self.fixups.push(Fixup { offset, label: label.to_string() });
        offset
    }

    fn emit(&mut self, instr: &Instruction) {
        match instr {
            Instruction::Mov { dest, src } => {
                match (dest, src) {
                    (Operand::Register(d, OperandSize::Qword), Operand::Immediate(v)) =>
                        self.imm_to_reg(*d, *v),
                    (Operand::Register(d, OperandSize::Qword), Operand::Register(s, OperandSize::Qword)) => {
                        self.rex_w_for_regs(*d, *s); self.u8(0x8B); self.modrm(3, Self::x86_reg_num(*d), Self::x86_reg_num(*s));
                    }
                    (Operand::Memory { base: Some(Register::RBP), displacement, .. }, Operand::Register(s, OperandSize::Qword)) =>
                        self.reg_to_mem_rbp(*s, *displacement),
                    (Operand::Register(d, OperandSize::Qword), Operand::Memory { base: Some(Register::RBP), displacement, .. }) =>
                        self.mem_rbp_to_reg(*d, *displacement),
                    (Operand::Register(d, OperandSize::Qword), Operand::Label(l)) => {
                        self.lea_rip_rel(*d);
                        self.add_fixup(l);
                    }
                    _ => {}
                }
            }
            Instruction::Add { dest, src } => {
                match (dest, src) {
                    (Operand::Register(Register::RSP, OperandSize::Qword), Operand::Immediate(v)) =>
                        self.add_rsp(*v),
                    (Operand::Register(d, OperandSize::Qword), Operand::Register(s, OperandSize::Qword)) =>
                        self.reg_to_reg(0x01, *d, *s),
                    _ => self.reg_to_reg(0x01, Register::RAX, Register::RCX),
                }
            }
            Instruction::Sub { dest, src } => {
                match (dest, src) {
                    (Operand::Register(Register::RSP, OperandSize::Qword), Operand::Immediate(v)) =>
                        self.sub_rsp(*v),
                    (Operand::Register(d, OperandSize::Qword), Operand::Register(s, OperandSize::Qword)) =>
                        self.reg_to_reg(0x29, *d, *s),
                    _ => self.reg_to_reg(0x29, Register::RAX, Register::RCX),
                }
            }
            Instruction::Imul { dest, src } => {
                if let (Operand::Register(d, _), Operand::Register(s, _)) = (dest, src) {
                    self.rex_w_for_regs(*d, *s); self.u8(0x0F); self.u8(0xAF); self.modrm(3, Self::x86_reg_num(*d), Self::x86_reg_num(*s));
                }
            }
            Instruction::Idiv { src } => {
                if let Operand::Register(r, _) = src {
                    if Self::x86_reg_num(*r) >= 8 { self.rex_wb(); } else { self.rex_w(); }
                    self.u8(0xF7); self.modrm(3, 7, Self::x86_reg_num(*r));
                }
            }
            Instruction::Cqo => { self.rex_w(); self.u8(0x99); }
            Instruction::Neg { dest } => {
                if let Operand::Register(r, _) = dest {
                    if Self::x86_reg_num(*r) >= 8 { self.rex_wb(); } else { self.rex_w(); }
                    self.u8(0xF7); self.modrm(3, 3, Self::x86_reg_num(*r));
                }
            }
            Instruction::And { dest, src } => {
                if let (Operand::Register(d, _), Operand::Register(s, _)) = (dest, src) {
                    self.reg_to_reg(0x21, *d, *s);
                }
            }
            Instruction::Or { dest, src } => {
                if let (Operand::Register(d, _), Operand::Register(s, _)) = (dest, src) {
                    self.reg_to_reg(0x09, *d, *s);
                }
            }
            Instruction::Xor { dest, src } => {
                match (dest, src) {
                    (Operand::Register(Register::RAX, _), Operand::Immediate(-1)) => {
                        self.rex_w(); self.u8(0xF7); self.modrm(3, 2, 0); // not rax
                    }
                    (Operand::Register(d, _), Operand::Register(s, _)) => {
                        self.reg_to_reg(0x31, *d, *s);
                    }
                    _ => {}
                }
            }
            Instruction::Push(op) => { if let Operand::Register(r, _) = op { self.push_reg(*r); } }
            Instruction::Pop(op) => { if let Operand::Register(r, _) = op { self.pop_reg(*r); } }
            Instruction::Call { target, .. } => {
                if self.externs.contains(target) {
                    // Call through IAT: FF 15 [rip + offset_to_IAT]
                    self.u8(0xFF); self.modrm(0, 2, 5);
                    self.add_fixup(&format!("@IAT@{}", target));
                } else {
                    // Direct relative call: E8 rel32
        self.u8(0xE8);
        self.add_fixup(target);
                }
            }
            Instruction::Ret => self.u8(0xC3),
            Instruction::Nop => self.u8(0x90),
            Instruction::Label(name) => { self.labels.insert(name.clone(), self.code.len() as u64); }
            Instruction::Cmp { left, right } => {
                match (left, right) {
                    (Operand::Register(l, _), Operand::Register(r, _)) =>
                        self.reg_to_reg(0x39, *l, *r),
                    (Operand::Register(l, _), Operand::Immediate(0)) => {
                        if Self::x86_reg_num(*l) >= 8 { self.rex_wb(); } else { self.rex_w(); }
                        self.u8(0x83); self.modrm(3, 7, Self::x86_reg_num(*l)); self.u8(0);
                    }
                    _ => {}
                }
            }
            Instruction::Test { left, right } => {
                if let (Operand::Register(l, _), Operand::Register(r, _)) = (left, right) {
                    self.rex_w_for_regs(*l, *r); self.u8(0x85); self.modrm(3, Self::x86_reg_num(*l), Self::x86_reg_num(*r));
                }
            }
            Instruction::Jmp(target) => { self.u8(0xE9); self.add_fixup(target); }
            Instruction::Je(target) => { self.u8(0x0F); self.u8(0x84); self.add_fixup(target); }
            Instruction::Jne(target) => { self.u8(0x0F); self.u8(0x85); self.add_fixup(target); }
            Instruction::Setcc { cond, .. } => self.setcc(cond),
            Instruction::Movzx { .. } => self.movzx_al_to_rax(),
            Instruction::Lea { dest, src } => {
                if let Operand::Register(d, _) = dest {
                    self.lea_rip_rel(*d);
                    if let Operand::Label(l) = src {
                        self.add_fixup(l);
                    } else { self.disp32(0); }
                }
            }
            Instruction::Shl { dest, count } => {
                if let Operand::Register(d, _) = dest {
                    if let Operand::Register(Register::RCX, OperandSize::Byte) = count {
                        if Self::x86_reg_num(*d) >= 8 { self.rex_wb(); } else { self.rex_w(); }
                        self.u8(0xD3); self.modrm(3, 4, Self::x86_reg_num(*d));
                    }
                }
            }
            Instruction::Shr { dest, count } => {
                if let Operand::Register(d, _) = dest {
                    if let Operand::Register(Register::RCX, OperandSize::Byte) = count {
                        if Self::x86_reg_num(*d) >= 8 { self.rex_wb(); } else { self.rex_w(); }
                        self.u8(0xD3); self.modrm(3, 5, Self::x86_reg_num(*d));
                    }
                }
            }
    // SIMD float ops are in the IR but not yet implemented. Fail loudly
    // so a future float feature pass catches the missing backend immediately.
    Instruction::Vaddpd { .. } | Instruction::Vmulpd { .. } | Instruction::Vmovapd { .. } => {
        unreachable!("SIMD instruction lowering not implemented: {:?}", instr)
    }
    _ => {}
}
    }

    fn resolve_fixups(&mut self) {
        for fixup in &self.fixups {
            let target_offset = match self.labels.get(&fixup.label) {
                Some(&off) => off,
                None => continue, // extern IAT — resolved by PE writer
            };
            let current = fixup.offset;
            let rel = (target_offset as i64) - (current as i64) - 4;
            let bytes = (rel as i32).to_le_bytes();
            self.code[current as usize .. current as usize + 4].copy_from_slice(&bytes);
        }
    }
}

/// A fixup record for an extern function call that must be patched
/// by the PE writer with a RIP-relative offset to the IAT entry.
#[derive(Debug, Clone)]
pub struct ExternFixup {
    /// Byte offset within the encoded code where the 4-byte displacement sits.
    pub offset: u64,
    /// Name of the extern function (e.g. "ExitProcess", "printf").
    pub name: String,
}

/// A fixup record for a RIP-relative reference that must be patched
/// by the PE writer with a RIP-relative offset.
#[derive(Debug, Clone)]
pub struct RipRelFixup {
    /// Byte offset within the encoded code where the 4-byte displacement sits.
    pub offset: u64,
    /// Name of the label (data item or extern function).
    pub label: String,
}

/// Encode compiled instructions into x86-64 machine code bytes.
/// Labels are resolved; extern call fixups and RIP-relative data fixups
/// are returned as separate lists so the PE writer can patch them.
pub fn encode(instructions: &[Instruction], externs: &[String]) -> (Vec<u8>, Vec<ExternFixup>, Vec<RipRelFixup>) {
    let mut enc = Encoder::new(externs);
    for instr in instructions {
        enc.emit(instr);
    }
    enc.resolve_fixups();

    let iat_fixups: Vec<ExternFixup> = enc.fixups.iter()
        .filter(|f| f.label.starts_with("@IAT@"))
        .map(|f| ExternFixup {
            offset: f.offset,
            name: f.label.trim_start_matches("@IAT@").to_string(),
        })
        .collect();

    let riprel_fixups: Vec<RipRelFixup> = enc.fixups.iter()
        .filter(|f| !f.label.starts_with("@IAT@"))
        .map(|f| RipRelFixup {
            offset: f.offset,
            label: f.label.clone(),
        })
        .collect();

    (enc.code, iat_fixups, riprel_fixups)
}
