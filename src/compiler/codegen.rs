use crate::compiler::ast::*;
use std::collections::HashMap;
use std::fmt;

pub type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Asm,
    RustSource,
    Pe,
}

// ============================================================================
// x86_64 Windows Code Generation (NASM syntax)
// ============================================================================
// ABI: Microsoft x64 calling convention
//   RCX, RDX, R8, R9  : first 4 integer/pointer args
//   XMM0..XMM3        : first 4 float/double args
//   RAX return        : integer/pointer result
//   XMM0 return       : float/double result
//   Shadow space      : 32 bytes reserved by caller (ABI-mandated)
//   Caller-saved      : RAX, RCX, RDX, R8, R9, R10, R11
//   Callee-saved      : RBX, RBP, RDI, RSI, R12..R15

const SHADOW_SPACE: i64 = 32;

// ============================================================================
// Operand Model
// ============================================================================

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperandSize {
    Byte, Word, Dword, Qword,
    Xmm, Ymm, Zmm,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP,
    R8, R9, R10, R11, R12, R13, R14, R15,
    XMM0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7,
    XMM8, XMM9, XMM10, XMM11, XMM12, XMM13, XMM14, XMM15,
}

impl fmt::Display for Register {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Register::RAX => write!(f, "rax"),
            Register::RBX => write!(f, "rbx"),
            Register::RCX => write!(f, "rcx"),
            Register::RDX => write!(f, "rdx"),
            Register::RSI => write!(f, "rsi"),
            Register::RDI => write!(f, "rdi"),
            Register::RBP => write!(f, "rbp"),
            Register::RSP => write!(f, "rsp"),
            Register::R8 => write!(f, "r8"),
            Register::R9 => write!(f, "r9"),
            Register::R10 => write!(f, "r10"),
            Register::R11 => write!(f, "r11"),
            Register::R12 => write!(f, "r12"),
            Register::R13 => write!(f, "r13"),
            Register::R14 => write!(f, "r14"),
            Register::R15 => write!(f, "r15"),
            Register::XMM0 => write!(f, "xmm0"),
            Register::XMM1 => write!(f, "xmm1"),
            Register::XMM2 => write!(f, "xmm2"),
            Register::XMM3 => write!(f, "xmm3"),
            Register::XMM4 => write!(f, "xmm4"),
            Register::XMM5 => write!(f, "xmm5"),
            Register::XMM6 => write!(f, "xmm6"),
            Register::XMM7 => write!(f, "xmm7"),
            Register::XMM8 => write!(f, "xmm8"),
            Register::XMM9 => write!(f, "xmm9"),
            Register::XMM10 => write!(f, "xmm10"),
            Register::XMM11 => write!(f, "xmm11"),
            Register::XMM12 => write!(f, "xmm12"),
            Register::XMM13 => write!(f, "xmm13"),
            Register::XMM14 => write!(f, "xmm14"),
            Register::XMM15 => write!(f, "xmm15"),
        }
    }
}

impl fmt::Display for OperandSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OperandSize::Byte => write!(f, "byte"),
            OperandSize::Word => write!(f, "word"),
            OperandSize::Dword => write!(f, "dword"),
            OperandSize::Qword => write!(f, "qword"),
            OperandSize::Xmm => write!(f, "xmm"),
            OperandSize::Ymm => write!(f, "ymm"),
            OperandSize::Zmm => write!(f, "zmm"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Operand {
    Register(Register, OperandSize),
    Immediate(i64),
    Memory {
        base: Option<Register>,
        index: Option<(Register, u8)>, // (reg, scale: 1/2/4/8)
        displacement: i64,
        size: OperandSize,
    },
    Label(String),
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operand::Register(reg, size) => {
                // For byte-sized operands we need the 8-bit register name
                // (al, cl, ...) — NASM rejects `setcc rax`. Fall back to
                // the 64-bit name for anything else.
                if *size == OperandSize::Byte {
                    write!(f, "{}", byte_register_name(*reg))
                } else {
                    write!(f, "{}", reg)
                }
            }
            Operand::Immediate(val) => write!(f, "{}", val),
            Operand::Memory { base, index, displacement, size } => {
                let _ = size;
                write!(f, "[")?;
                if let Some(b) = base { write!(f, "{}", b)?; }
                if let Some((idx, scale)) = index {
                    if base.is_some() { write!(f, " + ")?; }
                    write!(f, "{} * {}", idx, scale)?;
                }
                if *displacement != 0 {
                    if base.is_some() || index.is_some() {
                        if *displacement > 0 { write!(f, " + {}", displacement)?; }
                        else { write!(f, " - {}", -displacement)?; }
                    } else { write!(f, "{}", displacement)?; }
                }
                write!(f, "]")
            }
            Operand::Label(name) => write!(f, "{}", name),
        }
    }
}

/// Return the 8-bit register name for a given logical register. Only the
/// caller-saved and callee-saved GP registers that are reachable from the
/// `Register` enum are mapped; XMM registers don't have byte forms and
/// will fall back to their 64-bit name on call misuse (an unreachable case
/// in the current codegen).
fn byte_register_name(reg: Register) -> &'static str {
    match reg {
        Register::RAX => "al",  Register::RBX => "bl",
        Register::RCX => "cl",  Register::RDX => "dl",
        Register::RSI => "sil", Register::RDI => "dil",
        Register::RBP => "bpl", Register::RSP => "spl",
        Register::R8  => "r8b", Register::R9  => "r9b",
        Register::R10 => "r10b", Register::R11 => "r11b",
        Register::R12 => "r12b", Register::R13 => "r13b",
        Register::R14 => "r14b", Register::R15 => "r15b",
        // XMM registers don't have byte form — these should never be passed
        // here with Byte size. Return the 64-bit name to remain total.
        _ => "",
    }
}

// ============================================================================
// Instruction IR
// ============================================================================

/// x86 condition codes used by Setcc and the conditional jumps. The names
/// match the signed comparisons: `L` (<), `LE` (<=), `G` (>), `GE` (>=),
/// plus `E` (==) and `NE` (!=). Two constants are kept distinct even though
/// some encodings collapse (e.g. ZF=1 covers both `E` and the jump `Je`):
/// explicit naming keeps codegen intent legible as we lower comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conditional {
    E, NE, L, LE, G, GE,
}

impl fmt::Display for Conditional {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Conditional::E  => write!(f, "e"),
            Conditional::NE => write!(f, "ne"),
            Conditional::L  => write!(f, "l"),
            Conditional::LE => write!(f, "le"),
            Conditional::G  => write!(f, "g"),
            Conditional::GE => write!(f, "ge"),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum Instruction {
    // Data movement
    Mov { dest: Operand, src: Operand },
    // Arithmetic
    Add { dest: Operand, src: Operand },
    Sub { dest: Operand, src: Operand },
    Imul { dest: Operand, src: Operand },
    Idiv { src: Operand },       // IDIV src  (RDX:RAX / src)
    Cqo,                          // sign-extend RAX -> RDX:RAX
    Neg { dest: Operand },
    And { dest: Operand, src: Operand },
    Or  { dest: Operand, src: Operand },
    Xor { dest: Operand, src: Operand },
    // Stack
    Push(Operand),
    Pop(Operand),
    // Control flow
    Call { target: String, arg_count: usize },
    Ret,
    Syscall,
    Nop,
    Label(String),
    Cmp { left: Operand, right: Operand },
    Test { left: Operand, right: Operand },
    // Conditional jumps
    Jmp(String), Je(String), Jne(String),
    Jl(String), Jle(String), Jg(String), Jge(String),
    // Shifts (immediate or CL)
    Shl { dest: Operand, count: Operand },
    Shr { dest: Operand, count: Operand },
    // Bytes-set-on-condition: writes the low byte of a register to 0 or 1
    // based on flags. Pair with a prior movzx to widen to 64-bit.
    Setcc { cond: Conditional, dest: Operand },
    Movzx { dest: Operand, src: Operand },
    // Address-of via RIP-relative addressing (default rel).
    Lea { dest: Operand, src: Operand },
    // SIMD - AVX2/AVX-512
    Vaddpd { dest: Operand, src: Operand },
    Vmulpd { dest: Operand, src: Operand },
    Vmovapd { dest: Operand, src: Operand },
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Instruction::Mov { dest, src } => write!(f, "mov {}, {}", dest, src),
            Instruction::Add { dest, src } => write!(f, "add {}, {}", dest, src),
            Instruction::Sub { dest, src } => write!(f, "sub {}, {}", dest, src),
            Instruction::Imul { dest, src } => write!(f, "imul {}, {}", dest, src),
            Instruction::Idiv { src } => write!(f, "idiv {}", src),
            Instruction::Cqo => write!(f, "cqo"),
            Instruction::Neg { dest } => write!(f, "neg {}", dest),
            Instruction::And { dest, src } => write!(f, "and {}, {}", dest, src),
            Instruction::Or  { dest, src } => write!(f, "or {}, {}", dest, src),
            Instruction::Xor { dest, src } => write!(f, "xor {}, {}", dest, src),
            Instruction::Push(op) => write!(f, "push {}", op),
            Instruction::Pop(op) => write!(f, "pop {}", op),
            Instruction::Call { target, arg_count: _ } => write!(f, "call {}", target),
            Instruction::Ret => write!(f, "ret"),
            Instruction::Syscall => write!(f, "syscall"),
            Instruction::Nop => write!(f, "nop"),
            Instruction::Label(name) => write!(f, "{}:", name),
            Instruction::Cmp { left, right } => write!(f, "cmp {}, {}", left, right),
            Instruction::Test { left, right } => write!(f, "test {}, {}", left, right),
            Instruction::Jmp(target) => write!(f, "jmp {}", target),
            Instruction::Je(target) => write!(f, "je {}", target),
            Instruction::Jne(target) => write!(f, "jne {}", target),
            Instruction::Jl(target) => write!(f, "jl {}", target),
            Instruction::Jle(target) => write!(f, "jle {}", target),
            Instruction::Jg(target) => write!(f, "jg {}", target),
            Instruction::Jge(target) => write!(f, "jge {}", target),
            Instruction::Vaddpd { dest, src } => write!(f, "vaddpd {}, {}", dest, src),
            Instruction::Vmulpd { dest, src } => write!(f, "vmulpd {}, {}", dest, src),
            Instruction::Vmovapd { dest, src } => write!(f, "vmovapd {}, {}", dest, src),
            Instruction::Shl { dest, count } => write!(f, "shl {}, {}", dest, count),
            Instruction::Shr { dest, count } => write!(f, "shr {}, {}", dest, count),
            Instruction::Setcc { cond, dest } => write!(f, "set{} {}", cond, dest),
            Instruction::Movzx { dest, src } => write!(f, "movzx {}, {}", dest, src),
            // LEA's source must be a memory operand. When handed a label as
            // the source, wrap it in [] to form a usable address expression.
            // `default rel` is in effect at file scope, so bare labels use
            // RIP-relative addressing automatically.
            Instruction::Lea { dest, src } => match src {
                Operand::Label(name) => write!(f, "lea {}, [{}]", dest, name),
                _ => write!(f, "lea {}, {}", dest, src),
            },
        }
    }
}

// ============================================================================
// Symbol Table
// ============================================================================
// Maps each variable to an [rbp - offset] slot.
// This is intentionally local to a single module function.

#[derive(Debug, Default)]
pub struct SymbolTable {
    slots: HashMap<String, i64>,
    next_offset: i64,
}

impl SymbolTable {
    /// Declare a new local and return its `[rbp - offset]` slot offset.
    /// Offsets start at 8 (the first real local slot, immediately below
    /// saved RBP) and grow upward by 8 per declaration. We must never use
    /// offset 0: that would alias `[rbp]`, which holds the saved RBP and
    /// cannot be safely overwritten.
    pub fn declare(&mut self, name: &str) -> i64 {
        self.next_offset += 8;
        self.slots.insert(name.to_string(), self.next_offset);
        self.next_offset
    }

    pub fn get(&self, name: &str) -> Option<i64> {
        self.slots.get(name).copied()
    }
}

// ============================================================================
// Module Code Container
// ============================================================================
// NO abstract stack tracking. RSP is the only source of truth.
// All shadow space / local stack changes are explicit in Instruction stream.

#[derive(Debug)]
pub struct ModuleCode {
    pub instructions: Vec<Instruction>,
    pub externs: Vec<String>,
    pub label_counter: usize,
    pub symbols: SymbolTable,
    /// Named, deduplicated byte blobs emitted into the read-only data
    /// section. Used for format strings and other literals. Each entry
    /// maps a logical name to the raw byte payload; identical payloads
    /// share one label to keep .rdata lean.
    pub data_items: Vec<(String, Vec<u8>)>,
}

impl ModuleCode {
    pub fn new(_name: &str) -> Self {
        Self {
            instructions: Vec::new(),
            externs: Vec::new(),
            label_counter: 0,
            symbols: SymbolTable::default(),
            data_items: Vec::new(),
        }
    }

    pub fn emit(&mut self, instr: Instruction) {
        self.instructions.push(instr);
    }

    pub fn new_label(&mut self, prefix: &str) -> String {
        let label = format!(".L{}_{}", prefix, self.label_counter);
        self.label_counter += 1;
        label
    }

    pub fn add_extern(&mut self, sym: &str) {
        if !self.externs.iter().any(|s| s == sym) {
            self.externs.push(sym.to_string());
        }
    }

    /// Intern a byte blob, deduplicating by payload. Returns the label to
    /// reference from code. If `name` is already taken by different data, a
    /// counter suffix is appended to keep labels unique.
    pub fn intern_data(&mut self, name: &str, bytes: &[u8]) -> String {
        // Reuse an existing entry with the same byte payload regardless of name.
        for (existing_name, existing_bytes) in self.data_items.iter() {
            if existing_bytes.as_slice() == bytes {
                return existing_name.to_string();
            }
        }
        // Generate a unique label if the requested name is taken.
        let label = if self.data_items.iter().any(|(n, _)| n == name) {
            let unique = format!("{}_{}", name, self.label_counter);
            self.label_counter += 1;
            unique
        } else {
            name.to_string()
        };
        self.data_items.push((label.clone(), bytes.to_vec()));
        label
    }
}

// ============================================================================
// Code Generator
// ============================================================================
// Postfix lowering: stack machine semantics -> physical x64 assembly.

pub struct CodeGenerator {
    current_module: Option<String>,
    current_function_epilogue: Option<String>,
    format: OutputFormat,
}

impl CodeGenerator {
    pub fn new() -> Self {
        Self {
            current_module: None,
            current_function_epilogue: None,
            format: OutputFormat::Asm,
        }
    }

    /// Generate compiled module codes (shared by all output formats).
    /// This is the core codegen pass; callers can then format, encode, or
    /// further process the returned modules.
    pub fn generate_modules(&mut self, program: &Program, format: OutputFormat) -> Result<Vec<ModuleCode>> {
        self.format = format;
        let global_inputs: Vec<Parameter> = program.inputs.as_ref()
            .map(|ib| ib.items.iter().map(|(name, ty_str)| {
                let ty = match ty_str.as_str() {
                    "i64" => ValueType::I64,
                    "f64" => ValueType::F64,
                    _ => ValueType::I64,
                };
                Parameter { name: name.clone(), ty }
            }).collect())
            .unwrap_or_default();

        let mut modules = Vec::new();
        for module in &program.modules {
            let mut code = ModuleCode::new(&module.name);
            self.current_module = Some(module.name.clone());
            self.generate_module(&mut code, module, &global_inputs)?;
            modules.push(code);
        }
        Ok(modules)
    }

    pub fn generate(&mut self, program: &Program, format: OutputFormat) -> Result<String> {
        let modules = self.generate_modules(program, format)?;
        match format {
            OutputFormat::Asm => Ok(format_as_asm(&modules)),
            OutputFormat::RustSource => format_rust_source(&modules),
            OutputFormat::Pe => Err("Pe format cannot be returned as String; use generate_modules + encode directly".into()),
        }
    }

    // ---- Module generation ----

    fn generate_module(&mut self, code: &mut ModuleCode, module: &ModuleBlock, global_inputs: &[Parameter]) -> Result<()> {
        let _name = self.current_module.as_ref().unwrap();
        code.add_extern("ExitProcess");

        // Generate functions first (they're separate from the entry block)
        for func in &module.functions {
            self.generate_function(code, func)?;
        }

        // Merge global inputs with module-level inputs.
        let all_inputs: Vec<&Parameter> = global_inputs.iter()
            .chain(module.inputs.iter())
            .collect();

        let entry = code.new_label("entry");
        code.emit(Instruction::Label(entry));

        // Declare module inputs first (they get lower offsets, akin to
        // the "home locations" in the Microsoft x64 convention). Then scan
        // the module body for additional local variable declarations.
        let arg_regs = [Register::RCX, Register::RDX, Register::R8, Register::R9];
        for param in &all_inputs {
            code.symbols.declare(&param.name);
        }
        self.declare_locals(code, module);

        let locals_size = align_to_16(code.symbols.next_offset);
        // We push two non-volatile registers (RBX, RBP = even count), so
        // frame_size must be 8 mod 16 to keep RSP 16-byte aligned after
        // the prologue.  With 0-mod-16 frame_size, RSP would be 8 mod 16
        // after sub rsp, breaking all subsequent call alignment.
        let frame_size = SHADOW_SPACE + locals_size + 8;

        // Windows x64 prologue: save non-volatile regs.
        code.emit(Instruction::Push(Operand::Register(Register::RBX, OperandSize::Qword)));
        code.emit(Instruction::Push(Operand::Register(Register::RBP, OperandSize::Qword)));
        code.emit(Instruction::Mov {
            dest: Operand::Register(Register::RBP, OperandSize::Qword),
            src: Operand::Register(Register::RSP, OperandSize::Qword),
        });

        // Reserve the frame in a single subtraction: 32-byte ABI shadow
        // space plus the locals region (16-byte aligned). Anything in
        // [rbp - frame_size, rbp] is now writable scratch space.
        code.emit(Instruction::Sub {
            dest: Operand::Register(Register::RSP, OperandSize::Qword),
            src: Operand::Immediate(frame_size),
        });

        // Save module input register parameters to their stack slots.
        for (i, param) in all_inputs.iter().enumerate() {
            if i < 4 {
                let reg = arg_regs[i];
                let offset = code.symbols.get(&param.name).unwrap();
                code.emit(Instruction::Mov {
                    dest: Operand::Memory {
                        base: Some(Register::RBP),
                        index: None,
                        displacement: -offset,
                        size: OperandSize::Qword,
                    },
                    src: Operand::Register(reg, OperandSize::Qword),
                });
            }
        }

        for stmt in &module.statements {
            self.generate_statement(code, stmt)?;
        }

        // Emit the program exit point: hand control to ExitProcess with
        // the current RAX value as the process exit code. This lives at
        // the end of the entry module so the program never falls off the
        // bottom into someone else's code.
        self.emit_exit(code);

        // Windows x64 epilogue (used by non-entry helpers; entry modules
        // never reach here because emit_exit calls ExitProcess).
        code.emit(Instruction::Add {
            dest: Operand::Register(Register::RSP, OperandSize::Qword),
            src: Operand::Immediate(frame_size),
        });
        code.emit(Instruction::Pop(Operand::Register(Register::RBP, OperandSize::Qword)));
        code.emit(Instruction::Pop(Operand::Register(Register::RBX, OperandSize::Qword)));
        code.emit(Instruction::Ret);

        Ok(())
    }

    fn declare_locals(&mut self, code: &mut ModuleCode, module: &ModuleBlock) {
        for stmt in &module.statements {
            self.declare_locals_in_stmt(code, stmt);
        }
        // Also scan function bodies for local variables
        for func in &module.functions {
            for stmt in &func.body {
                self.declare_locals_in_stmt(code, stmt);
            }
        }
    }

    // Recursively walk and reserve slots for every assignment encountered in
    // any control-flow block. Stage 0 has block-level semantics where a
    // variable declared inside `if`/`while` is visible after the block; we
    // do not enforce proper scoping yet (those are Stage 0.5+ concerns).
    fn declare_locals_in_stmt(&mut self, code: &mut ModuleCode, stmt: &Statement) {
        match stmt {
            Statement::Assignment(assign) => {
                if code.symbols.get(&assign.name).is_none() {
                    code.symbols.declare(&assign.name);
                }
            }
            Statement::If { then_branch, else_branch, .. } => {
                for s in then_branch {
                    self.declare_locals_in_stmt(code, s);
                }
                if let Some(else_branch) = else_branch {
                    for s in else_branch {
                        self.declare_locals_in_stmt(code, s);
                    }
                }
            }
            Statement::While { body, .. } => {
                for s in body {
                    self.declare_locals_in_stmt(code, s);
                }
            }
            Statement::Expression(_) | Statement::Sink(_) | Statement::Return(_) => {}
        }
    }

    // Variant that uses an explicit symbol table (for function bodies).
    fn declare_locals_in_stmt_with_symbols(&mut self, symbols: &mut SymbolTable, stmt: &Statement) {
        match stmt {
            Statement::Assignment(assign) => {
                if symbols.get(&assign.name).is_none() {
                    symbols.declare(&assign.name);
                }
            }
            Statement::If { then_branch, else_branch, .. } => {
                for s in then_branch {
                    self.declare_locals_in_stmt_with_symbols(symbols, s);
                }
                if let Some(else_branch) = else_branch {
                    for s in else_branch {
                        self.declare_locals_in_stmt_with_symbols(symbols, s);
                    }
                }
            }
            Statement::While { body, .. } => {
                for s in body {
                    self.declare_locals_in_stmt_with_symbols(symbols, s);
                }
            }
            Statement::Expression(_) | Statement::Sink(_) | Statement::Return(_) => {}
        }
    }

    // ---- Statement lowering ----

    fn generate_statement(&mut self, code: &mut ModuleCode, stmt: &Statement) -> Result<()> {
        match stmt {
            Statement::Expression(expr) => {
                self.generate_expression(code, expr)?;
                code.emit(Instruction::Pop(Operand::Register(Register::RAX, OperandSize::Qword)));
                Ok(())
            }
            Statement::Assignment(assign) => self.generate_assignment(code, assign),
            Statement::Sink(sink) => self.generate_sink(code, sink),
            Statement::If { condition, then_branch, else_branch } => {
                self.generate_if(code, condition, then_branch, else_branch)
            }
            Statement::While { condition, body } => {
                self.generate_while(code, condition, body)
            }
            Statement::Return(ret) => self.generate_return(code, ret),
        }
    }

    fn generate_assignment(&mut self, code: &mut ModuleCode, assign: &Assignment) -> Result<()> {
        self.generate_expression(code, &assign.value)?;
        code.emit(Instruction::Pop(Operand::Register(Register::RAX, OperandSize::Qword)));
        if let Some(offset) = code.symbols.get(&assign.name) {
            code.emit(Instruction::Mov {
                dest: Operand::Memory {
                    base: Some(Register::RBP),
                    index: None,
                    displacement: -offset,
                    size: OperandSize::Qword,
                },
                src: Operand::Register(Register::RAX, OperandSize::Qword),
            });
        }
        Ok(())
    }

    // ---- Return lowering ----

    // Lower `return [expr]`:
    //
    //   <eval expr, leave value on RAX-via-pop>
    //   jmp <current_function_epilogue>
    //
    // The epilogue label is set by generate_function before emitting
    // the function body.
    fn generate_return(&mut self, code: &mut ModuleCode, ret: &Return) -> Result<()> {
        if let Some(value) = &ret.value {
            self.generate_expression(code, value)?;
            code.emit(Instruction::Pop(Operand::Register(Register::RAX, OperandSize::Qword)));
        }
        let epilogue = self.current_function_epilogue.as_ref().ok_or(
            "return statement outside of function body")?;
        code.emit(Instruction::Jmp(epilogue.clone()));
        Ok(())
    }

    // ---- Control flow lowering ----

    // Lower `if cond { then } else { else }`:
    //
    //   <eval cond, leave value on RAX-via-pop>
    //   cmp rax, 0
    //   je .Lelse_N
    //   <then branch>
    //   jmp .Lend_N
    // .Lelse_N:
    //   <else branch>
    // .Lend_N:
    //
    // When there is no `else`, `.Lelse_N` jumps to the same label we use
    // as the end marker, saving one label's worth of bookkeeping.
    fn generate_if(
        &mut self,
        code: &mut ModuleCode,
        condition: &Expression,
        then_branch: &[Statement],
        else_branch: &Option<Vec<Statement>>,
    ) -> Result<()> {
        self.generate_expression(code, condition)?;
        code.emit(Instruction::Pop(Operand::Register(Register::RAX, OperandSize::Qword)));

        let else_label = code.new_label("else");
        let end_label = code.new_label("end");

        code.emit(Instruction::Cmp {
            left: Operand::Register(Register::RAX, OperandSize::Qword),
            right: Operand::Immediate(0),
        });
        code.emit(Instruction::Je(else_label.clone()));

        for stmt in then_branch {
            self.generate_statement(code, stmt)?;
        }
        code.emit(Instruction::Jmp(end_label.clone()));

        code.emit(Instruction::Label(else_label));
        if let Some(else_branch) = else_branch {
            for stmt in else_branch {
                self.generate_statement(code, stmt)?;
            }
        }
        code.emit(Instruction::Label(end_label));
        Ok(())
    }

    // Lower `while cond { body }`:
    //
    // .Lstart_N:
    //   <eval cond, leave value via pop>
    //   cmp rax, 0
    //   je .Lend_N
    //   <body>
    //   jmp .Lstart_N
    // .Lend_N:
    fn generate_while(
        &mut self,
        code: &mut ModuleCode,
        condition: &Expression,
        body: &[Statement],
    ) -> Result<()> {
        let start_label = code.new_label("start");
        let end_label = code.new_label("end");

        code.emit(Instruction::Label(start_label.clone()));
        self.generate_expression(code, condition)?;
        code.emit(Instruction::Pop(Operand::Register(Register::RAX, OperandSize::Qword)));
        code.emit(Instruction::Cmp {
            left: Operand::Register(Register::RAX, OperandSize::Qword),
            right: Operand::Immediate(0),
        });
        code.emit(Instruction::Je(end_label.clone()));

        for stmt in body {
            self.generate_statement(code, stmt)?;
        }
        code.emit(Instruction::Jmp(start_label));

        code.emit(Instruction::Label(end_label));
        Ok(())
    }

    // ---- Function lowering ----

    // Generate a standalone function with its own stack frame, parameter
    // handling, and return value. Functions use the Microsoft x64 calling
    // convention: first 4 integer args in RCX, RDX, R8, R9; additional
    // args on stack; return value in RAX.
    // Emits a complete function (prologue, body, epilogue) into the module's
    // instruction stream. Uses a private symbol table for function locals so
    // they don't conflict with the module's main block or other functions.
    fn generate_function(&mut self, code: &mut ModuleCode, func: &FunctionBlock) -> Result<()> {
        // Private symbol table for this function's locals.
        let mut func_symbols = SymbolTable::default();

        // Reserve slots for parameters (so assignments to params work).
        for param in &func.params {
            func_symbols.declare(&param.name);
        }
        // Scan function body for additional local declarations.
        for stmt in &func.body {
            self.declare_locals_in_stmt_with_symbols(&mut func_symbols, stmt);
        }

        // Compute frame size: shadow space (32) + locals (16-byte aligned).
        // +8 for even push count (RBX, RBP) — see generate_module.
        let locals_size = align_to_16(func_symbols.next_offset);
        let frame_size = SHADOW_SPACE + locals_size + 8;

        let arg_regs = [Register::RCX, Register::RDX, Register::R8, Register::R9];

        // Function prologue
        code.emit(Instruction::Label(func.name.clone()));
        code.emit(Instruction::Push(Operand::Register(Register::RBX, OperandSize::Qword)));
        code.emit(Instruction::Push(Operand::Register(Register::RBP, OperandSize::Qword)));
        code.emit(Instruction::Mov {
            dest: Operand::Register(Register::RBP, OperandSize::Qword),
            src: Operand::Register(Register::RSP, OperandSize::Qword),
        });
        code.emit(Instruction::Sub {
            dest: Operand::Register(Register::RSP, OperandSize::Qword),
            src: Operand::Immediate(frame_size),
        });

// Save register parameters to their stack slots (home locations).
        for (i, param) in func.params.iter().enumerate() {
            if i < 4 {
                let reg = arg_regs[i];
                let offset = func_symbols.get(&param.name).unwrap();
                code.emit(Instruction::Mov {
                    dest: Operand::Memory {
                        base: Some(Register::RBP),
                        index: None,
                        displacement: -offset,
                        size: OperandSize::Qword,
                    },
                    src: Operand::Register(reg, OperandSize::Qword),
                });
            } else {
                return Err(format!("Function '{}' has more than 4 parameters; not yet supported in Stage 0", func.name));
            }
        }

        // Create epilogue label and set it BEFORE generating body so return
        // statements can jump to it.
        let epilogue_label = code.new_label(&format!("{}_epilogue", func.name));
        self.current_function_epilogue = Some(epilogue_label.clone());

        // Generate function body using the function's private symbol table.
        let saved_symbols = std::mem::replace(&mut code.symbols, func_symbols);
        for stmt in &func.body {
            self.generate_statement(code, stmt)?;
        }
        // Restore module symbol table.
        let _ = std::mem::replace(&mut code.symbols, saved_symbols);

        // Clear epilogue label now that body is generated.
        self.current_function_epilogue = None;

        // Function epilogue (target of return statements via jump)
        code.emit(Instruction::Label(epilogue_label));
        code.emit(Instruction::Add {
            dest: Operand::Register(Register::RSP, OperandSize::Qword),
            src: Operand::Immediate(frame_size),
        });
        code.emit(Instruction::Pop(Operand::Register(Register::RBP, OperandSize::Qword)));
        code.emit(Instruction::Pop(Operand::Register(Register::RBX, OperandSize::Qword)));
        code.emit(Instruction::Ret);

        Ok(())
    }

    // ---- Expression lowering (postfix -> x64) ----

    fn generate_expression(&mut self, code: &mut ModuleCode, expr: &Expression) -> Result<()> {
        match expr {
            Expression::Literal(lit) => {
                match &lit.value {
                    LiteralValue::String(s) => {
                        let mut bytes = s.as_bytes().to_vec();
                        bytes.push(0);
                        let label = code.intern_data("str", &bytes);
                        code.emit(Instruction::Lea {
                            dest: Operand::Register(Register::RAX, OperandSize::Qword),
                            src: Operand::Label(label),
                        });
                        code.emit(Instruction::Push(Operand::Register(Register::RAX, OperandSize::Qword)));
                    }
                    _ => {
                        code.emit(Instruction::Mov {
                            dest: Operand::Register(Register::RAX, OperandSize::Qword),
                            src: match lit.value {
                                LiteralValue::Int(v) => Operand::Immediate(v),
                                LiteralValue::Float(v) => Operand::Immediate(v.to_bits() as i64),
                                _ => unreachable!(),
                            },
                        });
                        code.emit(Instruction::Push(Operand::Register(Register::RAX, OperandSize::Qword)));
                    }
                }
            }

            Expression::Variable(var) => {
                let offset = code.symbols.get(&var.name).ok_or_else(|| {
                    format!("use of undeclared variable '{}' in module '{}'",
                        var.name,
                        self.current_module.as_deref().unwrap_or("<module>"))
                })?;
                code.emit(Instruction::Mov {
                    dest: Operand::Register(Register::RAX, OperandSize::Qword),
                    src: Operand::Memory {
                        base: Some(Register::RBP),
                        index: None,
                        displacement: -offset,
                        size: OperandSize::Qword,
                    },
                });
                code.emit(Instruction::Push(Operand::Register(Register::RAX, OperandSize::Qword)));
            }

            Expression::Binary { op, left, right } => {
                self.generate_expression(code, left)?;
                self.generate_expression(code, right)?;

                code.emit(Instruction::Pop(Operand::Register(Register::RCX, OperandSize::Qword)));
                code.emit(Instruction::Pop(Operand::Register(Register::RAX, OperandSize::Qword)));

                match op {
                    BinaryOp::Add => code.emit(Instruction::Add {
                        dest: Operand::Register(Register::RAX, OperandSize::Qword),
                        src: Operand::Register(Register::RCX, OperandSize::Qword),
                    }),
                    BinaryOp::Sub => code.emit(Instruction::Sub {
                        dest: Operand::Register(Register::RAX, OperandSize::Qword),
                        src: Operand::Register(Register::RCX, OperandSize::Qword),
                    }),
                    BinaryOp::Mul => code.emit(Instruction::Imul {
                        dest: Operand::Register(Register::RAX, OperandSize::Qword),
                        src: Operand::Register(Register::RCX, OperandSize::Qword),
                    }),
                    // Signed division: RDX:RAX / RCX -> quotient in RAX,
                    // remainder in RDX. We implement both Div (quotient) and
                    // Mod (remainder) by choosing which result to keep.
                    BinaryOp::Div => {
                        code.emit(Instruction::Cqo);
                        code.emit(Instruction::Idiv {
                            src: Operand::Register(Register::RCX, OperandSize::Qword),
                        });
                    }
                    BinaryOp::Mod => {
                        code.emit(Instruction::Cqo);
                        code.emit(Instruction::Idiv {
                            src: Operand::Register(Register::RCX, OperandSize::Qword),
                        });
                        code.emit(Instruction::Mov {
                            dest: Operand::Register(Register::RAX, OperandSize::Qword),
                            src: Operand::Register(Register::RDX, OperandSize::Qword),
                        });
                    }
                    BinaryOp::BitAnd => code.emit(Instruction::And {
                        dest: Operand::Register(Register::RAX, OperandSize::Qword),
                        src: Operand::Register(Register::RCX, OperandSize::Qword),
                    }),
                    BinaryOp::BitOr => code.emit(Instruction::Or {
                        dest: Operand::Register(Register::RAX, OperandSize::Qword),
                        src: Operand::Register(Register::RCX, OperandSize::Qword),
                    }),
                    BinaryOp::BitXor => code.emit(Instruction::Xor {
                        dest: Operand::Register(Register::RAX, OperandSize::Qword),
                        src: Operand::Register(Register::RCX, OperandSize::Qword),
                    }),
                    // Shifts: x86 shift by CL, result lands in RAX.
                    BinaryOp::Shl => code.emit(Instruction::Shl {
                        dest: Operand::Register(Register::RAX, OperandSize::Qword),
                        count: Operand::Register(Register::RCX, OperandSize::Byte),
                    }),
                    BinaryOp::Shr => code.emit(Instruction::Shr {
                        dest: Operand::Register(Register::RAX, OperandSize::Qword),
                        count: Operand::Register(Register::RCX, OperandSize::Byte),
                    }),
                    // Comparisons: cmp rax, rcx then set RAX to 0/1 via
                    // setCC + movzx. The order matters: `cmp rax, rcx`
                    // performs `rax - rcx`, so the sign of the flags matches
                    // the operand order written in the source.
                    BinaryOp::Eq => {
                        code.emit(Instruction::Cmp {
                            left: Operand::Register(Register::RAX, OperandSize::Qword),
                            right: Operand::Register(Register::RCX, OperandSize::Qword),
                        });
                        self.setcc(code, Conditional::E);
                    }
                    BinaryOp::Ne => {
                        code.emit(Instruction::Cmp {
                            left: Operand::Register(Register::RAX, OperandSize::Qword),
                            right: Operand::Register(Register::RCX, OperandSize::Qword),
                        });
                        self.setcc(code, Conditional::NE);
                    }
                    BinaryOp::Lt => {
                        code.emit(Instruction::Cmp {
                            left: Operand::Register(Register::RAX, OperandSize::Qword),
                            right: Operand::Register(Register::RCX, OperandSize::Qword),
                        });
                        self.setcc(code, Conditional::L);
                    }
                    BinaryOp::Le => {
                        code.emit(Instruction::Cmp {
                            left: Operand::Register(Register::RAX, OperandSize::Qword),
                            right: Operand::Register(Register::RCX, OperandSize::Qword),
                        });
                        self.setcc(code, Conditional::LE);
                    }
                    BinaryOp::Gt => {
                        code.emit(Instruction::Cmp {
                            left: Operand::Register(Register::RAX, OperandSize::Qword),
                            right: Operand::Register(Register::RCX, OperandSize::Qword),
                        });
                        self.setcc(code, Conditional::G);
                    }
                    BinaryOp::Ge => {
                        code.emit(Instruction::Cmp {
                            left: Operand::Register(Register::RAX, OperandSize::Qword),
                            right: Operand::Register(Register::RCX, OperandSize::Qword),
                        });
                        self.setcc(code, Conditional::GE);
                    }
                }

                code.emit(Instruction::Push(Operand::Register(Register::RAX, OperandSize::Qword)));
            }

            Expression::Unary { op, operand } => {
                self.generate_expression(code, operand)?;
                code.emit(Instruction::Pop(Operand::Register(Register::RAX, OperandSize::Qword)));

                match op {
                    UnaryOp::Pos => {
                        // Unary `+` is an identity operation: RAX already
                        // holds the operand value, no instructions needed.
                    }
                    UnaryOp::Negate => code.emit(Instruction::Neg {
                        dest: Operand::Register(Register::RAX, OperandSize::Qword),
                    }),
                    UnaryOp::Not => {
                        // Logical not: map nonzero -> 0, zero -> 1.
                        code.emit(Instruction::Test {
                            left: Operand::Register(Register::RAX, OperandSize::Qword),
                            right: Operand::Register(Register::RAX, OperandSize::Qword),
                        });
                        code.emit(Instruction::Mov {
                            dest: Operand::Register(Register::RAX, OperandSize::Qword),
                            src: Operand::Immediate(1),
                        });
                        let lz = code.new_label("zero");
                        code.emit(Instruction::Je(lz.clone()));
                        code.emit(Instruction::Mov {
                            dest: Operand::Register(Register::RAX, OperandSize::Qword),
                            src: Operand::Immediate(0),
                        });
                        code.emit(Instruction::Label(lz));
                    }
                    UnaryOp::BitNot => {
                        code.emit(Instruction::Xor {
                            dest: Operand::Register(Register::RAX, OperandSize::Qword),
                            src: Operand::Immediate(-1),
                        });
                    }
                }

                code.emit(Instruction::Push(Operand::Register(Register::RAX, OperandSize::Qword)));
            }

            Expression::Call { name, args } => {
                self.generate_call(code, name, args)?;
            }
        }
        Ok(())
    }

    // ---- Call ABI lowering ----

    fn generate_call(&mut self, code: &mut ModuleCode, name: &str, args: &Vec<Expression>) -> Result<()> {
        let arg_regs = [
            Register::RCX, Register::RDX, Register::R8, Register::R9
        ];

        code.emit(Instruction::Sub {
            dest: Operand::Register(Register::RSP, OperandSize::Qword),
            src: Operand::Immediate(SHADOW_SPACE),
        });

        // Evaluate args in reverse order so the first arg ends up on top
        // of the stack, ready to be popped into RCX first.
        for arg in args.iter().rev() {
            self.generate_expression(code, arg)?;
        }

        for (i, _) in args.iter().enumerate() {
            if i < 4 {
                code.emit(Instruction::Pop(Operand::Register(arg_regs[i], OperandSize::Qword)));
            }
        }

        if args.len() > 4 {
            let extra = ((args.len() - 4) * 8) as i64;
            code.emit(Instruction::Add {
                dest: Operand::Register(Register::RSP, OperandSize::Qword),
                src: Operand::Immediate(extra),
            });
        }

        self.emit_call_and_cleanup(code, name, args.len());
        code.emit(Instruction::Push(Operand::Register(Register::RAX, OperandSize::Qword)));
        Ok(())
    }

    // ---- Sink lowering ----

    fn generate_sink(&mut self, code: &mut ModuleCode, sink: &SinkCall) -> Result<()> {
        match sink.name.as_str() {
            "print" => self.lower_print(code, sink),
            "puts" => self.lower_puts(code, sink),
            "putchar" => self.lower_putchar(code, sink),
            _ => Err(format!("unknown sink '{}'", sink.name)),
        }
    }

    // Lower `print(expr).out` (and bare `print(expr)`): pop the last value
    // off the evaluation stack into RAX and call msvcrt `printf` with a
    // "%lld\n" format string. Any additional values pushed earlier in the
    // statement are popped and dropped so the stack stays balanced.
    fn lower_print(&mut self, code: &mut ModuleCode, sink: &SinkCall) -> Result<()> {
        if sink.args.is_empty() {
            return Ok(());
        }

        // Detect if the last (printed) argument is a string literal.
        let is_string = sink.args.last().map_or(false, |arg| {
            matches!(arg, Expression::Literal(lit) if matches!(lit.value, LiteralValue::String(_)))
        });

        // Evaluate each argument in order, pushing onto the stack, then
        // pop them all but only the *last* (topmost) value becomes the
        // printable effect. Earlier arguments are accepted and dropped.
        for arg in &sink.args {
            self.generate_expression(code, arg)?;
        }
        for _ in &sink.args {
            code.emit(Instruction::Pop(Operand::Register(Register::RAX, OperandSize::Qword)));
        }

        code.emit(Instruction::Sub {
            dest: Operand::Register(Register::RSP, OperandSize::Qword),
            src: Operand::Immediate(SHADOW_SPACE),
        });

        match self.format {
            OutputFormat::Asm | OutputFormat::Pe => {
                code.add_extern("printf");
                let format_label = if is_string {
                    code.intern_data("fmt_str_newline", b"%s\n\x00")
                } else {
                    code.intern_data("fmt_i64_newline", b"%lld\n\x00")
                };
                code.emit(Instruction::Lea {
                    dest: Operand::Register(Register::RCX, OperandSize::Qword),
                    src: Operand::Label(format_label),
                });
                code.emit(Instruction::Mov {
                    dest: Operand::Register(Register::RDX, OperandSize::Qword),
                    src: Operand::Register(Register::RAX, OperandSize::Qword),
                });
                self.emit_call_and_cleanup(code, "printf", 2);
            }
            OutputFormat::RustSource => {
                let target = if is_string { "bxen_print_str" } else { "bxen_print_int" };
                code.add_extern(target);
                code.emit(Instruction::Mov {
                    dest: Operand::Register(Register::RCX, OperandSize::Qword),
                    src: Operand::Register(Register::RAX, OperandSize::Qword),
                });
                self.emit_call_and_cleanup(code, target, 1);
            }
        }

        Ok(())
    }

    // Lower `puts(str).out` — call msvcrt `puts` with the string pointer.
    fn lower_puts(&mut self, code: &mut ModuleCode, sink: &SinkCall) -> Result<()> {
        let target = match self.format {
            OutputFormat::Asm | OutputFormat::Pe => "puts",
            OutputFormat::RustSource => "bxen_print_str",
        };
        self.lower_extern_sink(code, sink, target)
    }

    // Lower `putchar(ch).out` — call msvcrt `putchar` with the char value.
    fn lower_putchar(&mut self, code: &mut ModuleCode, sink: &SinkCall) -> Result<()> {
        let target = match self.format {
            OutputFormat::Asm | OutputFormat::Pe => "putchar",
            OutputFormat::RustSource => "bxen_putchar",
        };
        self.lower_extern_sink(code, sink, target)
    }

    // ---- Helpers ----

    /// Emit a call followed by the `add rsp, 32` that cleans up the
    /// shadow space. The matching `sub rsp, 32` must be emitted by the
    /// caller before arg evaluation (see `generate_call`, `emit_exit`,
    /// and `lower_print` for the canonical pattern).
    fn emit_call_and_cleanup(&mut self, code: &mut ModuleCode, target: &str, arg_count: usize) {
        code.emit(Instruction::Call { target: target.to_string(), arg_count });
        code.emit(Instruction::Add {
            dest: Operand::Register(Register::RSP, OperandSize::Qword),
            src: Operand::Immediate(SHADOW_SPACE),
        });
    }

    /// Evaluate all sink args, pop the last into RCX, and call an extern
    /// function with one argument via shadow-space boilerplate.
    fn lower_extern_sink(&mut self, code: &mut ModuleCode, sink: &SinkCall, name: &str) -> Result<()> {
        code.add_extern(name);
        if sink.args.is_empty() {
            return Ok(());
        }
        for arg in &sink.args {
            self.generate_expression(code, arg)?;
        }
        for _ in &sink.args {
            code.emit(Instruction::Pop(Operand::Register(Register::RCX, OperandSize::Qword)));
        }
        code.emit(Instruction::Sub {
            dest: Operand::Register(Register::RSP, OperandSize::Qword),
            src: Operand::Immediate(SHADOW_SPACE),
        });
        self.emit_call_and_cleanup(code, name, 1);
        Ok(())
    }

    /// Emit a `setCC al` followed by `movzx rax, al` so the boolean result
    /// of the preceding `cmp` lands in RAX as a clean 0/1 i64. The Cmp is
    /// emitted by the caller so the operand order is fixed in the source.
    fn setcc(&mut self, code: &mut ModuleCode, cond: Conditional) {
        code.emit(Instruction::Setcc {
            cond,
            dest: Operand::Register(Register::RAX, OperandSize::Byte),
        });
        code.emit(Instruction::Movzx {
            dest: Operand::Register(Register::RAX, OperandSize::Qword),
            src: Operand::Register(Register::RAX, OperandSize::Byte),
        });
    }

    /// Terminate the program by calling ExitProcess with the value in RAX.
    /// This is the canonical Windows way to leave a process; returning from
    /// `main` is also valid but the loader's behaviour for raw assembly
    /// entry points is murkier. We pop nothing here — RAX is whatever the
    /// last expression happened to produce, or zero if the module ends on
    /// an assignment (which leaves RAX holding the assigned value).
fn emit_exit(&mut self, code: &mut ModuleCode) {
    code.add_extern("ExitProcess");

    // Pop the top-of-stack value into RAX (the evaluation stack convention).
    code.emit(Instruction::Pop(Operand::Register(Register::RAX, OperandSize::Qword)));
    code.emit(Instruction::Mov {
        dest: Operand::Register(Register::RCX, OperandSize::Qword),
        src: Operand::Register(Register::RAX, OperandSize::Qword),
    });
    code.emit(Instruction::Sub {
        dest: Operand::Register(Register::RSP, OperandSize::Qword),
        src: Operand::Immediate(SHADOW_SPACE),
    });
    self.emit_call_and_cleanup(code, "ExitProcess", 1);
}
}

// ============================================================================
// Output Formatters
// ============================================================================

/// Format a vector of compiled modules as NASM assembly source.
fn format_as_asm(modules: &[ModuleCode]) -> String {
    let mut out = String::new();
    out.push_str("; Generated by Bxen Stage 0 compiler\n");
    out.push_str("; Target: Windows x64 (Microsoft calling convention)\n");
    out.push_str("default rel\n\n");

    for code in modules {
        if !code.externs.is_empty() {
            out.push_str("extern ");
            out.push_str(&code.externs.join(", "));
            out.push_str("\n\n");
        }
        out.push_str("section .text\n");
        for inst in &code.instructions {
            out.push_str(&format!("    {}\n", inst));
        }
        out.push_str("\n");
        if !code.data_items.is_empty() {
            out.push_str("section .rdata\n");
            for (name, bytes) in &code.data_items {
                out.push_str(&format!("{}:", name));
                out.push_str(&format!("    db {}\n",
                    bytes.iter()
                        .map(|b| b.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")));
            }
            out.push_str("\n");
        }
    }
    out
}

/// Format a vector of compiled modules as a Rust source file with
/// `global_asm!()` for code+data and `fn main()` as the C entry point.
/// The result can be compiled directly with `rustc` to produce a working
/// Windows x64 executable with no external tooling needed.
fn format_rust_source(modules: &[ModuleCode]) -> Result<String> {
    let mut out = String::new();
    out.push_str("// Generated by Bxen Stage 0 compiler\n\n");

    // Collect unique externs across all modules, skipping bxen_* helpers
    // (they are Rust functions defined in this file, not DLL imports).
    let all_externs: Vec<&str> = {
        let mut seen = std::collections::BTreeSet::new();
        for code in modules {
            for ext in &code.externs {
                if !ext.starts_with("bxen_") {
                    seen.insert(ext.as_str());
                }
            }
        }
        seen.into_iter().collect()
    };

    // Windows API declarations (kernel32.dll — always available)
    out.push_str("extern \"system\" {\n");
    out.push_str("    fn GetStdHandle(nStdHandle: u32) -> isize;\n");
    out.push_str("    fn WriteFile(\n");
    out.push_str("        hFile: isize,\n");
    out.push_str("        lpBuffer: *const u8,\n");
    out.push_str("        nNumberOfBytesToWrite: u32,\n");
    out.push_str("        lpNumberOfBytesWritten: *mut u32,\n");
    out.push_str("        lpOverlapped: *const u8,\n");
    out.push_str("    ) -> i32;\n");
    out.push_str("}\n\n");

    // CRT / kernel32 externs (only ExitProcess is needed for the Rust format)
    out.push_str("#[allow(dead_code)]\nextern \"C\" {\n");
    for ext in &all_externs {
        match *ext {
            "ExitProcess" => out.push_str("    fn ExitProcess(code: u32) -> !;\n"),
            _ => {}
        }
    }
    out.push_str("}\n\n");

    // --- Helper functions (Windows API I/O, no CRT dependency) ---
    out.push_str("const STD_OUTPUT_HANDLE: u32 = 0xFFFFFFF5u32;\n");
    out.push_str("static mut STDOUT: isize = 0;\n\n");

    out.push_str("fn ensure_stdout() -> isize {\n");
    out.push_str("    unsafe {\n");
    out.push_str("        if STDOUT == 0 {\n");
    out.push_str("            STDOUT = GetStdHandle(STD_OUTPUT_HANDLE);\n");
    out.push_str("        }\n");
    out.push_str("        STDOUT\n");
    out.push_str("    }\n");
    out.push_str("}\n\n");

    // bxen_print_int: write a signed i64 as decimal followed by newline
    out.push_str("#[no_mangle]\npub unsafe extern \"C\" fn bxen_print_int(val: i64) {\n");
    out.push_str("    let mut buf = [0u8; 20];\n");
    out.push_str("    let mut pos = 19usize;\n");
    out.push_str("    let mut n = if val < 0 { val.unsigned_abs() } else { val as u64 };\n");
    out.push_str("    loop {\n");
    out.push_str("        buf[pos] = b'0' + (n % 10) as u8;\n");
    out.push_str("        if n < 10 { break; }\n");
    out.push_str("        n /= 10;\n");
    out.push_str("        pos -= 1;\n");
    out.push_str("    }\n");
    out.push_str("    if val < 0 { pos -= 1; buf[pos] = b'-'; }\n");
    out.push_str("    let slice = core::slice::from_raw_parts(buf.as_ptr().add(pos), 20 - pos);\n");
    out.push_str("    let mut nl = b'\\n';\n");
    out.push_str("    let h = ensure_stdout();\n");
    out.push_str("    let mut written = 0u32;\n");
    out.push_str("    WriteFile(h, slice.as_ptr(), slice.len() as u32, &mut written, core::ptr::null());\n");
    out.push_str("    WriteFile(h, &mut nl, 1, &mut written, core::ptr::null());\n");
    out.push_str("}\n\n");

    // bxen_print_str: write a null-terminated string followed by newline
    out.push_str("#[no_mangle]\npub unsafe extern \"C\" fn bxen_print_str(s: *const u8) {\n");
    out.push_str("    let mut len = 0u32;\n");
    out.push_str("    while *s.add(len as usize) != 0 { len += 1; }\n");
    out.push_str("    let mut nl = b'\\n';\n");
    out.push_str("    let h = ensure_stdout();\n");
    out.push_str("    let mut written = 0u32;\n");
    out.push_str("    WriteFile(h, s, len, &mut written, core::ptr::null());\n");
    out.push_str("    WriteFile(h, &mut nl, 1, &mut written, core::ptr::null());\n");
    out.push_str("}\n\n");

    // bxen_putchar: write a single byte
    out.push_str("#[no_mangle]\npub unsafe extern \"C\" fn bxen_putchar(c: i64) {\n");
    out.push_str("    let mut ch = c as u8;\n");
    out.push_str("    let h = ensure_stdout();\n");
    out.push_str("    let mut written = 0u32;\n");
    out.push_str("    WriteFile(h, &mut ch, 1, &mut written, core::ptr::null());\n");
    out.push_str("}\n\n");

    // --- global_asm! block (code + data) ---
    out.push_str("core::arch::global_asm!(\n");

    let mut entry_emitted = false;
    for code in modules {
        out.push_str("    \".section .text\",\n");

        for inst in &code.instructions {
            // Insert bxen_main label just before the first .Lentry_N
            if !entry_emitted {
                if let Instruction::Label(ref name) = inst {
                    if name.starts_with(".Lentry_") {
                        out.push_str("    \".globl bxen_main\",\n");
                        out.push_str("    \"bxen_main:\",\n");
                        entry_emitted = true;
                    }
                }
            }

            let line = format_instruction_rust(inst);
            for ln in line.lines() {
                out.push_str(&format!("    \"    {}\",\n", ln));
            }
        }
        out.push_str("    \"\",\n");

        if !code.data_items.is_empty() {
            out.push_str("    \".section .rdata\",\n");
            for (name, bytes) in &code.data_items {
                out.push_str(&format!("    \"{}:\",\n", name));
                let byte_list: Vec<String> = bytes.iter().map(|b| b.to_string()).collect();
                out.push_str(&format!("    \"    .byte {}\",\n", byte_list.join(", ")));
            }
            out.push_str("    \"\",\n");
        }
    }

    out.push_str(");\n\n");

    // fn main() that calls bxen_main
    out.push_str("fn main() {\n");
    out.push_str("    unsafe { core::arch::asm!(\"call bxen_main\"); }\n");
    out.push_str("}\n");

    Ok(out)
}

/// Like `Instruction::fmt()` but uses `[rip + label]` syntax for LEA
/// with a label operand (required by LLVM MC's Intel syntax in global_asm!).
fn format_instruction_rust(instr: &Instruction) -> String {
    if let Instruction::Lea { dest, src: Operand::Label(l) } = instr {
        format!("lea {}, [rip + {}]", dest, l)
    } else if let Instruction::Cmp { left: Operand::Register(r, _), right: Operand::Immediate(v) } = instr {
        format!("cmp {}, {}", r, v)
    } else {
        format!("{}", instr)
    }
}

// ---- Module-level helpers ----

/// Round `n` up to the next multiple of 16. Windows x64 requires the
/// stack pointer to be 16-byte aligned prior to any `call` (i.e. when
/// the call pushes the return address the resulting RSP is 8 mod 16
/// and the prologue re-aligns it). Locals are sized in multiples of 8
/// but the reservation keeps RSP aligned *above* shadow space + locals.
fn align_to_16(n: i64) -> i64 {
    (n + 15) & !15
}
