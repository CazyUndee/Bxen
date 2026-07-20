# Bxen Stage 0 Implementation Guide

## Completed Work

### Language Toolchain
- **Lexer**: Hand-written lexer for Bxen v0.1 producing `TokenType` stream
- **Parser**: Recursive-descent parser that builds the AST and resolves postfix/precedence-climbing expressions
- **AST**: Core node types for `Literal`, `BinaryOp`, `UnaryOp`, `Variable`, `Call`, `Assignment`, `SinkCall`, `ModuleBlock`, `HeaderBlock`, `InputBlock`, `Program`
- **Code Generator**: NASM x86_64 code emitter with explicit Windows x64 calling convention support

### ABI Compliance
- RCX/RDX/R8/R9 calling register order
- 32-byte shadow space reserved per call
- Callee-saved register handling (RBX/RBP)
- Proper `idiv` prelude (`cqo`) for signed division
- Centralized `SHADOW_SPACE = 32` constant

### Output
- Writes NASM-formatted assembly (`.asm`) to disk
- Uses `default rel` for position-independent references
- Emits `extern ExitProcess` for Windows program termination

### Dependency Design
- ZERO external dependencies
- Pure stdlib codebase
- No proc-macros, no runtime dependencies

## Assumptions Made

### v0.1 Syntax
- Assumes postfix expression semantics (stack-based evaluation)
- Assumes `header { key: value }`, `module name: { ... }` form
- Assumes assignment form `name: expr`
- Assumes `expr.sink` notation for sinks

### Variable Handling
- Variables and assignments are parsed but NOT stored in Stage 0
- Assignment RHS is evaluated and popped into RAX (no symbol table)
- No local variable offsets, no stack slots for variables

### Sink System
- Sinks are structural placeholders navigating `print(...)` toward future runtime mapping
- No output sink is actually invoked; `nop` emitted as placeholder

### Debug Builds Only
- No optimized code path, no register constraints beyond manual allocation
- Expression lowering uses a stack-based strategy: push literal, pop operands into RAX/RCX, compute, push result

### Error Model
- All errors collapse to `String` using a local `Result<T>` alias (replaces removed `anyhow`)
- No span/backtrace recovery

## What Has NOT Been Done

### Runtime
- No `print`, `write`, `display`, or any sink target implemented
- No standard library or OS runtime linkage (no Windows API imports besides `ExitProcess`)
- No runtime stack/heap allocation

### Variables and Scope
- No symbol table
- No scoped/local variable offset allocation
- No parameter passing (inputs parsed but not lowered)

### Backend Completeness
- No `Jmp`/`Je`/control flow lowering in practice
- No SIMD emission despite support in IR (prepared for future)
- No linker integration or executable output

### Self-Hosting
- Not rewritten in Bxen
- No intermediate representation (IR)
- No optimization passes
- No executable bytecode or object output pipeline

### Testing
- No integration tests, fuzz testing, or golden assembly tests
- No test harness beyond `test.bxen` and manual CLI run

## Next Steps

### Stage 0 Harden
1. Add symbol table pass before codegen (assign `[RBP - offset]` storage)
2. Implement control-flow lowering for `if/then/else`, `while`, `begin/again`
3. Add function definitions with prologue matching ABI (argument and return slots)
4. Add sink-to-API mapping: `print` → `WriteConsoleA` or C `printf`

### Stage 0.5 — Linkable Output
1. Emit proper PE/COFF object output (not just NASM text)
2. Link subroutines across modules into single executable
3. Generate export/import tables or structure for Windows DLL linkage

### Stage 1 — Self-Hosting
1. Define minimal Bxen runtime in assembly
2. Write bootstrapping runtime in Bxen syntax using existing parser/codegen
3. Translate runtime primitives to equivalent NASM
4. Replace C-written lexer/parser/codegen with Bxen-emitted alternatives

## Design Rationale

### Why NASM First
- Lowest barrier to validating calling conventions and stack discipline
- Readable assembly output enables manual verification of ABI compliance
- Direct bridge to linker and executable generation

### Why No IR in Stage 0
- Extra passes add complexity without correctness wins for Stage 0
- Direct lowering reduces codebase size and simplifies bootstrap rewrite in Bxen
- IR is not necessary until multiple backends or optimizations are required

### Why Pure Stdlib
- Maximizes bootstrap feasibility (no build scripts, no proc-macros)
- Removes linker/cross-compilation dependency issues
- Keeps toolchain portable through the self-hosting transition
