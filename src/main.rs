mod compiler;

use compiler::codegen::{CodeGenerator, OutputFormat};
use compiler::lexer::Lexer;
use compiler::parser::Parser;
use compiler::pe;
use compiler::x64::{self, ExternFixup, RipRelFixup};
use std::fs;
use std::process;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: bxen <input.bxen> [output] [--emit asm|rust]");
        process::exit(1);
    }

    let input_path = &args[1];

    let mut emit = OutputFormat::Asm;
    let mut output_path: Option<&str> = None;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--emit" => {
                i += 1;
                let val = args.get(i).unwrap_or_else(|| {
                    eprintln!("[bxen] --emit requires an argument: asm or rust");
                    process::exit(1);
                });
                match val.as_str() {
                    "asm" => emit = OutputFormat::Asm,
                    "rust" => emit = OutputFormat::RustSource,
                    "pe" => emit = OutputFormat::Pe,
                    other => {
                        eprintln!("[bxen] Unknown --emit value '{}' (expected asm, rust, or pe)", other);
                        process::exit(1);
                    }
                }
            }
            _ => {
                // positional output path (only takes the first positional)
                if output_path.is_none() {
                    output_path = Some(&args[i]);
                }
            }
        }
        i += 1;
    }

    let output_path = output_path.unwrap_or(match emit {
        OutputFormat::Asm => "output.asm",
        OutputFormat::RustSource => "output.rs",
        OutputFormat::Pe => "output.exe",
    });

    let source = match fs::read_to_string(input_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[bxen] Error reading '{}': {}", input_path, e);
            process::exit(1);
        }
    };
    eprintln!("[bxen] Compiling: {}", input_path);

    let tokens = match Lexer::tokenize(&source) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[bxen] Lexer error: {}", e);
            process::exit(1);
        }
    };

    let program = match Parser::parse(tokens) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[bxen] Parse error: {}", e);
            process::exit(1);
        }
    };

    let mut codegen = CodeGenerator::new();

    match emit {
        OutputFormat::Pe => {
            // Native PE output: generate instruction IR → x86-64 encode → PE package.
            let modules = match codegen.generate_modules(&program, OutputFormat::Pe) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("[bxen] Codegen error: {}", e);
                    process::exit(1);
                }
            };

            let mut code = Vec::new();
            let mut data_items: Vec<(String, Vec<u8>)> = Vec::new();
            let mut externs: Vec<String> = Vec::new();
            let mut all_iat_fixups: Vec<ExternFixup> = Vec::new();
            let mut all_rip_fixups: Vec<RipRelFixup> = Vec::new();
            let mut code_offset: u64 = 0;

            for module in &modules {
                let (mut module_code, iat_fixups, rip_fixups) =
                    x64::encode(&module.instructions, &module.externs);

                // Adjust fixup offsets from per-module to global code position.
                for mut f in iat_fixups {
                    f.offset += code_offset;
                    all_iat_fixups.push(f);
                }
                for mut f in rip_fixups {
                    f.offset += code_offset;
                    all_rip_fixups.push(f);
                }

                code.append(&mut module_code);
                data_items.extend(module.data_items.clone());
                for ext in &module.externs {
                    if !externs.contains(ext) {
                        externs.push(ext.clone());
                    }
                }
                code_offset = code.len() as u64;
            }

            let exe_bytes = match pe::build_pe(&mut code, &data_items, &externs, &all_iat_fixups, &all_rip_fixups) {
                Ok(bytes) => bytes,
                Err(e) => {
                    eprintln!("[bxen] PE build error: {}", e);
                    process::exit(1);
                }
            };

            if let Err(e) = fs::write(output_path, exe_bytes) {
                eprintln!("[bxen] Write error: {}", e);
                process::exit(1);
            }
        }
        _ => {
            let output = match codegen.generate(&program, emit) {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("[bxen] Codegen error: {}", e);
                    process::exit(1);
                }
            };

            if let Err(e) = fs::write(output_path, output) {
                eprintln!("[bxen] Write error: {}", e);
                process::exit(1);
            }
        }
    }
    eprintln!("[bxen] Output written to: {}", output_path);
}
