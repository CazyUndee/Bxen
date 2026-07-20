use crate::compiler::x64::{ExternFixup, RipRelFixup};

pub type Result<T> = std::result::Result<T, String>;

/// Build a minimal PE32+ executable. Returns the raw `.exe` bytes.
///
/// `iat_fixups` lists the code offsets and function names for every
/// indirect call through the IAT. The PE writer patches each 4-byte
/// placeholder to a RIP-relative offset pointing into the IAT.
///
/// `rip_fixups` lists code offsets for RIP-relative references to data
/// labels (strings, etc.). These are patched to point to the correct
/// location in .rdata.
pub fn build_pe(
    code: &mut [u8],
    data_items: &[(String, Vec<u8>)],
    externs: &[String],
    iat_fixups: &[ExternFixup],
    rip_fixups: &[RipRelFixup],
) -> Result<Vec<u8>> {
    let writer = PeWriter { externs };
    writer.build(code, data_items, iat_fixups, rip_fixups)
}

struct PeWriter<'a> {
    externs: &'a [String],
}

impl<'a> PeWriter<'a> {
    fn build(&self, code: &mut [u8], data_items: &[(String, Vec<u8>)], iat_fixups: &[ExternFixup], rip_fixups: &[RipRelFixup]) -> Result<Vec<u8>> {
        // --- Partition externs by DLL ---
        let (kernel32_imports, _msvcrt_imports): (Vec<&str>, Vec<&str>) = self.externs.iter()
            .map(|s| s.as_str())
            .partition(|s| *s == "ExitProcess");
        // Remaining go to msvcrt
        let msvcrt_imports: Vec<&str> = self.externs.iter()
            .filter(|s| *s != "ExitProcess")
            .map(|s| s.as_str())
            .collect();

        let mut dll_imports: Vec<(&str, &[&str])> = Vec::new();
        if !kernel32_imports.is_empty() {
            dll_imports.push(("kernel32.dll", kernel32_imports.as_slice()));
        }
        if !msvcrt_imports.is_empty() {
            dll_imports.push(("msvcrt.dll", msvcrt_imports.as_slice()));
        }

        // --- Compute .rdata layout ---
        let data_bytes_len: usize = data_items.iter().map(|(_, b)| b.len()).sum();
        let data_pad = pad_len(data_bytes_len, 16);

        // Import directory layout within .rdata:
        // [import descriptors] 20 bytes each, DLL count + 1 null terminator
        // [hint-name entries]   2+len(name)+1 per function
        // [DLL name strings]    len(dll)+1 each
        // [IAT]                 8 bytes per function + 1 null terminator

        let desc_size = (dll_imports.len() + 1) * 20;
        let mut hint_name_size = 0usize;
        let mut func_count = 0usize;
        for (_, funcs) in &dll_imports {
            for f in *funcs {
                hint_name_size += 2 + f.len() + 1; // hint(2) + name + null
                func_count += 1;
            }
        }
        let dll_name_size: usize = dll_imports.iter().map(|(d, _)| d.len() + 1).sum();
        // One 8-byte IAT slot per function PLUS one 8-byte NULL terminator
        // per DLL (so the loader walks each DLL's OFT independently).
        let iat_size = (func_count + dll_imports.len()) * 8;

        let import_start = data_bytes_len + data_pad;
        let hint_name_start = import_start + desc_size;
        let dll_name_start = hint_name_start + hint_name_size;
        let iat_start = dll_name_start + dll_name_size;

        // --- Compute section RVAs ---
        const SECT_ALIGN: u64 = 0x1000;
        const FILE_ALIGN: u64 = 0x200;

        let text_va = 0x1000u64;
        let code_len = align_u64(code.len() as u64, FILE_ALIGN);
        let rdata_va = text_va + align_u64(code.len() as u64, SECT_ALIGN);
        let rdata_raw_size = iat_start + iat_size;
        let rdata_file_size = align_u64(rdata_raw_size as u64, FILE_ALIGN);
        let rdata_virt_size = align_u64(rdata_raw_size as u64, SECT_ALIGN);

        let image_size = align_u64(rdata_va + rdata_virt_size, SECT_ALIGN);

        // Offsets in file
        let hdr_size = 0x200u64; // 512 bytes for headers
        let text_raw_off = hdr_size;
        let rdata_raw_off = text_raw_off + code_len;

        // --- Patch @IAT@ fixups in code ---
        let base_va = 0x140000000u64;
        let iat_va = rdata_va + iat_start as u64;
        self.patch_iat_fixups(code, base_va, text_va, iat_va, &dll_imports, iat_fixups);

        // --- Patch RIP-relative data label fixups ---
        // Compute RVA of each data label within .rdata
        let mut label_rvas: std::collections::HashMap<&str, u64> = std::collections::HashMap::new();
        let mut data_offset = 0usize;
        for (name, bytes) in data_items {
            label_rvas.insert(name.as_str(), rdata_va + data_offset as u64);
            data_offset += bytes.len();
        }
        self.patch_rip_fixups(code, text_va, &label_rvas, rip_fixups);

        // --- Build PE output ---
        let mut out = Vec::new();

        // DOS header (64 bytes). e_lfanew at offset 0x3C points to the PE
        // signature at offset 0x80.
        out.extend_from_slice(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00");
        out.resize(0x40, 0);
        out[0x3C..0x3C+4].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew = 0x80

        // DOS stub (just pad to 0x80)
        out.resize(0x80, 0);

        // PE signature
        out.extend_from_slice(b"PE\x00\x00");

        // COFF header (20 bytes)
        out.extend_from_slice(&0x8664u16.to_le_bytes()); // machine: AMD64
        out.extend_from_slice(&2u16.to_le_bytes());      // sections
        out.extend_from_slice(&0u32.to_le_bytes());      // timestamp
        out.extend_from_slice(&0u32.to_le_bytes());      // symtab ptr
        out.extend_from_slice(&0u32.to_le_bytes());      // sym count
        out.extend_from_slice(&240u16.to_le_bytes());    // optional hdr size
        out.extend_from_slice(&0x22Eu16.to_le_bytes());  // characteristics

        // PE32+ optional header (240 bytes)
        // Standard fields
        out.extend_from_slice(&0x020Bu16.to_le_bytes()); // PE32+ magic
        out.push(0x10u8);                                  // major linker
        out.push(0x00u8);                                  // minor linker
        out.extend_from_slice(&(code_len as u32).to_le_bytes()); // size of code
        out.extend_from_slice(&(rdata_file_size as u32).to_le_bytes()); // size init data
        out.extend_from_slice(&0u32.to_le_bytes());      // size uninit data
        out.extend_from_slice(&(text_va as u32).to_le_bytes()); // entry point RVA
        out.extend_from_slice(&(text_va as u32).to_le_bytes()); // base of code
        // NT additional fields (PE32+)
        out.extend_from_slice(&base_va.to_le_bytes());   // image base
        out.extend_from_slice(&(SECT_ALIGN as u32).to_le_bytes());
        out.extend_from_slice(&(FILE_ALIGN as u32).to_le_bytes());
        out.extend_from_slice(&6u16.to_le_bytes());      // major OS
        out.extend_from_slice(&0u16.to_le_bytes());      // minor OS
        out.extend_from_slice(&0u16.to_le_bytes());      // major image
        out.extend_from_slice(&0u16.to_le_bytes());      // minor image
        out.extend_from_slice(&6u16.to_le_bytes());      // major subsystem
        out.extend_from_slice(&0u16.to_le_bytes());      // minor subsystem
        out.extend_from_slice(&0u32.to_le_bytes());      // Win32 version
        out.extend_from_slice(&(image_size as u32).to_le_bytes()); // size of image
        out.extend_from_slice(&(hdr_size as u32).to_le_bytes());   // size of headers
        out.extend_from_slice(&0u32.to_le_bytes());      // checksum
        out.extend_from_slice(&3u16.to_le_bytes());      // subsystem: CONSOLE
        out.extend_from_slice(&0x8140u16.to_le_bytes()); // DLL characteristics

        out.extend_from_slice(&0x100000u64.to_le_bytes()); // stack reserve
        out.extend_from_slice(&0x1000u64.to_le_bytes());   // stack commit
        out.extend_from_slice(&0x100000u64.to_le_bytes()); // heap reserve
        out.extend_from_slice(&0x1000u64.to_le_bytes());   // heap commit
        out.extend_from_slice(&0u32.to_le_bytes());        // loader flags
        out.extend_from_slice(&16u32.to_le_bytes());       // data directory count

        // Data directories (16 entries, 8 bytes each)
        // Export
        out.extend_from_slice(&0u64.to_le_bytes());
        // Import
        let import_rva = rdata_va + import_start as u64;
        out.extend_from_slice(&(import_rva as u32).to_le_bytes());
        out.extend_from_slice(&(desc_size as u32).to_le_bytes());
        // Rest (14 zeros)
        for _ in 0..14 {
            out.extend_from_slice(&0u64.to_le_bytes());
        }

        assert_eq!(out.len() - 0x80 - 4 - 20, 240);

        // Section table
        fn write_section(out: &mut Vec<u8>, name: &[u8; 8], vsize: u32, va: u32,
                         rsize: u32, roff: u32, chars: u32) {
            out.extend_from_slice(name);
            out.extend_from_slice(&vsize.to_le_bytes());
            out.extend_from_slice(&va.to_le_bytes());
            out.extend_from_slice(&rsize.to_le_bytes());
            out.extend_from_slice(&roff.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes()); // reloc
            out.extend_from_slice(&0u32.to_le_bytes()); // line nums
            out.extend_from_slice(&0u16.to_le_bytes()); // reloc count
            out.extend_from_slice(&0u16.to_le_bytes()); // line num count
            out.extend_from_slice(&chars.to_le_bytes());
        }

        // .text
        write_section(&mut out, b".text\x00\x00\x00",
            align_u64(code.len() as u64, SECT_ALIGN) as u32,
            text_va as u32,
            code_len as u32,
            text_raw_off as u32,
            0x60000020); // CODE | EXECUTE | READ

        // .rdata
        write_section(&mut out, b".rdata\x00\x00",
            rdata_virt_size as u32,
            rdata_va as u32,
            rdata_file_size as u32,
            rdata_raw_off as u32,
            0x40000040); // INITIALIZED_DATA | READ

        // Pad to text_raw_off
        out.resize(text_raw_off as usize, 0);

        // .text section: code
        out.extend_from_slice(code);
        out.resize((text_raw_off + code_len) as usize, 0);

        // .rdata section
        assert_eq!(out.len(), rdata_raw_off as usize);

        // 1. Data items
        for (_, bytes) in data_items {
            out.extend_from_slice(bytes);
        }
        // pad to import start
        out.resize((rdata_raw_off + import_start as u64) as usize, 0);

        // 2. Import descriptors
        // Each DLL gets one IMAGE_IMPORT_DESCRIPTOR (20 bytes). We track
        // per-DLL offsets into the IAT (func_offset) and the DLL name
        // string region (name_offset) so every descriptor points to the
        // correct, distinct data.
        let mut func_offset = 0usize;
        let mut name_offset = 0usize;
        for (dll_name, funcs) in &dll_imports {
            let ilt_va = iat_va + (func_offset * 8) as u64;
            let name_va = rdata_va + dll_name_start as u64 + name_offset as u64;

            // IMAGE_IMPORT_DESCRIPTOR layout:
            //   u32 OriginalFirstThunk (ILT RVA)
            //   u32 TimeDateStamp (0 — not bound)
            //   u32 ForwarderChain (0)
            //   u32 Name (RVA of DLL name string)
            //   u32 FirstThunk (IAT RVA = same as ILT)
            out.extend_from_slice(&(ilt_va as u32).to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(name_va as u32).to_le_bytes());
            out.extend_from_slice(&(ilt_va as u32).to_le_bytes());

            // Advance past this DLL's thunks PLUS its NULL terminator slot,
            // so the next DLL's IAT/ILT region starts in a fresh slot.
            func_offset += funcs.len() + 1;
            name_offset += dll_name.len() + 1;
        }
        // Null terminator descriptor
        out.extend_from_slice(&[0u8; 20]);

        // 3. Hint-name entries (one per function)
        for (_, funcs) in &dll_imports {
            for f in *funcs {
                out.extend_from_slice(&0u16.to_le_bytes()); // hint
                out.extend_from_slice(f.as_bytes());
                out.push(0); // null terminator
            }
        }

        // 4. DLL name strings
        for (dll_name, _) in &dll_imports {
            out.extend_from_slice(dll_name.as_bytes());
            out.push(0);
        }

        // 5. IAT/ILT entries: one qword per function (RVA of hint-name entry).
        // For named imports the thunk value is the RVA (not VA) of the
        // IMAGE_IMPORT_BY_NAME structure, with bit 63 clear. The loader
        // adds the image base to locate the structure, resolves the
        // function address, and overwrites this table entry.
        //
        // CRITICAL: each DLL's slot must be NULL-terminated separately,
        // otherwise the loader walks past the boundary, reads the next
        // DLL's thunk under the wrong DLL, and fails to resolve a function
        // that doesn't exist in the wrong DLL (STATUS_ENTRYPOINT_NOT_FOUND).
        let mut hint_rva = rdata_va + hint_name_start as u64;
        for (_, funcs) in &dll_imports {
            for f in *funcs {
                out.extend_from_slice(&hint_rva.to_le_bytes());
                hint_rva += 2 + f.len() as u64 + 1; // hint(2) + name + null
            }
            // Null terminator at the end of THIS DLL's IAT/ILT region.
            // The loader walks each DLL's OFT until it hits this terminator.
            out.extend_from_slice(&0u64.to_le_bytes());
        }

        // Pad to file alignment
        out.resize((rdata_raw_off + rdata_file_size) as usize, 0);

        Ok(out)
    }

    /// Patch `FF 15 [rip + disp32]` call fixups so `disp32` points to the
    /// correct IAT entry for each extern function. Each fixup is a 4-byte
    /// placeholder at the given code offset; the instruction is 6 bytes
    /// (FF 15 + 4-byte disp32), so RIP at resolution is `offset + 6` bytes
    /// into the `.text` section.
    ///
    /// `dll_imports` is the same ordering used when writing the IAT entries,
    /// so the index assigned to each function here matches its actual slot
    /// in the table.
    fn patch_iat_fixups(&self, code: &mut [u8], _base_va: u64, text_va: u64, iat_va: u64,
                        dll_imports: &[(&str, &[&str])],
                        iat_fixups: &[ExternFixup]) {
        // Build extern → IAT slot index from the dll_imports iteration order.
        // IAT layout interleaves per-DLL NULL terminators, so each DLL occupies
        // `funcs.len() + 1` slots (one extra for the terminator). Without that
        // extra slot, the next DLL's first function would collide with this
        // DLL's NULL terminator.
        let mut extern_to_index: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        let mut func_index = 0usize;
        for (_, funcs) in dll_imports {
            for f in *funcs {
                extern_to_index.insert(f, func_index);
                func_index += 1;
            }
            // Skip the NULL terminator slot.
            func_index += 1;
        }

        for fixup in iat_fixups {
            let Some(&iat_index) = extern_to_index.get(fixup.name.as_str()) else {
                continue; // skip if not an extern (shouldn't happen)
            };

            // Compute RIP-relative offset from the fixup site to the IAT entry.
            // The `FF 15 [rip + disp32]` instruction is 6 bytes; fixup.offset
            // points to the disp32 field (after the 2-byte FF 15 opcode/modrm),
            // so RIP after the instruction = text_va + fixup.offset + 4.
            let iat_entry_rva = iat_va + (iat_index as u64) * 8;
            let fixup_rip = text_va + fixup.offset + 4;
            let disp = (iat_entry_rva as i64 - fixup_rip as i64) as i32;

            let start = fixup.offset as usize;
            code[start..start + 4].copy_from_slice(&disp.to_le_bytes());
        }
    }

    /// Patch RIP-relative references to data labels (strings, etc.) in .rdata.
    /// Each fixup is a 4-byte disp32 placeholder at the given code offset.
    /// The instruction is typically `LEA reg, [rip + disp32]` (7 bytes for
    /// REX.W + opcode + modrm + disp32), so RIP at resolution =
    /// text_va + fixup.offset + 4 (the disp32 itself is 4 bytes after the
    /// preceding opcode bytes; RIP-relative addressing uses the address
    /// of the next instruction, which sits 4 bytes after the disp32).
    fn patch_rip_fixups(&self, code: &mut [u8], text_va: u64,
                        label_rvas: &std::collections::HashMap<&str, u64>,
                        rip_fixups: &[RipRelFixup]) {
        for fixup in rip_fixups {
            let Some(&target_rva) = label_rvas.get(fixup.label.as_str()) else {
                // Unknown label — skip silently (likely a local code label
                // that was already resolved by the encoder)
                continue;
            };
            let fixup_rip = text_va + fixup.offset + 4;
            let disp = (target_rva as i64 - fixup_rip as i64) as i32;
            let start = fixup.offset as usize;
            code[start..start + 4].copy_from_slice(&disp.to_le_bytes());
        }
    }
}

fn align_u64(n: u64, a: u64) -> u64 { (n + a - 1) & !(a - 1) }
fn pad_len(n: usize, a: usize) -> usize { (a - (n % a)) % a }
