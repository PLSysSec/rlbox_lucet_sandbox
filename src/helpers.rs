use crate::types::Error;

use goblin::{elf, Object};

use lucet_module_data::{ModuleData, Signature};

use std::fs::File;
use std::io::Read;

pub(crate) fn get_signatures(path: &String) -> Result<Vec<Signature>, Error> {
    let mut fd = File::open(path).expect("open");
    let mut buffer = Vec::new();
    fd.read_to_end(&mut buffer).expect("read");
    let object = Object::parse(&buffer).expect("parse");

    if let Object::Elf(eo) = object {
        for ref sym in eo.syms.iter() {
            let name = eo.strtab.get(sym.st_name);

            if name.is_some() && name.unwrap()? == "lucet_module_data" {
                let module_data_bytes = read_memory(&buffer, &eo, sym.st_value, sym.st_size)?;
                let module_data = ModuleData::deserialize(module_data_bytes)?;
                let signatures = module_data.signatures().to_vec();
                return Ok(signatures);
            }
        }
    }

    return Err(Error::LucetRLBoxError(
        "Could not find symbol `lucet_module_data` from module!",
    ));
}

fn read_memory<'a>(
    buffer: &'a Vec<u8>,
    elf: &'a elf::Elf,
    addr: u64,
    size: u64,
) -> Result<&'a [u8], Error> {
    for header in &elf.program_headers {
        if header.p_type == elf::program_header::PT_LOAD {
            // Bounds check the entry
            if addr >= header.p_vaddr && (addr + size) <= (header.p_vaddr + header.p_memsz) {
                let start = (addr - header.p_vaddr + header.p_offset) as usize;
                let end = start + size as usize;

                return Ok(&buffer[start..end]);
            }
        }
    }

    return Err(Error::LucetRLBoxError(
        "Out of bounds while reading module signatures",
    ));
}
