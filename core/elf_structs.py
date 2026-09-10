
from dataclasses import dataclass

@dataclass
class Elf64_Ehdr:
    e_ident: bytes = b''
    e_type: int = 0
    e_machine: int = 0
    e_version: int = 0
    e_entry: int = 0
    e_phoff: int = 0
    e_shoff: int = 0
    e_flags: int = 0
    e_ehsize: int = 0
    e_phentsize: int = 0
    e_phnum: int = 0
    e_shentsize: int = 0
    e_shnum: int = 0
    e_shstrndx: int = 0
    

@dataclass
class Elf64_Phdr:
    p_type: int = 0
    p_flags: int = 0
    p_offset: int = 0
    p_vaddr: int = 0
    p_paddr: int = 0
    p_filesz: int = 0
    p_memsz: int = 0
    p_align: int = 0