import ctypes
import struct
from typing import List, Optional, Type, TypeVar

from elftools.elf.elffile import ELFFile

from core.logger import Log

from .elf_structs import Elf64_Ehdr, Elf64_Phdr

log = Log("ElfReader")

T = TypeVar("T", bound=ctypes.Structure)


class ELFReader:
    def __init__(self, path):
        self.path = path
        self.file = open(path, "rb")
        self.elf = ELFFile(self.file)
        self._elf_header = self._read_elf64_header()
        self._program_segments = self._read_elf64_phdrs()

        self.is64 = self.elf.elfclass == 64
        self.arch = self.elf.get_machine_arch()

        self.load_segments = []

        # log.warn("Building relocations, its can take a while...")

        # self.relocations = self._build_relocations()

        for seg in self.elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue

            self.load_segments.append({
                "vaddr": seg["p_vaddr"],
                "offset": seg["p_offset"],
                "filesz": seg["p_filesz"],
                "memsz": seg["p_memsz"],
                "flags": seg["p_flags"],
                "align": seg["p_align"],
            })

        self.load_segments.sort(
            key=lambda x: x["vaddr"]
        )

    # ================================================================
    # ELF header
    # ================================================================

    def _read_elf64_header(self) -> Elf64_Ehdr:
        ehdr = self.elf.header

        header = Elf64_Ehdr()

        header.e_ident = ehdr["e_ident"]
        header.e_type = ehdr["e_type"]
        header.e_machine = ehdr["e_machine"]
        header.e_version = ehdr["e_version"]
        header.e_entry = ehdr["e_entry"]
        header.e_phoff = ehdr["e_phoff"]
        header.e_shoff = ehdr["e_shoff"]
        header.e_flags = ehdr["e_flags"]
        header.e_ehsize = ehdr["e_ehsize"]
        header.e_phentsize = ehdr["e_phentsize"]
        header.e_phnum = ehdr["e_phnum"]
        header.e_shentsize = ehdr["e_shentsize"]
        header.e_shnum = ehdr["e_shnum"]
        header.e_shstrndx = ehdr["e_shstrndx"]

        return header

    # ================================================================
    # Program headers
    # ================================================================

    def _read_elf64_phdrs(self) -> List[Elf64_Phdr]:
        segments = []

        for seg in self.elf.iter_segments():
            phdr = Elf64_Phdr()

            phdr.p_type = seg["p_type"]
            phdr.p_flags = seg["p_flags"]
            phdr.p_offset = seg["p_offset"]
            phdr.p_vaddr = seg["p_vaddr"]
            phdr.p_paddr = seg["p_paddr"]
            phdr.p_filesz = seg["p_filesz"]
            phdr.p_memsz = seg["p_memsz"]
            phdr.p_align = seg["p_align"]

            segments.append(phdr)

        return segments

    # ================================================================
    # Relocation building
    # ================================================================

    def _build_relocations(self):
        relocations = {}

        for section in self.elf.iter_sections():
            if section.header["sh_type"] != "SHT_RELA":
                continue

            for rel in section.iter_relocations():
                relocations[rel["r_offset"]] = {
                    "type": rel["r_info_type"],
                    "sym": rel["r_info_sym"],
                    "addend": rel["r_addend"],
                }
        return relocations

    # ================================================================
    # Segment lookup
    # ================================================================

    def _find_load_segment(self, va: int):
        for segment in self.load_segments:
            start = segment["vaddr"]
            end = start + segment["memsz"]

            if start <= va < end:
                return segment

        return None

    def _find_file_segment(self, offset: int):
        for segment in self.load_segments:
            start = segment["offset"]
            end = start + segment["filesz"]

            if start <= offset < end:
                return segment

        return None

    # ================================================================
    # Address mapping
    # ================================================================

    def map_vaddr(self, addr: int) -> int:
        """
        Virtual address -> file offset.

        Addresses in the BSS part of a segment do not have
        a corresponding file offset.
        """

        for phdr in self._program_segments:
            if phdr.p_type != "PT_LOAD":
                continue

            start = phdr.p_vaddr
            end = start + phdr.p_filesz

            if start <= addr < end:
                return phdr.p_offset + (addr - start)

        raise ValueError(
            f"Address 0x{addr} "
            f"not in any file-backed segment"
        )

    def map_fileaddr(self, file_offset: int) -> int:
        """
        File offset -> virtual address.
        """

        segment = self._find_file_segment(file_offset)

        if segment is None:
            raise ValueError(
                f"File offset {file_offset:#x} not mapped"
            )

        return (
            segment["vaddr"]
            + (file_offset - segment["offset"])
        )

    # ================================================================
    # Raw file reading
    # ================================================================

    def read_file(
        self,
        offset: int,
        size: int,
    ) -> bytes:
        if offset < 0:
            raise ValueError(
                "offset cannot be negative"
            )

        if size < 0:
            raise ValueError(
                "size cannot be negative"
            )

        if size == 0:
            return b""

        self.file.seek(offset)

        data = self.file.read(size)

        if len(data) != size:
            raise EOFError(
                f"Failed to read {size} bytes "
                f"at file offset 0x{offset:x}; "
                f"got {len(data)} bytes"
            )

        return data

    # ================================================================
    # Virtual memory reading
    # ================================================================

    def read_va(
        self,
        va: int,
        size: int,
    ) -> bytes:
        """
        Read virtual memory.

        Supports:
        - normal PT_LOAD data
        - crossing PT_LOAD boundaries
        - BSS (zero-filled)
        """

        if va < 0:
            raise ValueError(
                "virtual address cannot be negative"
            )

        if size < 0:
            raise ValueError(
                "size cannot be negative"
            )

        if size == 0:
            return b""

        result = bytearray()

        current_va = va
        remaining = size

        while remaining > 0:
            segment = self._find_load_segment(
                current_va
            )

            if segment is None:
                raise ValueError(
                    f"Address 0x{current_va:x} not mapped"
                )

            segment_start = segment["vaddr"]

            segment_mem_end = (
                segment_start
                + segment["memsz"]
            )

            segment_file_end = (
                segment_start
                + segment["filesz"]
            )

            chunk = min(
                remaining,
                segment_mem_end - current_va,
            )

            # --------------------------------------------------------
            # BSS
            # --------------------------------------------------------

            if current_va >= segment_file_end:
                result.extend(
                    b"\x00" * chunk
                )

            # --------------------------------------------------------
            # File-backed data
            # --------------------------------------------------------

            else:
                file_chunk = min(
                    chunk,
                    segment_file_end - current_va,
                )

                file_offset = (
                    segment["offset"]
                    + current_va
                    - segment_start
                )

                self.file.seek(file_offset)

                data = self.file.read(
                    file_chunk
                )

                if len(data) != file_chunk:
                    raise EOFError(
                        f"Failed to read "
                        f"{file_chunk} bytes at "
                        f"file offset "
                        f"0x{file_offset:x}"
                    )

                result.extend(data)

                # ----------------------------------------------------
                # BSS tail
                # ----------------------------------------------------

                bss_size = chunk - file_chunk

                if bss_size > 0:
                    result.extend(
                        b"\x00" * bss_size
                    )

            current_va += chunk
            remaining -= chunk

        return bytes(result)

    def read_bytes(
        self,
        va: int,
        size: int,
    ) -> bytes:
        return self.read_va(va, size)

    # ================================================================
    # Primitive types
    # ================================================================

    def read_primitive(
        self,
        fmt: str,
        data: bytes,
        offset: int
    ):
        return struct.unpack_from(fmt, data, offset)[0]
        # ================================================================
        # Unsigned primitives
        # ================================================================

    def read_u8(self, data: bytes, offset: int) -> int:
        return self.read_primitive(
            "B",
            data,
            offset
        )

    def read_u16(self, data: bytes, offset: int) -> int:
        return self.read_primitive(
            "H",
            data,
            offset
        )

    def read_u32(self, data: bytes, offset: int) -> int:
        return self.read_primitive(
            "I",
            data,
            offset
        )

    def read_u64(self, data: bytes, offset: int) -> int:
        return self.read_primitive(
            "Q",
            data,
            offset
        )

    # ================================================================
    # Pointer
    # ================================================================

    def read_ptr(self, va: int) -> int:
        if self.is64:
            return self.read_u64(va)

        return self.read_u32(va)

    # ================================================================
    # ctypes structures
    # ================================================================

    def read_class(
        self,
        va: int,
        cls: Type[T],
    ) -> T:
        """
        Read ctypes.Structure from virtual address.
        """

        size = ctypes.sizeof(cls)

        data = self.read_va(
            va,
            size,
        )

        return cls.from_buffer_copy(data)

    def read_class_file(
        self,
        offset: int,
        cls: Type[T],
    ) -> T:
        """
        Read ctypes.Structure from file offset.
        """

        size = ctypes.sizeof(cls)

        data = self.read_file(
            offset,
            size,
        )

        return cls.from_buffer_copy(data)

    def map_vaddr_class(
        self,
        va: int,
        cls: Type[T],
    ) -> T:
        return self.read_class(
            va,
            cls,
        )

    # ================================================================
    # Arrays
    # ================================================================

    def read_array(
        self,
        va: int,
        cls: Type[T],
        count: int,
    ) -> List[T]:
        """
        Read array of ctypes structures.
        """

        if count < 0:
            raise ValueError(
                "count cannot be negative"
            )

        size = ctypes.sizeof(cls)

        data = self.read_va(
            va,
            size * count,
        )

        result = []

        for i in range(count):
            offset = i * size

            obj = cls.from_buffer_copy(
                data[offset:offset + size]
            )

            result.append(obj)

        return result

    # ================================================================
    # Strings
    # ================================================================

    def read_cstring(
        self,
        va: int,
        max_size: int = 0x10000,
        encoding: str = "utf-8",
    ) -> str:
        """
        Read null-terminated C string.
        """

        if max_size <= 0:
            return ""

        result = bytearray()

        for i in range(max_size):
            value = self.read_u8(
                va + i
            )

            if value == 0:
                break

            result.append(value)

        return result.decode(
            encoding,
            errors="replace",
        )

    def read_wstring(
        self,
        va: int,
        max_chars: int = 0x10000,
        encoding: str = "utf-16-le",
    ) -> str:
        """
        Read null-terminated UTF-16 string.
        """

        result = bytearray()

        for i in range(max_chars):
            data = self.read_va(
                va + i * 2,
                2,
            )

            if data == b"\x00\x00":
                break

            result.extend(data)

        return result.decode(
            encoding,
            errors="replace",
        )

    # ================================================================
    # Memory checks
    # ================================================================

    def contains_va(
        self,
        va: int,
        size: int = 1,
    ) -> bool:
        """
        Check whether a VA range is mapped.

        This checks PT_LOAD memory, including BSS.
        """

        if size <= 0:
            return False

        current = va
        remaining = size

        while remaining > 0:
            segment = self._find_load_segment(
                current
            )

            if segment is None:
                return False

            end = (
                segment["vaddr"]
                + segment["memsz"]
            )

            chunk = min(
                remaining,
                end - current,
            )

            current += chunk
            remaining -= chunk

        return True

    def contains_file_offset(
        self,
        offset: int,
        size: int = 1,
    ) -> bool:
        """
        Check whether file offset range exists
        inside file-backed PT_LOAD data.
        """

        if size <= 0:
            return False

        current = offset
        remaining = size

        while remaining > 0:
            segment = self._find_file_segment(
                current
            )

            if segment is None:
                return False

            end = (
                segment["offset"]
                + segment["filesz"]
            )

            chunk = min(
                remaining,
                end - current,
            )

            current += chunk
            remaining -= chunk

        return True

    # ================================================================
    # ELF information
    # ================================================================

    @property
    def entry_point(self) -> int:
        return self._elf_header.e_entry

    @property
    def elf_header(self) -> Elf64_Ehdr:
        return self._elf_header

    @property
    def program_headers(self) -> List[Elf64_Phdr]:
        return self._program_segments

    # ================================================================
    # Symbols
    # ================================================================

    def find_symbol(
        self,
        name: str,
    ) -> Optional[int]:
        """
        Find symbol VA by name.

        Searches .dynsym and .symtab.
        """

        # Prefer normal symbol table first.
        for section_name in (
            ".symtab",
            ".dynsym",
        ):
            section = self.elf.get_section_by_name(
                section_name
            )

            if section is None:
                continue

            for symbol in section.iter_symbols():
                if symbol.name == name:
                    return symbol["st_value"]

        return None

    def get_symbol(
        self,
        name: str,
    ):
        """
        Return complete pyelftools symbol object.
        """

        for section_name in (
            ".symtab",
            ".dynsym",
        ):
            section = self.elf.get_section_by_name(
                section_name
            )

            if section is None:
                continue

            for symbol in section.iter_symbols():
                if symbol.name == name:
                    return symbol

        return None

    # ================================================================
    # Sections
    # ================================================================

    def get_section(self, name: str):
        return self.elf.get_section_by_name(
            name
        )

    def section_va(self, name: str) -> int:
        section = self.get_section(name)

        if section is None:
            raise ValueError(
                f"Section {name!r} not found"
            )

        return section["sh_addr"]

    def section_size(self, name: str) -> int:
        section = self.get_section(name)

        if section is None:
            raise ValueError(
                f"Section {name!r} not found"
            )

        return section["sh_size"]

    def section_offset(self, name: str) -> int:
        section = self.get_section(name)

        if section is None:
            raise ValueError(
                f"Section {name!r} not found"
            )

        return section["sh_offset"]

    # ================================================================
    # Cleanup
    # ================================================================

    def close(self):
        if self.file is not None:
            self.file.close()
            self.file = None

    def __enter__(self):
        return self

    def __exit__(
        self,
        exc_type,
        exc_val,
        exc_tb,
    ):
        self.close()
