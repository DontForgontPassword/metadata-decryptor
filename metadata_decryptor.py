#!/usr/bin/env python3

# Global metadata header reconstruction using heuristic
# CodeRegistration, MetadataRegistration reconstruction using heuristic
# Im reconstructed only fields what using in Il2CppDumper(v39)
# Big thanks to Michel-M-Code

# Bad peoples from axlebolt reordered many structures fields.
# Poor me, i spended to this shit about week - month
# But i'm really got fun with this

# For any help you can ask me, just write me in discord (experienceinmymind)

# Used AI to reconstruct code to readable view

import argparse
import os
import collections
import struct
from dataclasses import dataclass
from typing import Callable, Optional

from tqdm import tqdm
from colorama import init
from core.elf_reader import ELFReader
from core.logger import Log

init(autoreset=False)

parser = argparse.ArgumentParser(
    description="Generic IL2CPP metadata / registration analyzer"
)

parser.add_argument(
    "--libunity",
    required=True,
    help="libunity.so",
)

parser.add_argument(
    "--output",
    required=True,
    default="global-metadata.dat",
    help="global-metadata.dat / dumped metadata",
)

args = parser.parse_args()

log = Log("METADATA")

elf = ELFReader(args.libunity)


"""
    Found in metadata loader, its a blob data in .rodata section (look for "global-metadata.dat" xref)
"""

METADATA_SIGNATURE = bytes.fromhex(
    "90 1A 00 00 C0 D3 01 00 58 9A 0B 00 AB F6 02 00")

"""
    Changes every update, you need to find it by finding a max offset value in 
    header, then find a matched size to this offset (metadata size +- 21.5mb)
"""

METADATA_END_SIGNATURE = bytes.fromhex(
    "3F 0E 00 00 00 00 00 00 CA 07 00 00 00 00 40 0E"
)


def find_embedded_metadata(elf_reader):
    elf = elf_reader.elf

    if os.path.isfile("embedded-metadata.bin"):
        log.ok("Using existing embedded-metadata.bin")

        with open("embedded-metadata.bin", "rb") as f:
            embedded = f.read()

        if not embedded:
            raise RuntimeError("embedded-metadata.bin exists but is empty")

        log.info(
            f"Read {len(embedded):,} bytes from existing embedded-metadata.bin")

        return embedded

    candidates = []

    log.info("Searching embedded metadata in libunity.so...")

    for section in elf.iter_sections():
        if section.header["sh_type"] != "SHT_RELA":
            continue

        entsize = section.header["sh_entsize"]

        if not entsize:
            continue

        total = section.header["sh_size"] // entsize

        for relocation in tqdm(
            section.iter_relocations(),
            total=total,
            unit="relocations",
            colour="green",
        ):
            r_addend = relocation["r_addend"]

            try:
                file_offset = elf_reader.map_vaddr(r_addend)
            except ValueError:
                continue

            try:
                data = elf_reader.read_file(
                    file_offset,
                    len(METADATA_SIGNATURE),
                )
            except Exception:
                continue

            if data != METADATA_SIGNATURE:
                continue

            candidate = {
                "va": r_addend,
                "file_offset": file_offset,
            }

            candidates.append(candidate)

            log.debug(
                f"Metadata candidate: VA={r_addend:#x} FILE={file_offset:#x}")

    candidates = list({(x["va"], x["file_offset"]): x for x in candidates}.values())

    if not candidates:
        raise RuntimeError("Embedded metadata was not found in libunity.so")

    if len(candidates) > 1:
        log.warn(f"Found {len(candidates)} metadata candidates")

        for i, candidate in enumerate(candidates):
            log.warn(
                f"  [{i}] VA={candidate['va']:#x} FILE={candidate['file_offset']:#x}"
            )

    result = candidates[0]

    metadata_offset = result["file_offset"]
    metadata_va = result["va"]

    log.ok(
        f"Embedded metadata found: VA={metadata_va:#x}, FILE={metadata_offset:#x}")

    elf_reader.file.seek(metadata_offset)

    embedded = bytearray(elf_reader.file.read())

    if not embedded:
        raise RuntimeError("Failed to read embedded metadata")

    log.info(f"Read {len(embedded):,} bytes from embedded metadata")

    end_index = embedded.find(METADATA_END_SIGNATURE)

    if end_index == -1:
        raise RuntimeError("Metadata end signature was not found")

    metadata_end = end_index + len(METADATA_END_SIGNATURE)

    embedded = embedded[:metadata_end]

    log.ok(
        f"Metadata end found: relative=0x{end_index:X}, size=0x{metadata_end:X}")

    with open(
        "embedded-metadata.bin",
        "wb",
    ) as f:
        f.write(embedded)

    log.ok("Embedded metadata saved to embedded-metadata.bin")

    return embedded


metadata = find_embedded_metadata(elf)


@dataclass
class Section:
    name: str
    fmt: Optional[str] = None
    validator: Optional[Callable] = None
    signature: Optional[bytes] = None
    prefer_small: bool = False

    offset: Optional[int] = None
    size: Optional[int] = None

    @property
    def stride(self):
        if not self.fmt:
            return 1
        return struct.calcsize(self.fmt)

    @property
    def count(self):
        if self.size is None:
            return 0
        return self.size // self.stride


class SectionScanner:
    def __init__(self, data, candidates):
        self.data = data
        self.candidates = list(candidates)

    def scan(self, section: Section):
        hits = []

        for offset, size in self.candidates:
            blob = self.data[offset: offset + size]

            if section.signature is not None:
                if blob.startswith(section.signature):
                    hits.append((offset, size))
                continue

            if not section.fmt or not section.validator:
                continue

            stride = struct.calcsize(section.fmt)
            value_count = len(struct.Struct(
                section.fmt).unpack(b"\0" * stride))

            if stride <= 0:
                continue

            entries = []

            for pos in range(0, len(blob) - stride + 1, stride):
                try:
                    value = struct.unpack_from(
                        section.fmt,
                        blob,
                        pos,
                    )
                except struct.error:
                    break

                if value_count == 1:
                    value = value[0]

                entries.append(value)

            if not entries:
                continue

            try:
                valid = section.validator(
                    entries,
                    offset,
                    size,
                )
            except Exception as e:
                print(f"[{section.name}] Caught an exception:", e)
                valid = False

            if valid:
                hits.append((offset, size))

        if not hits:
            raise RuntimeError(
                f"Could not find metadata section: {section.name}")

        hits.sort(
            key=lambda x: x[1],
            reverse=not section.prefer_small,
        )

        offset, size = hits[0]

        section.offset = offset
        section.size = size

        self.candidates.remove((offset, size))

        log.info(
            f"{section.name:<48}"
            f" offset=0x{offset:08X}"
            f" size=0x{size:08X}"
            f" count={section.count}"
        )

        return section


def get_field(entry, index):
    if isinstance(entry, tuple):
        return entry[index]

    if index != 0:
        raise IndexError(f"Cannot access field {index} from scalar entry")

    return entry


def all_field(index, predicate):

    def validator(entries, *_):
        return bool(entries) and all(
            predicate(get_field(entry, index)) for entry in entries
        )

    return validator


def token(index, prefix):

    return all_field(
        index,
        lambda x: (x & 0xFF000000) == prefix,
    )


def grouped_by(index):
    def validator(entries, *_):
        last = None

        for entry in entries:
            value = get_field(entry, index)

            if last is not None and value < last:
                return False

            last = value

        return True

    return validator


def monotonic(index, less=True):
    def validator(entries, *_):
        last = -1

        for entry in entries:
            value = get_field(entry, index)

            if less:
                if value < last:
                    return False
            else:
                if value > last:
                    return False

            last = value

        return True

    return validator


def range_check(index, minimum, maximum):
    return all_field(
        index,
        lambda x: minimum <= x <= maximum,
    )


# Callbacks


def nestedTypes_callback(e, *_):
    r = p = a = 0
    for x in e:
        a += 1
        r += 1 if x > p else -1
        if r > 256:
            return True
        if r < -4 or x > 0x01000000 or a > 512:
            return False
        p = x
    return False

# Test callbacks


def vtableMethodsTest_callback(entries, *_):
    if _[0] != 0xF52218:
        return False
    for encodedIndex in entries:
        print()
        # if encodedIndex & 0xE0000000 == 0x60000000:
        #     return True
    return False


def attributeDataRangesTest_callback(entries, *_):
    if _[0] != 0x10828B8:
        return False
    for token, start in entries:
        print(hex(token & 0xFF000000))
        # if encodedIndex & 0xE0000000 == 0x60000000:
        #     return True
    return False

# Section Processing


def metadata_sections():

    return [
        Section(
            "stringLiterals",
            signature=bytes.fromhex(
                "00 00 00 00 00 00 00 00 01 00 00 00 05 00 00 00"),
            prefer_small=True,
        ),
        Section(
            "stringLiteralData",
            signature=bytes.fromhex("00 00 00 01 09 00 00 01 64 00 00 01"),
        ),
        Section(
            "strings",
            signature=b"Assembly-CSharp",
            prefer_small=True,
        ),
        Section(
            "events",
            "<IIIIII",
            token(5, 0x14000000),
        ),
        Section(
            "properties",
            "<IIIII",
            token(0, 0x17000000),
        ),
        Section(
            "methods",
            "<IIIIHHHHII",
            token(1, 0x06000000),
        ),
        Section(
            "parameterDefaultValues",
            "<III",
            monotonic(0),
            prefer_small=True,
        ),
        Section(
            "fieldDefaultValues",
            "<III",
            monotonic(0),
        ),
        Section(
            "fieldAndParameterDefaultValueData",
            signature=bytes.fromhex("00 0A 23 20 23 23 30"),
        ),
        Section(
            "parameters",
            "<III",
            token(1, 0x08000000),
            prefer_small=True,
        ),
        Section(
            "fields",
            "<III",
            token(1, 0x04000000),
            prefer_small=True,
        ),
        Section(
            "genericParameters",
            "<HHHII",  # genericContainerIndex == 2
            grouped_by(1),
            prefer_small=True,
        ),
        Section(
            "genericParameterConstraints",
            "<I",
            range_check(0, 256, 1024576),
            prefer_small=True,
        ),
        Section(
            "genericContainers",
            "<IIII",
            lambda entries, *_: all(
                (x[0] == 0 or x[0] == 1) or (x[1] == 1 or x[1] == 2) for x in entries
            ),
            prefer_small=True,
        ),
        Section(
            "nestedTypes",
            "<I",
            nestedTypes_callback,
        ),
        Section(
            "interfaces",
            "<I",
            range_check(0, 256, 1024576),
        ),
        Section(
            "vtableMethods",
            "<I",
            lambda entries, *_: len(entries) >= 10 and sum((x & 0xE0000000)
                                                           == 0x60000000 for x in entries[:10]) >= 8,
        ),
        Section(
            "interfaceOffsets",
            "<II",
            lambda entries, *_: all(x[0] != 0 and x[1]
                                    <= 256 for x in entries),
        ),
        Section(
            "typeDefinitions",
            "<HIIIIIIIIIIIIIIIHHHHHHHHI",  # genericContainerIndex == 2
            lambda entries, *_: (
                bool(entries) and (entries[0][6] & 0xFF000000) == 0x02000000
            ),
        ),
        Section(
            "images",
            "<IIIIIIIII",
            monotonic(2),
        ),
        Section(
            "assemblies",
            "<IIIIIIIIIIIIIII8s",
            lambda entries, *_: all(
                x[1] in (0, 1) and x[2] in (0x20000000, 0x20000001) for x in entries
            ),
        ),
        Section(
            "fieldRefs",
            "<II",
            lambda entries, *
            _: entries[0][1] >= 34068 and monotonic(1)(entries),
        ),
        Section(
            "attributeData",
            signature=bytes.fromhex("01 8E FF 00 00 00 00"),
        ),
        Section(
            "attributeDataRanges",
            "<II",
            lambda entries, *
            _: entries[0][1] == 0x0 and (entries[0][0] & 0xFF000000) == 0x02000000,
        ),
    ]


def find_metadata_candidates(data):

    fields = []

    for offset in range(0, min(372, len(data)), 4):
        value = elf.read_u32(data, offset)

        if 0 < value < len(data):
            fields.append(value)

    candidates = {
        380,
        22698036,  # stringLiteralsData, i tired and hardcoded it
    }

    for field in fields:
        if field < 8192:
            continue

        if field % 4:
            continue

        if field > len(data) / 3:
            candidates.add(field)
            continue

        before = data[max(0, field - 4096): field]

        after = data[field: field + 4096]

        zero_before = before.count(0)
        zero_after = after.count(0)

        cb = collections.Counter(before)
        ca = collections.Counter(after)

        keys = set(cb) | set(ca)

        distance = sum(abs(cb.get(k, 0) / 4096 - ca.get(k, 0) / 4096)
                       for k in keys)

        score = abs(zero_before - zero_after) / 512 + distance

        if score > 0.75:
            candidates.add(field)

    return sorted(candidates)


def make_offset_sizes(data, candidates):

    values = []

    for offset in range(
        0,
        min(372, len(data)),
        4,
    ):
        value = elf.read_u32(data, offset)

        if 0 < value < len(data):
            values.append(value)

    candidates = sorted(set(candidates))
    sizes = [x for x in values if x not in candidates]

    result = []

    for offset in candidates:
        found = False

        for size in sizes:
            if size == offset:
                continue

            if size >= len(data) / 3:
                continue

            if offset + size == len(data):
                result.append((offset, size))

                found = True
                break

            for next_offset in candidates:
                if offset != next_offset and offset + size == next_offset:
                    result.append((offset, size))

                    found = True
                    break

            if found:
                break

        if not found:
            index = candidates.index(offset)

            if index + 1 < len(candidates):
                next_offset = candidates[index + 1]

                size = next_offset - offset

            else:
                size = len(data) - offset

            if size > 0:
                result.append((offset, size))

    return sorted(set(result))


def reconstruct_metadata(data, pairs):
    scanner = SectionScanner(
        data,
        pairs,
    )

    sections = {}

    for definition in metadata_sections():
        try:
            section = scanner.scan(definition)
            sections[section.name] = section

        except RuntimeError as e:
            log.warn(str(e))

    # Metadata version

    VERSION = 39
    HEADER_SIZE = 0x17C

    output = bytearray(data)

    if len(output) < HEADER_SIZE:
        output.extend(b"\0" * (HEADER_SIZE - len(output)))

    # Новый header
    struct.pack_into(
        "<II",
        output,
        0x00,
        0xFAB11BAF,
        VERSION,
    )

    def add(name, header):

        log.info(
            f"Processing {name:<48}"
            f" header=0x{header:08X}"
        )

        section = sections.get(name)

        if section is None:

            # Section not found.
            # But 12 bytes is need to present in header.
            struct.pack_into(
                "<III",
                output,
                header,
                0,
                0,
                0,
            )

            log.warn(
                f"{name:<48}"
                f" MISSING -> offset=0 size=0 count=0"
            )

            return

        offset = section.offset
        size = section.size
        count = section.count

        struct.pack_into(
            "<III",
            output,
            header,
            offset,
            size,
            count,
        )

        log.info(
            f"{name:<48}"
            f" offset=0x{offset:08X}"
            f" size=0x{size:08X}"
            f" count={count}"
        )

    layout = [
        ("stringLiterals",                         0x008),
        ("stringLiteralData",                      0x014),
        ("strings",                                0x020),
        ("events",                                 0x02C),
        ("properties",                             0x038),
        ("methods",                                0x044),
        ("parameterDefaultValues",                 0x050),
        ("fieldDefaultValues",                     0x05C),
        ("fieldAndParameterDefaultValueData",      0x068),
        ("fieldMarshaledSizes",                    0x074),
        ("parameters",                             0x080),
        ("fields",                                 0x08C),
        ("genericParameters",                      0x098),
        ("genericParameterConstraints",             0x0A4),
        ("genericContainers",                      0x0B0),
        ("nestedTypes",                            0x0BC),
        ("interfaces",                             0x0C8),
        ("vtableMethods",                          0x0D4),
        ("interfaceOffsets",                       0x0E0),
        ("typeDefinitions",                        0x0EC),
        ("images",                                 0x0F8),
        ("assemblies",                             0x104),
        ("fieldRefs",                              0x110),
        ("referencedAssemblies",                   0x11C),
        ("attributeData",                          0x128),
        ("attributeDataRanges",                    0x134),
        ("unresolvedIndirectCallParameterTypes",   0x140),
        ("unresolvedIndirectCallParameterRanges",  0x14C),
        ("windowsRuntimeTypeNames",                0x158),
        ("windowsRuntimeStrings",                  0x164),
        ("exportedTypeDefinitions",               0x170),
    ]

    for name, header in layout:
        add(name, header)

    # --------------------------------------------------------
    # Sanity checks
    # --------------------------------------------------------

    assert len(layout) == 31
    assert HEADER_SIZE == 0x17C
    assert layout[-1][1] + 12 == HEADER_SIZE

    for name, section in sections.items():

        if section.offset is None or section.size is None:
            continue

        if section.offset + section.size > len(data):
            log.warn(
                f"{name}: "
                f"0x{section.offset:X} + 0x{section.size:X} "
                f"> metadata size 0x{len(data):X}"
            )

    return output, sections

# g_CodeRegistration (not implemented yet)

# g_MetadataRegistration (not implemented yet)


def main():
    log.info("Searching metadata sections...")

    candidates = find_metadata_candidates(metadata)

    log.info(f"Found {len(candidates)} candidate offsets")

    pairs = make_offset_sizes(
        metadata,
        candidates,
    )

    log.info(f"Found {len(pairs)} offset/size pairs")

    reconstructed, sections = reconstruct_metadata(
        metadata,
        pairs,
    )

    with open(
        args.output,
        "wb",
    ) as f:
        f.write(reconstructed)

    log.ok(f"Metadata written to: {args.output}")

    log.ok("Done.")


if __name__ == "__main__":
    main()
