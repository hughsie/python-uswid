#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=wrong-import-position

from enum import Enum
import argparse

import os
import sys

import pefile

sys.path.append(os.path.realpath("."))

from uswid import uSwidIdentity, NotSupportedError


def adjust_SectionSize(sz, align):
    if sz % align:
        sz = ((sz + align) // align) * align
    return sz


def _pe_get_section_by_name(pe: pefile.PE, name: str) -> pefile.SectionStructure:
    for sect in pe.sections:
        if sect.Name == name.encode().ljust(8, b"\0"):
            return sect
    return None


def _pe_delete_section(pe: pefile.PE, sect: pefile.SectionStructure) -> None:

    # clear out data
    pe.set_bytes_at_offset(sect.PointerToRawData, b"\x00" * sect.SizeOfRawData)

    # clear header
    sect.Name = b"\x00" * 8
    sect.Misc_VirtualSize = 0x0
    sect.Misc_PhysicalAddress = 0x0
    sect.Misc = 0x0
    sect.SizeOfRawData = 0x0
    sect.PointerToRawData = 0x0
    sect.Characteristics = 0x0

    # write to __data__
    pe.merge_modified_section_data()
    pe.sections.remove(sect)


def _pe_add_section(pe: pefile.PE, name: str, blob: bytes) -> None:

    # new section filled with zeros
    sect = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__)
    sect.__unpack__(bytearray(sect.sizeof()))

    # place section header after last section header
    last_section = pe.sections[-1]
    sect.set_file_offset(last_section.get_file_offset() + last_section.sizeof())

    # create
    sect.Name = name.encode()
    sect.SizeOfRawData = adjust_SectionSize(len(blob), pe.OPTIONAL_HEADER.FileAlignment)
    blob_aligned = blob.ljust(sect.SizeOfRawData, b"\0")
    sect.PointerToRawData = len(pe.__data__)
    sect.Misc = sect.Misc_PhysicalAddress = sect.Misc_VirtualSize = len(blob)
    sect.VirtualAddress = last_section.VirtualAddress + adjust_SectionSize(
        last_section.Misc_VirtualSize, pe.OPTIONAL_HEADER.SectionAlignment
    )
    sect.Characteristics = (
        pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_CNT_INITIALIZED_DATA"]
        | pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_READ"]
    )
    pe.OPTIONAL_HEADER.SizeOfImage += adjust_SectionSize(
        len(blob), pe.OPTIONAL_HEADER.SectionAlignment
    )

    # append new section to structures
    pe.FILE_HEADER.NumberOfSections += 1
    pe.sections.append(sect)
    pe.__structures__.append(sect)

    # add new section data
    pe.__data__ = bytearray(pe.__data__) + blob_aligned


def _import_efi(identity: uSwidIdentity, fn: str) -> None:
    # EFI file
    pe = pefile.PE(fn)
    sect = _pe_get_section_by_name(pe, ".sbom")
    if sect:
        identity.import_bytes(sect.get_data())


def _export_efi(identity: uSwidIdentity, fn: str) -> None:
    # EFI file

    blob = identity.export_bytes(use_header=False)
    pe = pefile.PE(fn)
    sect = _pe_get_section_by_name(pe, ".sbom")
    if sect:
        # can we squeeze the new uSWID blob into the existing space
        if len(blob) <= sect.SizeOfRawData:
            pe.set_bytes_at_offset(sect.PointerToRawData, blob)

        # new data is too large for existing section, delete and start again
        else:
            _pe_delete_section(pe, sect)
            sect = None

    # add new section
    if not sect:
        _pe_add_section(pe, ".sbom", blob)

    # save
    pe.write(fn)


class SwidFormat(Enum):
    UNKNOWN = 0
    INI = 1
    XML = 2
    USWID = 3
    PE = 4


def _detect_format(fn: str) -> SwidFormat:
    ext = fn.rsplit(".", maxsplit=1)[-1].lower()
    if ext in ["exe", "efi"]:
        return SwidFormat.PE
    if ext in ["uswid", "raw", "bin"]:
        return SwidFormat.USWID
    if ext == "ini":
        return SwidFormat.INI
    if ext == "xml":
        return SwidFormat.XML
    return SwidFormat.UNKNOWN


def main():
    parser = argparse.ArgumentParser(description="Generate CoSWID metadata")
    parser.add_argument(
        "--load",
        default=[],
        action="append",
        help="file to import, .efi,.ini,.uswid,.xml",
    )
    parser.add_argument(
        "--save",
        default=[],
        action="append",
        help="file to export, .efi,.ini,.uswid,.xml",
    )
    parser.add_argument(
        "--verbose",
        dest="verbose",
        default=False,
        action="store_true",
        help="Show verbose operation",
    )
    args = parser.parse_args()
    if not args.load and not args.save:
        print("Use uswid --help for command line arguments")
        sys.exit(1)

    # collect data here
    identity = uSwidIdentity()
    for fn in args.load:
        try:
            fmt = _detect_format(fn)
            if fmt == SwidFormat.PE:
                _import_efi(identity, fn)
            elif fmt == SwidFormat.USWID:
                with open(fn, "rb") as f:
                    identity.import_bytes(f.read(), use_header=True)
            elif fmt == SwidFormat.XML:
                with open(fn, "rb") as f:
                    identity.import_xml(f.read())
            elif fmt == SwidFormat.INI:
                with open(fn, "rb") as f:
                    identity.import_ini(f.read().decode())
            else:
                print("{} extension is not supported".format(fn))
                sys.exit(1)
        except FileNotFoundError:
            print("{} does not exist".format(fn))
            sys.exit(1)
        except NotSupportedError as e:
            print(e)
            sys.exit(1)

    # debug
    if args.load and args.verbose:
        print("Loaded:\n{}".format(identity))

    # optional save
    if args.save and args.verbose:
        print("Saving:\n{}".format(identity))
    for fn in args.save:
        try:
            fmt = _detect_format(fn)
            if fmt == SwidFormat.PE:
                _export_efi(identity, fn)
            elif fmt == SwidFormat.USWID:
                with open(fn, "wb") as f:
                    f.write(identity.export_bytes(use_header=True))
            elif fmt == SwidFormat.XML:
                with open(fn, "wb") as f:
                    f.write(identity.export_xml())
            elif fmt == SwidFormat.INI:
                with open(fn, "wb") as f:
                    f.write(identity.export_ini().encode())
            else:
                print("{} extension is not supported".format(fn))
                sys.exit(1)
        except NotSupportedError as e:
            print(e)
            sys.exit(1)

    # success
    sys.exit(0)


if __name__ == "__main__":
    main()
