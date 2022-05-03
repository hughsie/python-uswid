#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=wrong-import-position

from enum import Enum
from typing import Optional
import argparse
import tempfile
import subprocess

import os
import sys
import shutil

import pefile

sys.path.append(os.path.realpath("."))

from uswid import uSwidIdentity, uSwidContainer, NotSupportedError


def adjust_SectionSize(sz, align):
    if sz % align:
        sz = ((sz + align) // align) * align
    return sz


def _pe_get_section_by_name(pe: pefile.PE, name: str) -> pefile.SectionStructure:
    for sect in pe.sections:
        if sect.Name == name.encode().ljust(8, b"\0"):
            return sect
    return None


def _import_efi_pefile(identity: uSwidIdentity, fn: str) -> None:
    """read EFI file using pefile"""
    pe = pefile.PE(fn)
    sect = _pe_get_section_by_name(pe, ".sbom")
    if sect:
        identity.import_bytes(sect.get_data())


def _import_efi_objcopy(identity: uSwidIdentity, fn: str, objcopy: str) -> None:
    """read EFI file using objcopy"""
    objcopy_full = shutil.which(objcopy)
    if not objcopy_full:
        print("executable {} not found".format(objcopy))
        sys.exit(1)
    with tempfile.NamedTemporaryFile(
        mode="w+b", prefix="objcopy_", suffix=".bin", delete=True
    ) as dst:
        try:
            # pylint: disable=unexpected-keyword-arg
            subprocess.check_output(
                [
                    objcopy_full,
                    "-O",
                    "binary",
                    "--only-section=.sbom",
                    fn,
                    dst.name,
                ],
                stderr=subprocess.PIPE,
            )
        except subprocess.CalledProcessError as e:
            print(e)
            sys.exit(1)
        identity.import_bytes(dst.read())


def _export_efi_pefile(identity: uSwidIdentity, fn: str) -> None:
    """modify EFI file using pefile"""
    blob = identity.export_bytes()
    pe = pefile.PE(fn)
    sect = _pe_get_section_by_name(pe, ".sbom")
    if not sect:
        raise NotSupportedError("PE files have to have an linker-defined .sbom section")

    # can we squeeze the new uSWID blob into the existing space
    sect.Misc = len(blob)
    if len(blob) <= sect.SizeOfRawData:
        pe.set_bytes_at_offset(sect.PointerToRawData, blob)

    # save
    pe.write(fn)


def _export_efi_objcopy(
    identity: uSwidIdentity, fn: str, cc: Optional[str], objcopy: str
) -> None:
    """modify EFI file using objcopy"""
    objcopy_full = shutil.which(objcopy)
    if not objcopy_full:
        print("executable {} not found".format(objcopy))
        sys.exit(1)
    if not os.path.exists(fn):
        if not cc:
            raise NotSupportedError("compiler is required for missing section")
        subprocess.run([cc, "-x", "c", "-c", "-o", fn, "/dev/null"], check=True)

    # save to file?
    try:
        blob = identity.export_bytes()
    except NotSupportedError as e:
        print(e)
        sys.exit(1)

    with tempfile.NamedTemporaryFile(
        mode="wb", prefix="objcopy_", suffix=".bin", delete=True
    ) as src:
        src.write(blob)
        src.flush()
        try:
            # pylint: disable=unexpected-keyword-arg
            subprocess.check_output(
                [
                    objcopy_full,
                    "--remove-section=.sbom",
                    "--add-section",
                    ".sbom={}".format(src.name),
                    "--set-section-flags",
                    ".sbom=contents,alloc,load,readonly,data",
                    fn,
                ]
            )
        except subprocess.CalledProcessError as e:
            print(e)
            sys.exit(1)


class SwidFormat(Enum):
    UNKNOWN = 0
    INI = 1
    XML = 2
    USWID = 3
    PE = 4
    JSON = 5


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
    if ext == "json":
        return SwidFormat.JSON
    return SwidFormat.UNKNOWN


def main():
    parser = argparse.ArgumentParser(description="Generate CoSWID metadata")
    parser.add_argument("--cc", default="gcc", help="Compiler to use for empty object")
    parser.add_argument("--binfile", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--rawfile", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--inifile", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--xmlfile", default=None, help=argparse.SUPPRESS)
    parser.add_argument(
        "--objcopy", default=None, help="Binary file to use for objcopy"
    )
    parser.add_argument(
        "--load",
        default=None,
        action="append",
        help="file to import, .efi,.ini,.uswid,.xml,.json",
    )
    parser.add_argument(
        "--save",
        default=None,
        action="append",
        help="file to export, .efi,.ini,.uswid,.xml,.json",
    )
    parser.add_argument(
        "--compress",
        dest="compress",
        default=False,
        action="store_true",
        help="Compress uSWID containers",
    )
    parser.add_argument(
        "--verbose",
        dest="verbose",
        default=False,
        action="store_true",
        help="Show verbose operation",
    )
    args = parser.parse_args()
    load_fns = args.load if args.load else []
    save_fns = args.save if args.save else []

    # deprecated arguments
    if args.binfile:
        load_fns.append(args.binfile)
        save_fns.append(args.binfile)
    if args.rawfile:
        save_fns.append(args.rawfile)
    if args.xmlfile:
        load_fns.append(args.xmlfile)

    # sanity check
    if not load_fns and not save_fns:
        print("Use uswid --help for command line arguments")
        sys.exit(1)

    # collect data here
    container = uSwidContainer()
    for fn in load_fns:
        try:
            fmt = _detect_format(fn)
            if fmt == SwidFormat.PE:
                identity = container.get_default()
                if not identity:
                    print("cannot load PE when no default identity")
                    sys.exit(1)
                if args.objcopy:
                    _import_efi_objcopy(identity, fn, objcopy=args.objcopy)
                else:
                    _import_efi_pefile(identity, fn)
            elif fmt == SwidFormat.XML:
                identity = container.get_default()
                if not identity:
                    print("cannot load XML when no default identity")
                    sys.exit(1)
                with open(fn, "rb") as f:
                    identity.import_xml(f.read())
            elif fmt == SwidFormat.JSON:
                identity = container.get_default()
                if not identity:
                    print("cannot load JSON when no default identity")
                    sys.exit(1)
                with open(fn, "rb") as f:
                    identity.import_json(f.read())
            elif fmt == SwidFormat.INI:
                identity = container.get_default()
                if not identity:
                    print("cannot load INI when no default identity")
                    sys.exit(1)
                with open(fn, "rb") as f:
                    identity.import_ini(f.read().decode())
            else:
                print("{} has unknown extension, using uSWID".format(fn))
                with open(fn, "rb") as f:
                    container.import_bytes(f.read())

        except FileNotFoundError:
            print("{} does not exist".format(fn))
            sys.exit(1)
        except NotSupportedError as e:
            print(e)
            sys.exit(1)

    # debug
    if load_fns and args.verbose:
        print("Loaded:\n{}".format(container))

    # optional save
    if save_fns and args.verbose:
        print("Saving:\n{}".format(container))
    for fn in save_fns:
        try:
            fmt = _detect_format(fn)
            if fmt == SwidFormat.PE:
                identity = container.get_default()
                if not identity:
                    print("cannot save PE when no default identity")
                    sys.exit(1)
                if args.objcopy:
                    _export_efi_objcopy(identity, fn, args.cc, args.objcopy)
                else:
                    _export_efi_pefile(identity, fn)
            elif fmt == SwidFormat.USWID:
                with open(fn, "wb") as f:
                    f.write(container.export_bytes(compress=args.compress))
            elif fmt == SwidFormat.XML:
                identity = container.get_default()
                if not identity:
                    print("cannot save XML when no default identity")
                    sys.exit(1)
                with open(fn, "wb") as f:
                    f.write(identity.export_xml())
            elif fmt == SwidFormat.JSON:
                identity = container.get_default()
                if not identity:
                    print("cannot save JSON when no default identity")
                    sys.exit(1)
                with open(fn, "wb") as f:
                    f.write(identity.export_json())
            elif fmt == SwidFormat.INI:
                identity = container.get_default()
                if not identity:
                    print("cannot save INI when no default identity")
                    sys.exit(1)
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
