#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=wrong-import-position

from enum import IntEnum
from typing import Optional, Any
import argparse
import tempfile
import subprocess

import os
import sys
import shutil

import pefile

sys.path.append(os.path.realpath("."))

from uswid import uSwidIdentity, uSwidContainer, NotSupportedError
from uswid.format_coswid import uSwidFormatCoswid
from uswid.format_ini import uSwidFormatIni
from uswid.format_goswid import uSwidFormatGoswid
from uswid.format_pkgconfig import uSwidFormatPkgconfig
from uswid.format_swid import uSwidFormatSwid
from uswid.format_uswid import uSwidFormatUswid
from uswid.format_cyclonedx import uSwidFormatCycloneDX


def adjust_SectionSize(sz, align):
    if sz % align:
        sz = ((sz + align) // align) * align
    return sz


def _pe_get_section_by_name(pe: pefile.PE, name: str) -> pefile.SectionStructure:
    for sect in pe.sections:
        if sect.Name == name.encode().ljust(8, b"\0"):
            return sect
    return None


def _load_efi_pefile(filepath: str) -> uSwidContainer:
    """read EFI file using pefile"""
    pe = pefile.PE(filepath)
    sect = _pe_get_section_by_name(pe, ".sbom")
    if not sect:
        raise NotSupportedError("PE files have to have an linker-defined .sbom section")
    return uSwidFormatCoswid().load(sect.get_data())


def _load_efi_objcopy(filepath: str, objcopy: str) -> uSwidContainer:
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
                    filepath,
                    dst.name,
                ],
                stderr=subprocess.PIPE,
            )
        except subprocess.CalledProcessError as e:
            print(e)
            sys.exit(1)
        return uSwidFormatCoswid().load(dst.read())


def _save_efi_pefile(identity: uSwidIdentity, filepath: str) -> None:
    """modify EFI file using pefile"""

    blob = uSwidFormatCoswid().save(uSwidContainer([identity]))
    pe = pefile.PE(filepath)
    sect = _pe_get_section_by_name(pe, ".sbom")
    if not sect:
        raise NotSupportedError("PE files have to have an linker-defined .sbom section")

    # can we squeeze the new uSWID blob into the existing space
    sect.Misc = len(blob)
    if len(blob) <= sect.SizeOfRawData:
        pe.set_bytes_at_offset(sect.PointerToRawData, blob)

    # save
    pe.write(filepath)


def _save_efi_objcopy(
    identity: uSwidIdentity, filepath: str, cc: Optional[str], objcopy: str
) -> None:
    """modify EFI file using objcopy"""
    objcopy_full = shutil.which(objcopy)
    if not objcopy_full:
        print("executable {} not found".format(objcopy))
        sys.exit(1)
    if not os.path.exists(filepath):
        if not cc:
            raise NotSupportedError("compiler is required for missing section")
        subprocess.run([cc, "-x", "c", "-c", "-o", filepath, "/dev/null"], check=True)

    # save to file?
    try:
        blob = uSwidFormatIni().save(uSwidContainer([identity]))
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
                    filepath,
                ]
            )
        except subprocess.CalledProcessError as e:
            print(e)
            sys.exit(1)


class SwidFormat(IntEnum):
    UNKNOWN = 0
    INI = 1
    XML = 2
    USWID = 3
    PE = 4
    JSON = 5
    PKG_CONFIG = 6
    COSWID = 7
    CYCLONE_DX = 8


def _detect_format(filepath: str) -> SwidFormat:
    if os.path.basename(filepath).endswith("bom.json"):
        return SwidFormat.CYCLONE_DX
    ext = filepath.rsplit(".", maxsplit=1)[-1].lower()
    if ext in ["exe", "efi", "o"]:
        return SwidFormat.PE
    if ext in ["uswid", "raw", "bin"]:
        return SwidFormat.USWID
    if ext == "coswid":
        return SwidFormat.COSWID
    if ext == "ini":
        return SwidFormat.INI
    if ext == "xml":
        return SwidFormat.XML
    if ext == "json":
        return SwidFormat.JSON
    if ext == "pc":
        return SwidFormat.PKG_CONFIG
    return SwidFormat.UNKNOWN


def _type_for_fmt(
    fmt: SwidFormat, args: Any, filepath: Optional[str] = None
) -> Optional[Any]:
    if fmt == SwidFormat.INI:
        return uSwidFormatIni()
    if fmt == SwidFormat.COSWID:
        return uSwidFormatCoswid()
    if fmt == SwidFormat.JSON:
        return uSwidFormatGoswid()
    if fmt == SwidFormat.XML:
        return uSwidFormatSwid()
    if fmt == SwidFormat.CYCLONE_DX:
        return uSwidFormatCycloneDX()
    if fmt == SwidFormat.PKG_CONFIG:
        return uSwidFormatPkgconfig(filepath=filepath)
    if fmt == SwidFormat.USWID:
        return uSwidFormatUswid(compress=args.compress)  # type: ignore
    return None


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
    load_filepaths = args.load if args.load else []
    save_filepaths = args.save if args.save else []

    # deprecated arguments
    if args.binfile:
        load_filepaths.append(args.binfile)
        save_filepaths.append(args.binfile)
    if args.rawfile:
        save_filepaths.append(args.rawfile)
    if args.xmlfile:
        load_filepaths.append(args.xmlfile)

    # sanity check
    if not load_filepaths and not save_filepaths:
        print("Use uswid --help for command line arguments")
        sys.exit(1)

    # always load into a temporary identity so that we can query the tag_id
    container = uSwidContainer()

    # collect data here
    for filepath in load_filepaths:
        try:
            fmt = _detect_format(filepath)
            if fmt == SwidFormat.UNKNOWN:
                print("{} has unknown extension, using uSWID".format(filepath))
                fmt = SwidFormat.USWID
            if fmt == SwidFormat.PE:
                if args.objcopy:
                    container_tmp = _load_efi_objcopy(filepath, objcopy=args.objcopy)
                else:
                    container_tmp = _load_efi_pefile(filepath)
                for identity in container_tmp:
                    identity_new = container.merge(identity)
                    if identity_new:
                        print(
                            "{} was merged into existing identity {}".format(
                                filepath, identity_new.tag_id
                            )
                        )
            elif fmt in [
                SwidFormat.INI,
                SwidFormat.JSON,
                SwidFormat.USWID,
                SwidFormat.XML,
                SwidFormat.PKG_CONFIG,
            ]:
                base = _type_for_fmt(fmt, args, filepath=filepath)
                if not base:
                    print("{} no type for format".format(fmt))
                    sys.exit(1)
                with open(filepath, "rb") as f:
                    for identity in base.load(f.read()):
                        identity_new = container.merge(identity)
                        if identity_new:
                            print(
                                "{} was merged into existing identity {}".format(
                                    filepath, identity_new.tag_id
                                )
                            )

        except FileNotFoundError:
            print("{} does not exist".format(filepath))
            sys.exit(1)
        except NotSupportedError as e:
            print(e)
            sys.exit(1)
    # debug
    if load_filepaths and args.verbose:
        print("Loaded:\n{}".format(container))

    # optional save
    if save_filepaths and args.verbose:
        print("Saving:\n{}".format(container))
    for filepath in save_filepaths:
        try:
            fmt = _detect_format(filepath)
            if fmt == SwidFormat.PE:
                identity_pe: Optional[uSwidIdentity] = container.get_default()
                if not identity_pe:
                    print("cannot save PE when no default identity")
                    sys.exit(1)
                if args.objcopy:
                    _save_efi_objcopy(identity_pe, filepath, args.cc, args.objcopy)
                else:
                    _save_efi_pefile(identity_pe, filepath)
            elif fmt in [
                SwidFormat.INI,
                SwidFormat.COSWID,
                SwidFormat.JSON,
                SwidFormat.XML,
                SwidFormat.USWID,
                SwidFormat.CYCLONE_DX,
            ]:
                base = _type_for_fmt(fmt, args)
                if not base:
                    print("{} no type for format".format(fmt))
                    sys.exit(1)
                blob = base.save(container)
                with open(filepath, "wb") as f:
                    f.write(blob)
            else:
                print("{} extension is not supported".format(filepath))
                sys.exit(1)
        except NotSupportedError as e:
            print(e)
            sys.exit(1)

    # success
    sys.exit(0)


if __name__ == "__main__":
    main()
