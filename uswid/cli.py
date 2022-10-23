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


def _import_efi_pefile(identity: uSwidIdentity, filepath: str) -> None:
    """read EFI file using pefile"""
    pe = pefile.PE(filepath)
    sect = _pe_get_section_by_name(pe, ".sbom")
    if sect:
        identity.import_bytes(sect.get_data())


def _import_efi_objcopy(identity: uSwidIdentity, filepath: str, objcopy: str) -> None:
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
        identity.import_bytes(dst.read())


def _export_efi_pefile(identity: uSwidIdentity, filepath: str) -> None:
    """modify EFI file using pefile"""
    blob = identity.export_bytes()
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


def _export_efi_objcopy(
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
                    filepath,
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
    PKG_CONFIG = 6
    COSWID = 7


def _detect_format(filepath: str) -> SwidFormat:
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
            if fmt == SwidFormat.PE:
                identity = uSwidIdentity()
                if args.objcopy:
                    _import_efi_objcopy(identity, filepath, objcopy=args.objcopy)
                else:
                    _import_efi_pefile(identity, filepath)
                identity_new = container.merge(identity)
                if identity_new:
                    print(
                        "{} was merged into existing identity {}".format(
                            filepath, identity_new.tag_id
                        )
                    )
            elif fmt == SwidFormat.XML:
                identity = uSwidIdentity()
                with open(filepath, "rb") as f:
                    identity.import_xml(f.read())
                identity_new = container.merge(identity)
                if identity_new:
                    print(
                        "{} was merged into existing identity {}".format(
                            filepath, identity_new.tag_id
                        )
                    )
            elif fmt == SwidFormat.JSON:
                with open(filepath, "rb") as f:
                    container.import_json(f.read())
            elif fmt == SwidFormat.INI:
                identity = uSwidIdentity()
                with open(filepath, "rb") as f:
                    identity.import_ini(f.read().decode())
                identity_new = container.merge(identity)
                if identity_new:
                    print(
                        "{} was merged into existing identity {}".format(
                            filepath, identity_new.tag_id
                        )
                    )
            elif fmt == SwidFormat.USWID:
                with open(filepath, "rb") as f:
                    container.import_bytes(f.read())
            elif fmt == SwidFormat.PKG_CONFIG:
                identity = uSwidIdentity()
                with open(filepath, "rb") as f:
                    identity.import_pkg_config(f.read().decode(), filepath=filepath)
                identity_new = container.merge(identity)
                if identity_new:
                    print(
                        "{} was merged into existing identity {}".format(
                            filepath, identity_new.tag_id
                        )
                    )
            else:
                print("{} has unknown extension, using uSWID".format(filepath))
                with open(filepath, "rb") as f:
                    container.import_bytes(f.read())

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
                identity = container.get_default()
                if not identity:
                    print("cannot save PE when no default identity")
                    sys.exit(1)
                if args.objcopy:
                    _export_efi_objcopy(identity, filepath, args.cc, args.objcopy)
                else:
                    _export_efi_pefile(identity, filepath)
            elif fmt == SwidFormat.USWID:
                with open(filepath, "wb") as f:
                    f.write(container.export_bytes(compress=args.compress))
            elif fmt == SwidFormat.COSWID:
                identity = container.get_default()
                if not identity:
                    print("cannot save XML when no default identity")
                    sys.exit(1)
                with open(filepath, "wb") as f:
                    f.write(identity.export_bytes())
            elif fmt == SwidFormat.XML:
                identity = container.get_default()
                if not identity:
                    print("cannot save XML when no default identity")
                    sys.exit(1)
                with open(filepath, "wb") as f:
                    f.write(identity.export_xml())
            elif fmt == SwidFormat.JSON:
                with open(filepath, "wb") as f:
                    f.write(container.export_json())
            elif fmt == SwidFormat.INI:
                identity = container.get_default()
                if not identity:
                    print("cannot save INI when no default identity")
                    sys.exit(1)
                with open(filepath, "wb") as f:
                    f.write(identity.export_ini().encode())
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
