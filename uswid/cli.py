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
import tempfile
import subprocess

import os
import sys

sys.path.append(os.path.realpath("."))

from uswid import uSwidIdentity, NotSupportedError


def _import_efi(identity: uSwidIdentity, fn: str, objcopy: str) -> None:
    # EFI file
    with tempfile.NamedTemporaryFile(
        mode="w+b", prefix="objcopy_", suffix=".bin", delete=True
    ) as dst:
        try:
            # pylint: disable=unexpected-keyword-arg
            subprocess.check_output(
                [
                    objcopy,
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


def _export_efi(identity: uSwidIdentity, fn: str, cc: str, objcopy: str) -> None:
    # EFI file
    if not os.path.exists(fn):
        subprocess.run([cc, "-x", "c", "-c", "-o", fn, "/dev/null"], check=True)

    # save to file?
    try:
        blob = identity.export_bytes(use_header=False)
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
                    objcopy,
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
    parser.add_argument("--cc", default="gcc", help="Compiler to use for empty object")
    parser.add_argument("--binfile", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--rawfile", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--inifile", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--xmlfile", default=None, help=argparse.SUPPRESS)
    parser.add_argument(
        "--objcopy", default="/usr/bin/objcopy", help="Binary file to use for objcopy"
    )
    parser.add_argument(
        "--load",
        default=None,
        action="append",
        help="file to import, .efi,.ini,.uswid,.xml",
    )
    parser.add_argument(
        "--save",
        default=None,
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
    identity = uSwidIdentity()
    for fn in load_fns:
        try:
            fmt = _detect_format(fn)
            if fmt == SwidFormat.PE:
                _import_efi(identity, fn, objcopy=args.objcopy)
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
    if load_fns and args.verbose:
        print("Loaded:\n{}".format(identity))

    # optional save
    if save_fns and args.verbose:
        print("Saving:\n{}".format(identity))
    for fn in save_fns:
        try:
            fmt = _detect_format(fn)
            if fmt == SwidFormat.PE:
                _export_efi(identity, fn, args.cc, args.objcopy)
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
