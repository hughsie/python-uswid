#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=wrong-import-position

import argparse
import tempfile
import subprocess

import os
import sys

sys.path.append(os.path.realpath("."))

from uswid import uSwidIdentity, NotSupportedError


def main():
    parser = argparse.ArgumentParser(description="Generate CoSWID metadata")
    parser.add_argument("--cc", default="gcc", help="Compiler to use for empty object")
    parser.add_argument("--binfile", default=None, help="PE binary to modify")
    parser.add_argument(
        "--inifile", action="append", default=None, help="INI data source"
    )
    parser.add_argument(
        "--xmlfile", action="append", default=None, help="SWID XML data source"
    )
    parser.add_argument(
        "--objcopy", default="/usr/bin/objcopy", help="Binary file to use for objcopy"
    )
    parser.add_argument(
        "--verbose",
        dest="verbose",
        default=False,
        action="store_true",
        help="Show verbose operation",
    )
    args = parser.parse_args()
    if not args.binfile and not args.inifile and not args.xmlfile:
        print("Use uswid --help for command line arguments")
        sys.exit(1)

    # collect data here
    identity = uSwidIdentity()

    # load in existing uSwidIdentity object
    if args.binfile and os.path.exists(args.binfile):
        with tempfile.NamedTemporaryFile(
            mode="w+b", prefix="objcopy_", suffix=".bin", delete=True
        ) as dst:
            try:
                # pylint: disable=unexpected-keyword-arg
                subprocess.check_output(
                    [
                        args.objcopy,
                        "-O",
                        "binary",
                        "--only-section=.sbom",
                        args.binfile,
                        dst.name,
                    ],
                    stderr=subprocess.PIPE,
                )
            except subprocess.CalledProcessError as e:
                print(e)
                sys.exit(1)
            identity.import_bytes(dst.read())

            # debug
            if args.verbose:
                print("Loaded:\n{}".format(identity))

    # merge data
    if args.xmlfile:
        for xmlfile in args.xmlfile:
            try:
                with open(xmlfile, "rb") as f:
                    identity.import_xml(f.read())
            except FileNotFoundError:
                print("{} does not exist".format(xmlfile))
                sys.exit(1)
    if args.inifile:
        for inifile in args.inifile:
            try:
                with open(inifile, "rb") as f:
                    identity.import_ini(f.read().decode())
            except FileNotFoundError:
                print("{} does not exist".format(inifile))
                sys.exit(1)

    # create empty EFI binary?
    if args.binfile and not os.path.exists(args.binfile):
        subprocess.run(
            [args.cc, "-x", "c", "-c", "-o", args.binfile, "/dev/null"], check=True
        )

    # save to file?
    if args.verbose:
        print("Saving:\n{}".format(identity))
    try:
        blob = identity.export_bytes()
    except NotSupportedError as e:
        print(e)
        sys.exit(1)
    if args.binfile:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix="objcopy_", suffix=".bin", delete=True
        ) as src:
            src.write(blob)
            src.flush()
            try:
                # pylint: disable=unexpected-keyword-arg
                subprocess.check_output(
                    [
                        args.objcopy,
                        "--remove-section=.sbom",
                        "--add-section",
                        ".sbom={}".format(src.name),
                        "--set-section-flags",
                        ".sbom=contents,alloc,load,readonly,data",
                        args.binfile,
                    ]
                )
            except subprocess.CalledProcessError as e:
                print(e)
                sys.exit(1)
    else:
        print(blob)

    # success
    sys.exit(0)


if __name__ == "__main__":
    main()
