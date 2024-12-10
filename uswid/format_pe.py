#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# pylint: disable=too-few-public-methods,protected-access

from typing import Optional

import sys
import shutil
import subprocess
import tempfile
import os

import pefile

from .container import uSwidContainer
from .format import uSwidFormatBase
from .errors import NotSupportedError
from .format_coswid import uSwidFormatCoswid


def _adjust_SectionSize(sz, align):
    if sz % align:
        sz = ((sz + align) // align) * align
    return sz


def _pe_get_section_by_name(pe: pefile.PE, name: str) -> pefile.SectionStructure:
    for sect in pe.sections:
        if sect.Name == name.encode().ljust(8, b"\0"):
            return sect
    return None


def _load_efi_objcopy(filepath: str, objcopy: str) -> uSwidContainer:
    """read EFI file using objcopy"""
    objcopy_full = shutil.which(objcopy)
    if not objcopy_full:
        print(f"executable {objcopy} not found")
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
        component = uSwidFormatCoswid().load(dst.read())
        component.add_source_filename(filepath)
        return component


def _save_efi_objcopy(
    container: uSwidContainer,
    filepath: str,
    cc: Optional[str],
    cflags: str,
    objcopy: str,
) -> None:
    """modify EFI file using objcopy"""
    objcopy_full = shutil.which(objcopy)
    if not objcopy_full:
        print(f"executable {objcopy} not found")
        sys.exit(1)
    if not os.path.exists(filepath):
        if not cc:
            raise NotSupportedError("compiler is required for missing section")
        subprocess.run(
            [cc, "-x", "c", "-c", "-o", filepath, "/dev/null"] + cflags.split(" "),
            check=True,
        )

    # save to file?
    try:
        blob = uSwidFormatCoswid().save(container)
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
                    f".sbom={src.name}",
                    "--set-section-flags",
                    ".sbom=contents,alloc,load,readonly,data",
                    filepath,
                ]
            )
        except subprocess.CalledProcessError as e:
            print(e)
            sys.exit(1)


class uSwidFormatPe(uSwidFormatBase):
    """PE file"""

    def __init__(self, filepath: Optional[str] = None) -> None:
        """Initializes uSwidFormatPe"""
        uSwidFormatBase.__init__(self, "PE")  # type:ignore[call-arg]
        self.objcopy: Optional[str] = None
        self.cc: Optional[str] = None
        self.cflags: Optional[str] = None
        self.filepath: Optional[str] = filepath

    def load(self, blob: bytes, path: Optional[str] = None) -> uSwidContainer:

        if not path:
            raise NotSupportedError("cannot load when no path")
        if self.objcopy:
            return _load_efi_objcopy(path, objcopy=self.objcopy)

        pe = pefile.PE(data=blob)
        sect = _pe_get_section_by_name(pe, ".sbom")
        if not sect:
            raise NotSupportedError(
                "PE files have to have an linker-defined .sbom section"
            )
        container = uSwidFormatCoswid().load(sect.get_data())
        if self.filepath:
            for component in container:
                component.add_source_filename(self.filepath)
        return container

    def save(self, container: uSwidContainer) -> bytes:

        if not self.filepath:
            raise NotSupportedError("cannot save when no path")
        if self.objcopy:
            # if not self.cflags:
            #    raise NotSupportedError("cannot save when no cflags")
            _save_efi_objcopy(
                container, self.filepath, self.cc, self.cflags or "", self.objcopy
            )
            return b""

        blob = uSwidFormatCoswid().save(container)
        pe = pefile.PE(self.filepath)
        sect = _pe_get_section_by_name(pe, ".sbom")
        if not sect:
            raise NotSupportedError(
                "PE files have to have an linker-defined .sbom section"
            )

        # can we squeeze the new uSWID blob into the existing space
        sect.Misc = len(blob)
        if len(blob) <= sect.SizeOfRawData:
            pe.set_bytes_at_offset(sect.PointerToRawData, blob)

        # save
        return pe.write()
