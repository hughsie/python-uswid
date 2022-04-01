#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2023 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=wrong-import-position,protected-access

from typing import List

import os
import sys
import unittest
import pefile

# allows us to run this from the project root
sys.path.append(os.path.realpath("."))

from uswid.pe import (
    PeFile,
    PeSection,
    PeSectionFlag,
    PeCoffDllCharacteristics,
    PeImageDirectoryEntry,
)


def _pe_sensible_warnings(pe: pefile.PE) -> List[str]:
    warnings: List[str] = []
    for warning in pe.get_warnings():
        if warning.startswith("Byte 0x00 makes up"):
            continue
        if warning.startswith("SizeOfHeaders is smaller than AddressOfEntryPoint"):
            continue
        if warning.startswith("AddressOfEntryPoint"):
            continue
        warnings.append(warning)
    return warnings


class Test(unittest.TestCase):
    def test_load(self):

        with open("./data/fwupdx64.efi", "rb") as f:
            data = f.read()
        pe = pefile.PE(data=data)
        self.assertEqual(_pe_sensible_warnings(pe), [])

        # all sections
        mype = PeFile(data)
        self.assertEqual(len(mype.sections), 7)

        # get specific section
        sect = mype.get_section_by_name(".text")
        assert sect
        self.assertEqual(len(sect.RawData), 31643)

    def test_export(self):

        with open("./data/fwupdx64.efi", "rb") as f:
            mype = PeFile(f.read())
        self.assertEqual(len(mype.sections), 7)
        pe = pefile.PE(data=mype.export())
        self.assertEqual(_pe_sensible_warnings(pe), [])

    def test_empty(self):

        mype = PeFile()
        mype.coff_hdr.DllCharacteristics = PeCoffDllCharacteristics.NX_COMPAT

        mype._relink()
        self.assertEqual(mype.coff_hdr.NumberOfSections, 0x0)
        self.assertEqual(mype.coff_hdr.SizeOfCode, 0x0)
        self.assertEqual(mype.coff_hdr.SizeOfInitializedData, 0x0)
        self.assertEqual(mype.coff_hdr.SizeOfUninitializedData, 0x0)
        self.assertEqual(mype.coff_hdr.AddressOfEntryPoint, 0x0)
        self.assertEqual(mype.coff_hdr.BaseOfCode, 0x0)
        self.assertEqual(mype.coff_hdr.ImageBase, 0x0)
        self.assertEqual(mype.coff_hdr.SizeOfImage, 0x200)
        self.assertEqual(mype.coff_hdr.SizeOfHeaders, 0x200)
        self.assertEqual(
            mype.data_directories[PeImageDirectoryEntry.BASERELOC].VirtualAddress.addr,
            0x0,
        )
        self.assertEqual(
            mype.data_directories[PeImageDirectoryEntry.BASERELOC].Size, 0x0
        )

        pe = pefile.PE(data=mype.export())
        self.assertEqual(_pe_sensible_warnings(pe), [])

    def test_one(self):

        mype = PeFile()
        mype.coff_hdr.DllCharacteristics = PeCoffDllCharacteristics.NX_COMPAT

        sect = PeSection()
        sect.Name = ".text"
        sect.RawData = b"Hello World"
        sect.Characteristics = (
            PeSectionFlag.IMAGE_SCN_MEM_READ
            | PeSectionFlag.IMAGE_SCN_MEM_EXECUTE
            | PeSectionFlag.IMAGE_SCN_CNT_CODE
        )
        mype.add_section(sect)

        mype._relink()
        self.assertEqual(len(sect.RawData), 0xB)
        self.assertEqual(sect.SizeOfRawData, 0x200)
        self.assertEqual(mype.coff_hdr.NumberOfSections, 0x1)
        self.assertEqual(mype.coff_hdr.SizeOfCode, 0x200)
        self.assertEqual(mype.coff_hdr.SizeOfInitializedData, 0x0)
        self.assertEqual(mype.coff_hdr.SizeOfUninitializedData, 0x0)
        self.assertEqual(mype.coff_hdr.AddressOfEntryPoint, 0x200)
        self.assertEqual(mype.coff_hdr.BaseOfCode, 0x200)
        self.assertEqual(mype.coff_hdr.ImageBase, 0x0)
        self.assertEqual(mype.coff_hdr.SizeOfImage, 0x400)
        self.assertEqual(mype.coff_hdr.SizeOfHeaders, 0x200)
        self.assertEqual(
            mype.data_directories[PeImageDirectoryEntry.BASERELOC].VirtualAddress.addr,
            0x0,
        )
        self.assertEqual(
            mype.data_directories[PeImageDirectoryEntry.BASERELOC].Size, 0x0
        )

        pe = pefile.PE(data=mype.export())
        self.assertEqual(_pe_sensible_warnings(pe), [])

    def test_reloc(self):

        mype = PeFile()

        sect = PeSection()
        sect.Name = ".text"
        sect.RawData = b"Hello World"
        sect.Characteristics = (
            PeSectionFlag.IMAGE_SCN_MEM_READ
            | PeSectionFlag.IMAGE_SCN_MEM_EXECUTE
            | PeSectionFlag.IMAGE_SCN_CNT_CODE
        )
        mype.add_section(sect)

        sect = PeSection()
        sect.Name = ".reloc"
        sect.RawData = b"Hello World"
        sect.Characteristics = (
            PeSectionFlag.IMAGE_SCN_CNT_INITIALIZED_DATA
            | PeSectionFlag.IMAGE_SCN_MEM_DISCARDABLE
            | PeSectionFlag.IMAGE_SCN_MEM_READ
        )
        mype.add_section(sect)

        mype._relink()
        # print(str(mype))
        self.assertEqual(mype.coff_hdr.NumberOfSections, 0x2)
        self.assertEqual(mype.coff_hdr.SizeOfCode, 0x200)
        self.assertEqual(mype.coff_hdr.SizeOfInitializedData, 0x200)
        self.assertEqual(mype.coff_hdr.SizeOfUninitializedData, 0x0)
        self.assertEqual(mype.coff_hdr.AddressOfEntryPoint, 0x200)
        self.assertEqual(mype.coff_hdr.BaseOfCode, 0x200)
        self.assertEqual(mype.coff_hdr.ImageBase, 0x0)
        self.assertEqual(mype.coff_hdr.SizeOfImage, 0x600)
        self.assertEqual(mype.coff_hdr.SizeOfHeaders, 0x200)
        # self.assertEqual(mype.data_directories[PeImageDirectoryEntry.BASERELOC].VirtualAddress.addr, 0x400)
        # self.assertEqual(mype.data_directories[PeImageDirectoryEntry.BASERELOC].Size, 0xB)

        pe = pefile.PE(data=mype.export())
        # pe.print_info()
        self.assertEqual(_pe_sensible_warnings(pe), [])


if __name__ == "__main__":
    unittest.main()
