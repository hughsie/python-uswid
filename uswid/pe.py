#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# See https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=wrong-import-position,protected-access


from struct import unpack_from, pack, calcsize
from typing import Dict, Any, Optional, List
from enum import IntEnum

import json


def _align_up(value: int, align: int) -> int:
    if value == 0 or align == 0:
        return 0
    if value % align == 0:
        return value
    return (int(value / align) + 1) * align


class PeDosHeader:

    _STRUCT_FORMAT = "<HHHHHHHHHHHHHH8sHH20sL"

    def __init__(self, buf: Optional[bytes] = None, offset: int = 0):

        self.e_magic: int = 0x5A4D
        self.e_cblp: int = 0x90  # bytes on last page of file
        self.e_cp: int = 0x3  # pages in file
        self.e_crlc: int = 0x0  # relocations
        self.e_cparhdr: int = 0x4  # size of header in paragraphs
        self.e_minalloc: int = 0x0  # minimum extra paragraphs needed
        self.e_maxalloc: int = 0xFFFF  # maximum extra paragraphs needed
        self.e_ss: int = 0x0  # initial (relative) SS value
        self.e_sp: int = 0xB8  # initial SP value
        self.e_csum: int = 0x0  # checksum
        self.e_ip: int = 0x0  # initial IP value
        self.e_cs: int = 0x0  # initial (relative) CS value
        self.e_lfarlc: int = 0x40  # file address of relocation table
        self.e_ovno: int = 0x0  # overlay version
        self.e_res: bytes = b""  # reserved words
        self.e_oemid: int = 0x0  # OEM ID
        self.e_oeminfo: int = 0x0  # OEM info
        self.e_res2: bytes = b""  # more reserved words
        self.e_lfanew: int = 0x80  # file address of EXE header
        if buf:
            self._import(buf, offset)

    def _import(self, buf: bytes, offset: int = 0) -> None:
        (
            self.e_magic,
            self.e_cblp,
            self.e_cp,
            self.e_crlc,
            self.e_cparhdr,
            self.e_minalloc,
            self.e_maxalloc,
            self.e_ss,
            self.e_sp,
            self.e_csum,
            self.e_ip,
            self.e_cs,
            self.e_lfarlc,
            self.e_ovno,
            self.e_res,
            self.e_oemid,
            self.e_oeminfo,
            self.e_res2,
            self.e_lfanew,
        ) = unpack_from(self._STRUCT_FORMAT, buf, offset)

    def __len__(self) -> int:
        return calcsize(self._STRUCT_FORMAT)

    def _json(self) -> Dict[str, Any]:
        return {
            "e_magic": "0x{:04X}".format(self.e_magic),
            "e_cblp": "0x{:04X}".format(self.e_cblp),
            "e_cp": "0x{:04X}".format(self.e_cp),
            "e_crlc": "0x{:04X}".format(self.e_crlc),
            "e_cparhdr": "0x{:04X}".format(self.e_cparhdr),
            "e_minalloc": "0x{:04X}".format(self.e_minalloc),
            "e_maxalloc": "0x{:04X}".format(self.e_maxalloc),
            "e_ss": "0x{:04X}".format(self.e_ss),
            "e_sp": "0x{:04X}".format(self.e_sp),
            "e_csum": "0x{:04X}".format(self.e_csum),
            "e_ip": "0x{:04X}".format(self.e_ip),
            "e_cs": "0x{:04X}".format(self.e_cs),
            "e_lfarlc": "0x{:04X}".format(self.e_lfarlc),
            "e_ovno": "0x{:04X}".format(self.e_ovno),
            # "e_res": self.e_res,
            "e_oemid": "0x{:04X}".format(self.e_oemid),
            "e_oeminfo": "0x{:04X}".format(self.e_oeminfo),
            # "e_res2": self.e_res2,
            "e_lfanew": "0x{:02X}".format(self.e_lfanew),
        }

    def __str__(self) -> str:
        return json.dumps(self._json(), indent=4)

    def _export(self) -> bytes:
        return pack(
            self._STRUCT_FORMAT,
            self.e_magic,
            self.e_cblp,
            self.e_cp,
            self.e_crlc,
            self.e_cparhdr,
            self.e_minalloc,
            self.e_maxalloc,
            self.e_ss,
            self.e_sp,
            self.e_csum,
            self.e_ip,
            self.e_cs,
            self.e_lfarlc,
            self.e_ovno,
            self.e_res,
            self.e_oemid,
            self.e_oeminfo,
            self.e_res2,
            self.e_lfanew,
        )


class PeDosStub:

    _STRUCT_FORMAT = "<64s"

    def __init__(self, buf: Optional[bytes] = None, offset: int = 0):
        self.RawData: bytes = b""
        if buf:
            self._import(buf, offset)

    def _import(self, buf: bytes, offset: int = 0) -> None:
        (self.RawData,) = unpack_from(self._STRUCT_FORMAT, buf, offset)

    def _json(self) -> Dict[str, Any]:
        return {
            "RawDataSz": "0x{:04X}".format(len(self.RawData) if self.RawData else 0x0)
        }

    def __str__(self) -> str:
        return json.dumps(self._json(), indent=4)

    def __len__(self) -> int:
        return calcsize(self._STRUCT_FORMAT)

    def _export(self) -> bytes:
        return pack(self._STRUCT_FORMAT, self.RawData)


class PeCoffDllCharacteristics(IntEnum):
    HIGH_ENTROPY_VA = 0x0020
    DYNAMIC_BASE = 0x0040
    FORCE_INTEGRITY = 0x0080
    NX_COMPAT = 0x0100
    NO_ISOLATION = 0x0200
    NO_SEH = 0x0400
    NO_BIND = 0x0800
    APPCONTAINER = 0x1000
    WDM_DRIVER = 0x2000
    GUARD_CF = 0x4000
    TERMINAL_SERVER_AWARE = 0x8000


class PeCoffHeader:

    _STRUCT_FORMAT_64 = "<LHHLLLHHHBBLLLLLQLLHHHHHHLLLLHHQQQQLL"
    _STRUCT_FORMAT_32 = "<LHHLLLHHHBBLLLLLLLLLHHHHHHLLLLHHLLLLLL"

    def __init__(self, buf: Optional[bytes] = None, offset: int = 0):
        self.Signature: int = 0x4550
        self.Machine: int = 0x8664
        self._NumberOfSections: int = 0
        self.TimeDateStamp: int = 0
        self.PointerToSymbolTable: int = 0
        self.NumberOfSymbols: int = 0
        self.SizeOfOptionalHeader: int = 0xF0
        self.Characteristics: int = 0x2022
        self.Magic: int = 0x020B
        self.MajorLinkerVersion: int = 0x0E
        self.MinorLinkerVersion: int = 0x0E
        self._SizeOfCode: int = 0x0
        self._SizeOfInitializedData: int = 0x0
        self._SizeOfUninitializedData: int = 0x0
        self.AddressOfEntryPoint: int = 0x0
        self._BaseOfCode: int = 0x0
        # self.BaseOfData: int = 0x0
        self.ImageBase: int = 0x0
        self.SectionAlignment: int = 0x200
        self.FileAlignment: int = 0x200
        self.MajorOperatingSystemVersion: int = 0x0
        self.MinorOperatingSystemVersion: int = 0x0
        self.MajorImageVersion: int = 0x0
        self.MinorImageVersion: int = 0x0
        self.MajorSubsystemVersion: int = 0x0
        self.MinorSubsystemVersion: int = 0x0
        self.Win32VersionValue: int = 0x0
        self.SizeOfImage: int = 0x0
        self._SizeOfHeaders: int = 0x0
        self.CheckSum: int = 0x0
        self.Subsystem: int = 0xA
        self.DllCharacteristics: int = 0x0
        self.SizeOfStackReserve: int = 0x0
        self.SizeOfStackCommit: int = 0x0
        self.SizeOfHeapReserve: int = 0x0
        self.SizeOfHeapCommit: int = 0x0
        self.LoaderFlags: int = 0x0
        self._NumberOfRvaAndSizes: int = 0x0
        if buf:
            self._import(buf, offset)

    def _import(self, buf: bytes, offset: int = 0) -> None:
        (
            self.Signature,
            self.Machine,
            self._NumberOfSections,
            self.TimeDateStamp,
            self.PointerToSymbolTable,
            self.NumberOfSymbols,
            self.SizeOfOptionalHeader,
            self.Characteristics,
            self.Magic,
            self.MajorLinkerVersion,
            self.MinorLinkerVersion,
            self._SizeOfCode,
            self._SizeOfInitializedData,
            self._SizeOfUninitializedData,
            self.AddressOfEntryPoint,
            self._BaseOfCode,
            # self.BaseOfData,
            self.ImageBase,
            self.SectionAlignment,
            self.FileAlignment,
            self.MajorOperatingSystemVersion,
            self.MinorOperatingSystemVersion,
            self.MajorImageVersion,
            self.MinorImageVersion,
            self.MajorSubsystemVersion,
            self.MinorSubsystemVersion,
            self.Win32VersionValue,
            self.SizeOfImage,
            self._SizeOfHeaders,
            self.CheckSum,
            self.Subsystem,
            self.DllCharacteristics,
            self.SizeOfStackReserve,
            self.SizeOfStackCommit,
            self.SizeOfHeapReserve,
            self.SizeOfHeapCommit,
            self.LoaderFlags,
            self._NumberOfRvaAndSizes,
        ) = unpack_from(self._STRUCT_FORMAT_64, buf, offset)

    @property
    def NumberOfSections(self) -> int:
        return self._NumberOfSections

    @property
    def SizeOfCode(self) -> int:
        return self._SizeOfCode

    @property
    def SizeOfUninitializedData(self) -> int:
        return self._SizeOfUninitializedData

    @property
    def SizeOfInitializedData(self) -> int:
        return self._SizeOfInitializedData

    @property
    def BaseOfCode(self) -> int:
        return self._BaseOfCode

    @property
    def SizeOfHeaders(self) -> int:
        return self._SizeOfHeaders

    @property
    def NumberOfRvaAndSizes(self) -> int:
        return self._NumberOfRvaAndSizes

    def _json(self) -> Dict[str, Any]:
        return {
            "Signature": "0x{:04X}".format(self.Signature),
            "Machine": "0x{:04X}".format(self.Machine),
            "NumberOfSections": "0x{:02X}".format(self.NumberOfSections),
            "TimeDateStamp": "0x{:X}".format(self.TimeDateStamp),
            "PointerToSymbolTable": "0x{:X}".format(self.PointerToSymbolTable),
            "NumberOfSymbols": "0x{:X}".format(self.NumberOfSymbols),
            "SizeOfOptionalHeader": "0x{:X}".format(self.SizeOfOptionalHeader),
            "Characteristics": "0x{:X}".format(self.Characteristics),
            "Magic": "0x{:X}".format(self.Magic),
            "MajorLinkerVersion": "0x{:X}".format(self.MajorLinkerVersion),
            "MinorLinkerVersion": "0x{:X}".format(self.MinorLinkerVersion),
            "SizeOfCode": "0x{:X}".format(self.SizeOfCode),
            "SizeOfInitializedData": "0x{:X}".format(self.SizeOfInitializedData),
            "SizeOfUninitializedData": "0x{:X}".format(self.SizeOfUninitializedData),
            "AddressOfEntryPoint": "0x{:X}".format(self.AddressOfEntryPoint),
            "BaseOfCode": "0x{:X}".format(self.BaseOfCode),
            # "BaseOfData": "0x{:X}".format(self.BaseOfData),
            "ImageBase": "0x{:X}".format(self.ImageBase),
            "SectionAlignment": "0x{:X}".format(self.SectionAlignment),
            "FileAlignment": "0x{:X}".format(self.FileAlignment),
            "MajorOperatingSystemVersion": "0x{:X}".format(
                self.MajorOperatingSystemVersion
            ),
            "MinorOperatingSystemVersion": "0x{:X}".format(
                self.MinorOperatingSystemVersion
            ),
            "MajorImageVersion": "0x{:X}".format(self.MajorImageVersion),
            "MinorImageVersion": "0x{:X}".format(self.MinorImageVersion),
            "MajorSubsystemVersion": "0x{:X}".format(self.MajorSubsystemVersion),
            "MinorSubsystemVersion": "0x{:X}".format(self.MinorSubsystemVersion),
            "Win32VersionValue": "0x{:X}".format(self.Win32VersionValue),
            "SizeOfImage": "0x{:X}".format(self.SizeOfImage),
            "SizeOfHeaders": "0x{:X}".format(self.SizeOfHeaders),
            "CheckSum": "0x{:X}".format(self.CheckSum),
            "Subsystem": "0x{:X}".format(self.Subsystem),
            "DllCharacteristics": "0x{:X}".format(self.DllCharacteristics),
            "SizeOfStackReserve": "0x{:X}".format(self.SizeOfStackReserve),
            "SizeOfStackCommit": "0x{:X}".format(self.SizeOfStackCommit),
            "SizeOfHeapReserve": "0x{:X}".format(self.SizeOfHeapReserve),
            "SizeOfHeapCommit": "0x{:X}".format(self.SizeOfHeapCommit),
            "LoaderFlags": "0x{:X}".format(self.LoaderFlags),
            "NumberOfRvaAndSizes": "0x{:X}".format(self.NumberOfRvaAndSizes),
        }

    def __str__(self) -> str:
        return json.dumps(self._json(), indent=4)

    def __len__(self) -> int:
        return calcsize(self._STRUCT_FORMAT_64)

    def _export(self) -> bytes:
        return pack(
            self._STRUCT_FORMAT_64,
            self.Signature,
            self.Machine,
            self.NumberOfSections,
            self.TimeDateStamp,
            self.PointerToSymbolTable,
            self.NumberOfSymbols,
            self.SizeOfOptionalHeader,
            self.Characteristics,
            self.Magic,
            self.MajorLinkerVersion,
            self.MinorLinkerVersion,
            self.SizeOfCode,
            self.SizeOfInitializedData,
            self.SizeOfUninitializedData,
            self.AddressOfEntryPoint,
            self.BaseOfCode,
            # self.BaseOfData,
            self.ImageBase,
            self.SectionAlignment,
            self.FileAlignment,
            self.MajorOperatingSystemVersion,
            self.MinorOperatingSystemVersion,
            self.MajorImageVersion,
            self.MinorImageVersion,
            self.MajorSubsystemVersion,
            self.MinorSubsystemVersion,
            self.Win32VersionValue,
            self.SizeOfImage,
            self.SizeOfHeaders,
            self.CheckSum,
            self.Subsystem,
            self.DllCharacteristics,
            self.SizeOfStackReserve,
            self.SizeOfStackCommit,
            self.SizeOfHeapReserve,
            self.SizeOfHeapCommit,
            self.LoaderFlags,
            self.NumberOfRvaAndSizes,
        )


class PeRVA:
    def __init__(self, addr: int = 0):

        self._addr = addr
        self._offset = 0x0
        self._section: Optional["PeSection"] = None

    @property
    def addr(self) -> int:
        return self._addr

    @property
    def section(self) -> Optional["PeSection"]:
        return self._section

    @section.setter
    def section(self, section: Optional["PeSection"]) -> None:
        self._section = section
        if section:
            self._offset = self._addr - section.VirtualAddress

    def update_from_section_va(self) -> None:
        if not self._section:
            return
        self._addr = self._section.VirtualAddress + self._offset

    def _json(self) -> Dict[str, Any]:
        val = {
            "Addr": "0x{:X}".format(self._addr),
        }
        if self._section:
            val["Offset"] = "0x{:X}".format(self._offset)
            val["Section"] = self._section.Name
        return val

    def __str__(self) -> str:
        return json.dumps(self._json(), indent=4)


class PeDataDirectory:
    _STRUCT_FORMAT = "<LL"

    def __init__(self, buf: Optional[bytes] = None, offset: int = 0):

        self.VirtualAddress: PeRVA = PeRVA()
        self.Size: int = 0x0
        if buf:
            self._import(buf, offset)

    def _import(self, buf: bytes, offset: int = 0) -> None:
        self.VirtualAddress._addr, self.Size = unpack_from(
            self._STRUCT_FORMAT, buf, offset
        )

    def _json(self) -> Dict[str, Any]:
        return {
            "VirtualAddress": self.VirtualAddress._json(),
            "Size": "0x{:02X}".format(self.Size),
        }

    def __len__(self) -> int:
        return calcsize(self._STRUCT_FORMAT)

    def __str__(self) -> str:
        return json.dumps(self._json(), indent=4)

    def _export(self) -> bytes:
        return pack(self._STRUCT_FORMAT, self.VirtualAddress.addr, self.Size)


class PeSectionFlag(IntEnum):
    IMAGE_SCN_TYPE_NO_PAD = 0x00000008
    IMAGE_SCN_CNT_CODE = 0x00000020
    IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
    IMAGE_SCN_LNK_OTHER = 0x00000100
    IMAGE_SCN_LNK_INFO = 0x00000200
    IMAGE_SCN_LNK_REMOVE = 0x00000800
    IMAGE_SCN_LNK_COMDAT = 0x00001000
    IMAGE_SCN_GPREL = 0x00008000
    IMAGE_SCN_MEM_PURGEABLE = 0x00020000
    IMAGE_SCN_MEM_16BIT = 0x00020000
    IMAGE_SCN_MEM_LOCKED = 0x00040000
    IMAGE_SCN_MEM_PRELOAD = 0x00080000
    IMAGE_SCN_ALIGN_1BYTES = 0x00100000
    IMAGE_SCN_ALIGN_2BYTES = 0x00200000
    IMAGE_SCN_ALIGN_4BYTES = 0x00300000
    IMAGE_SCN_ALIGN_8BYTES = 0x00400000
    IMAGE_SCN_ALIGN_16BYTES = 0x00500000
    IMAGE_SCN_ALIGN_32BYTES = 0x00600000
    IMAGE_SCN_ALIGN_64BYTES = 0x00700000
    IMAGE_SCN_ALIGN_128BYTES = 0x00800000
    IMAGE_SCN_ALIGN_256BYTES = 0x00900000
    IMAGE_SCN_ALIGN_512BYTES = 0x00A00000
    IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000
    IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000
    IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000
    IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000
    IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000
    IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
    IMAGE_SCN_MEM_NOT_CACHED = 0x04000000
    IMAGE_SCN_MEM_NOT_PAGED = 0x08000000
    IMAGE_SCN_MEM_SHARED = 0x10000000
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_SCN_MEM_READ = 0x40000000
    IMAGE_SCN_MEM_WRITE = 0x80000000


class PeSection:
    _STRUCT_FORMAT = "<8sLLLLLLHHL"

    def __init__(self, buf: Optional[bytes] = None, offset: int = 0, align: int = 0):

        self._align = align

        self.Name: str = ""
        self._VirtualSize: int = 0x0
        self.VirtualAddress: int = 0x0
        self.PointerToRawData: int = 0x0
        self.PointerToRelocations: int = 0x0
        self.PointerToLinenumbers: int = 0x0
        self.NumberOfRelocations: int = 0x0
        self.NumberOfLinenumbers: int = 0x0
        self.Characteristics: int = 0x0
        self._RawData: bytes = b""
        if buf:
            self._import(buf, offset)

    def _import(self, buf: bytes, offset: int = 0) -> None:
        (
            _Name,
            self._VirtualSize,
            self.VirtualAddress,
            _SizeOfRawData,
            self.PointerToRawData,
            self.PointerToRelocations,
            self.PointerToLinenumbers,
            self.NumberOfRelocations,
            self.NumberOfLinenumbers,
            self.Characteristics,
        ) = unpack_from(self._STRUCT_FORMAT, buf, offset)
        if self._VirtualSize and self.PointerToRawData:
            self._RawData = buf[
                self.PointerToRawData : self.PointerToRawData + self._VirtualSize
            ]
        self.Name = _Name.decode().replace("\0", "")

    @property
    def RawData(self) -> bytes:
        return self._RawData

    @RawData.setter
    def RawData(self, buf: bytes) -> None:
        self._RawData = buf
        self._VirtualSize = len(buf)

    @property
    def SizeOfRawData(self) -> int:
        if not self._RawData:
            return 0
        return _align_up(len(self._RawData), self._align)

    @property
    def VirtualSize(self) -> int:
        return self._VirtualSize

    def _json(self) -> Dict[str, Any]:
        return {
            "Name": self.Name,
            "VirtualSize": "0x{:04X}".format(self.VirtualSize),
            "VirtualAddress": "0x{:02X}".format(self.VirtualAddress),
            "SizeOfRawData": "0x{:02X}".format(self.SizeOfRawData),
            "PointerToRawData": "0x{:02X}".format(self.PointerToRawData),
            "PointerToRelocations": "0x{:02X}".format(self.PointerToRelocations),
            "PointerToLinenumbers": "0x{:02X}".format(self.PointerToLinenumbers),
            "NumberOfRelocations": "0x{:02X}".format(self.NumberOfRelocations),
            "NumberOfLinenumbers": "0x{:02X}".format(self.NumberOfLinenumbers),
            "Characteristics": "0x{:02X}".format(self.Characteristics),
        }

    def __len__(self) -> int:
        return calcsize(self._STRUCT_FORMAT)

    def __str__(self) -> str:
        return json.dumps(self._json(), indent=4)

    def _export(self) -> bytes:
        return pack(
            self._STRUCT_FORMAT,
            self.Name.encode().ljust(8, b"\0"),
            self.VirtualSize,
            self.VirtualAddress,
            self.SizeOfRawData,
            self.PointerToRawData,
            self.PointerToRelocations,
            self.PointerToLinenumbers,
            self.NumberOfRelocations,
            self.NumberOfLinenumbers,
            self.Characteristics,
        )


class PeImageDirectoryEntry(IntEnum):
    EXPORT = 0
    IMPORT = 1
    RESOURCE = 2
    EXCEPTION = 3
    SECURITY = 4
    BASERELOC = 5
    DEBUG = 6
    COPYRIGHT = 7
    GLOBALPTR = 8
    TLS = 9
    LOAD_CONFIG = 10
    BOUND_IMPORT = 11
    IAT = 12
    DELAY_IMPORT = 13
    COM_DESCRIPTOR = 14
    RESERVED = 15


class PeFile:
    def __init__(self, buf: Optional[bytes] = None):

        self.data_directories: List[PeDataDirectory] = [PeDataDirectory()] * 0x10
        self._sections: Dict[str, PeSection] = {}
        self.dos_hdr: PeDosHeader = PeDosHeader()
        self.dos_stub: PeDosStub = PeDosStub()
        self.coff_hdr: PeCoffHeader = PeCoffHeader()
        self.symbol_table = b""
        if buf:
            self._import(buf)

    def _import(self, buf: bytes) -> None:

        self.dos_hdr._import(buf)
        self.dos_stub._import(buf, 0x40)

        offset: int = self.dos_hdr.e_lfanew

        self.coff_hdr._import(buf, offset)

        # avoid parsing this and just take the blob to the end
        if self.coff_hdr.PointerToSymbolTable:
            self.symbol_table = buf[self.coff_hdr.PointerToSymbolTable : len(buf)]

        offset += len(self.coff_hdr)

        self.data_directories.clear()
        for _ in range(self.coff_hdr.NumberOfRvaAndSizes):
            data_directory = PeDataDirectory(buf, offset)
            self.data_directories.append(data_directory)
            offset += len(data_directory)
        for _ in range(self.coff_hdr._NumberOfSections):
            section = PeSection(buf, offset, align=self.coff_hdr.FileAlignment)
            self._sections[section.Name] = section
            offset += len(section)

        # convert all the RVAs to physical addresses
        for directory in self.data_directories:
            if not directory.VirtualAddress.addr:
                continue
            sect = self._find_section_for_virtual_addr(directory.VirtualAddress.addr)
            if sect:
                directory.VirtualAddress.section = sect

    def _find_section_for_virtual_addr(self, addr: int) -> Optional[PeSection]:
        for section in self.sections:
            if not section.VirtualAddress:
                continue
            if (
                section.VirtualAddress
                >= addr
                < section.VirtualAddress + section.VirtualSize
            ):
                return section
        return None

    @property
    def sections(self) -> List[PeSection]:
        return list(self._sections.values())

    def add_section(self, section: PeSection) -> None:
        self._sections[section.Name] = section
        section._align = self.coff_hdr.FileAlignment

    def get_section_by_name(self, name: str) -> Optional[PeSection]:
        return self._sections.get(name)

    def get_section_by_characteristic(self, flag: PeSectionFlag) -> Optional[PeSection]:
        for section in self.sections:
            if section.Characteristics & flag:
                return section
        return None

    def _relink(self) -> None:

        # update COFF header as soon as possible
        self.coff_hdr._NumberOfSections = len(self._sections)
        self.coff_hdr._NumberOfRvaAndSizes = len(self.data_directories)

        # update code sizes
        self.coff_hdr._SizeOfCode = 0
        self.coff_hdr._SizeOfInitializedData = 0x0
        self.coff_hdr._SizeOfUninitializedData = 0x0
        sect: Optional[PeSection]
        for sect in self.sections:
            if sect.Characteristics & PeSectionFlag.IMAGE_SCN_CNT_CODE:
                self.coff_hdr._SizeOfCode += _align_up(
                    sect.VirtualSize, self.coff_hdr.FileAlignment
                )
        for sect in self.sections:
            if sect.Name == "/4":
                continue
            if sect.Characteristics & PeSectionFlag.IMAGE_SCN_CNT_INITIALIZED_DATA:
                self.coff_hdr._SizeOfInitializedData += _align_up(
                    sect.VirtualSize, self.coff_hdr.FileAlignment
                )
        for sect in self.sections:
            if sect.Characteristics & PeSectionFlag.IMAGE_SCN_CNT_UNINITIALIZED_DATA:
                self.coff_hdr._SizeOfUninitializedData += _align_up(
                    sect.VirtualSize, self.coff_hdr.FileAlignment
                )

        # generate something sane
        raw_offset = len(self.dos_hdr) + len(self.dos_stub) + len(self.coff_hdr)

        # headers done
        for section in self.sections:
            raw_offset += len(section)
        for data_directory in self.data_directories:
            raw_offset += len(data_directory)
        raw_offset = _align_up(raw_offset, self.coff_hdr.FileAlignment)
        self.coff_hdr._SizeOfHeaders = raw_offset

        # section data itself
        virtual_offset = _align_up(raw_offset, self.coff_hdr.SectionAlignment)
        for sect in self.sections:
            if sect.SizeOfRawData:
                sect.PointerToRawData = raw_offset
                sect.VirtualAddress = virtual_offset
                raw_offset += _align_up(sect.SizeOfRawData, self.coff_hdr.FileAlignment)
                virtual_offset += _align_up(
                    sect.VirtualSize, self.coff_hdr.SectionAlignment
                )

        # entry point is .text if unset
        if self.coff_hdr.AddressOfEntryPoint == 0x0:
            sect = self._sections.get(".text")
            self.coff_hdr.AddressOfEntryPoint = sect.VirtualAddress if sect else 0x0

        # BASERELOC
        sect = self.get_section_by_name(".reloc")
        if sect:
            data_dir = self.data_directories[PeImageDirectoryEntry.BASERELOC]
            data_dir.VirtualAddress.section = sect

        # symbol table
        if self.symbol_table:
            self.coff_hdr.PointerToSymbolTable = raw_offset

        # pointer to .text
        sect = self.get_section_by_characteristic(PeSectionFlag.IMAGE_SCN_CNT_CODE)
        if sect:
            self.coff_hdr._BaseOfCode = sect.VirtualAddress

        # total virtual size
        self.coff_hdr.SizeOfImage = virtual_offset

        # recalculate the RVAs for each directory
        for directory in self.data_directories:
            directory.VirtualAddress.update_from_section_va()

    def export(self) -> bytes:

        self._relink()

        buf: bytes = b""

        # export blob
        buf += self.dos_hdr._export()
        buf += self.dos_stub._export()
        buf += self.coff_hdr._export()
        for data_directory in self.data_directories:
            buf += data_directory._export()
        for section in self.sections:
            buf += section._export()
        buf += b"\0" * (
            _align_up(self.coff_hdr._SizeOfHeaders, self.coff_hdr.FileAlignment)
            - len(buf)
        )
        for sect in self.sections:
            buf += sect.RawData
            buf += b"\0" * (sect.SizeOfRawData - len(sect.RawData))
        if self.symbol_table:
            buf += self.symbol_table

        return buf

    def _json(self) -> Dict[str, Any]:
        return {
            "DosHdr": self.dos_hdr._json(),
            "DosStub": self.dos_stub._json(),
            "CoffHdr": self.coff_hdr._json(),
            "DataDirectories": [d._json() for d in self.data_directories],
            "Sections": [d._json() for d in self.sections],
        }

    def __str__(self) -> str:
        return json.dumps(self._json(), indent=4)
