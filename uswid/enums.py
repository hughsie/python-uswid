#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent

from enum import IntEnum


class uSwidVersionScheme(IntEnum):
    """Represents an enumerated version scheme"""

    UNKNOWN = 0
    MULTIPARTNUMERIC = 1
    MULTIPARTNUMERIC_SUFFIX = 2
    ALPHANUMERIC = 3
    DECIMAL = 4
    SEMVER = 16384

    def __str__(self):
        return self.name.lower()

    @classmethod
    def from_version(cls, version: str) -> "uSwidVersionScheme":
        """guesses a version scheme from a version string"""

        version_set = set(version)
        if version_set.issubset(set("0123456789")):
            return cls(uSwidVersionScheme.DECIMAL)
        if version_set.issubset(set("0123456789.")):
            return cls(uSwidVersionScheme.SEMVER)
        if version_set.issubset(set("0123456789.-")):
            return cls(uSwidVersionScheme.MULTIPARTNUMERIC)
        return cls(uSwidVersionScheme.ALPHANUMERIC)


USWID_HEADER_MAGIC = b"\x53\x42\x4F\x4D\xD6\xBA\x2E\xAC\xA3\xE6\x7A\x52\xAA\xEE\x3B\xAF"

# deprecated
USWID_HEADER_FLAG_COMPRESSED = 0x01


class uSwidHeaderFlags(IntEnum):
    """The header flags type"""

    NONE = 0x00
    COMPRESSED = 0x01

    def __str__(self):
        return self.name.lower()


class uSwidPayloadCompression(IntEnum):
    """The payload compression type"""

    NONE = 0
    ZLIB = 1
    LZMA = 2

    def __str__(self):
        return self.name.lower()

    def __repr__(self):
        return str(self)

    @staticmethod
    def argparse(s):
        """Used only for argparse"""
        try:
            return uSwidPayloadCompression[s.upper()]
        except KeyError:
            return s
