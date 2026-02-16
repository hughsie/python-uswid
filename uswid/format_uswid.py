#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# pylint: disable=too-few-public-methods,protected-access

from typing import Optional

import struct
import zlib
import lzma

from .enums import (
    USWID_HEADER_MAGIC,
    uSwidHeaderFlags,
    uSwidPayloadCompression,
    uSwidPayloadFormat,
)
from .container import uSwidContainer
from .format import uSwidFormatBase
from .errors import NotSupportedError
from .component import uSwidComponent
from .format_coswid import uSwidFormatCoswid
from .format_cyclonedx import uSwidFormatCycloneDX
from .format_spdx import uSwidFormatSpdx


class uSwidFormatUswid(uSwidFormatBase):
    """uSWID file"""

    def __init__(
        self,
        compress: bool = False,
        compression: uSwidPayloadCompression = uSwidPayloadCompression.NONE,
        fmt: uSwidPayloadFormat = uSwidPayloadFormat.COSWID,
    ) -> None:
        """Initializes uSwidFormatUswid"""
        uSwidFormatBase.__init__(self, "uSWID")
        self.compression: uSwidPayloadCompression = compression
        if self.compression == uSwidPayloadCompression.NONE and compress:
            self.compression = uSwidPayloadCompression.ZLIB
        self.format: uSwidPayloadFormat = fmt

    @property
    def compress(self) -> bool:
        """Provided for backward compatibility only"""
        return self.compression != uSwidPayloadCompression.NONE

    def load(self, blob: bytes, path: Optional[str] = None) -> uSwidContainer:
        container = uSwidContainer()

        # find magic GUIDs marking external uSWID sections
        offset: int = 0
        cnt: int = 0
        while 1:
            offset = blob.find(USWID_HEADER_MAGIC, offset)
            if offset == -1:
                break
            if self.verbose:
                print(f"Found USWID header at offset: {offset}")
            offset += self._load_bytes(container, blob, offset)
            cnt += 1
        if cnt == 0:
            raise NotSupportedError("file does not have expected magic GUID")
        return container

    @property
    def _fmt(self) -> uSwidFormatBase:

        if self.format == uSwidPayloadFormat.COSWID:
            return uSwidFormatCoswid
        if self.format == uSwidPayloadFormat.CYCLONEDX:
            return uSwidFormatCycloneDX
        if self.format == uSwidPayloadFormat.SPDX:
            return uSwidFormatSpdx
        raise NotSupportedError("SBOM format not supported")

    def save(self, container: uSwidContainer) -> bytes:

        flags: uSwidHeaderFlags = uSwidHeaderFlags.NONE
        blob: bytes = self._fmt().save(container)

        # v3 header specifies the compression type
        if self.compression == uSwidPayloadCompression.LZMA:
            payload = lzma.compress(blob, preset=9)
            flags |= uSwidHeaderFlags.COMPRESSED
        elif self.compression == uSwidPayloadCompression.ZLIB:
            payload = zlib.compress(blob)
            flags |= uSwidHeaderFlags.COMPRESSED
        else:
            payload = blob

        # v4 added support for non-coSWID data
        if self.format != uSwidPayloadFormat.COSWID:
            return (
                struct.pack(
                    "<16sBHIBBB",
                    USWID_HEADER_MAGIC,
                    4,  # version
                    26,  # hdrsz
                    len(payload),
                    flags,
                    self.compression,
                    self.format,
                )
                + payload
            )

        # v3 header added the compression type (allowing LZMA)
        if self.compression == uSwidPayloadCompression.LZMA:
            return (
                struct.pack(
                    "<16sBHIBB",
                    USWID_HEADER_MAGIC,
                    3,  # version
                    25,  # hdrsz
                    len(payload),
                    flags,
                    self.compression,
                )
                + payload
            )

        # v2 header specifies the flags and is our new baseline
        return (
            struct.pack(
                "<16sBHIB",
                USWID_HEADER_MAGIC,
                2,  # version
                24,  # hdrsz
                len(payload),
                flags,
            )
            + payload
        )

    def _load_bytes(self, container: uSwidContainer, blob: bytes, offset: int) -> int:
        _USWID_HEADER_FMT = "<BHI"

        # this is the most basic of headers
        hdrver, hdrsz, payloadsz = struct.unpack_from(
            _USWID_HEADER_FMT, blob, offset + len(USWID_HEADER_MAGIC)
        )
        if hdrver == 0:
            raise NotSupportedError("file does not have expected header version")
        payload = blob[offset + hdrsz : offset + hdrsz + payloadsz]

        # load flags and possibly decompress payload
        offset += struct.calcsize(_USWID_HEADER_FMT)
        if hdrver >= 4:
            (
                flags,
                self.compression,
                self.format,
            ) = struct.unpack_from("<BBB", blob, len(USWID_HEADER_MAGIC) + offset)
        elif hdrver >= 3:
            (
                flags,
                self.compression,
            ) = struct.unpack_from("<BB", blob, len(USWID_HEADER_MAGIC) + offset)
        elif hdrver == 2:
            (flags,) = struct.unpack_from("<B", blob, len(USWID_HEADER_MAGIC) + offset)
            if flags & uSwidHeaderFlags.COMPRESSED:
                self.compression = uSwidPayloadCompression.ZLIB
            else:
                self.compression = uSwidPayloadCompression.NONE

        # decompress
        if self.compression == uSwidPayloadCompression.NONE:
            pass
        elif self.compression == uSwidPayloadCompression.ZLIB:
            payload = zlib.decompress(payload)
        elif self.compression == uSwidPayloadCompression.LZMA:
            payload = lzma.decompress(payload)
        else:
            raise NotSupportedError(
                f"file has unknown compression type {self.compression}"
            )

        # read each blob of specified format
        payload_offset = 0
        while payload_offset < len(payload):
            component = uSwidComponent()
            payload_offset += self._fmt()._load_component(
                component, payload, payload_offset
            )
            container.append(component)

        # consumed
        return hdrsz + payloadsz
