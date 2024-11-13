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

from .enums import USWID_HEADER_MAGIC, uSwidHeaderFlags, uSwidPayloadCompression
from .container import uSwidContainer
from .format import uSwidFormatBase
from .errors import NotSupportedError
from .component import uSwidComponent
from .format_coswid import uSwidFormatCoswid


class uSwidFormatUswid(uSwidFormatBase):
    """uSWID file"""

    def __init__(
        self,
        compress: bool = False,
        compression: uSwidPayloadCompression = uSwidPayloadCompression.NONE,
    ) -> None:
        """Initializes uSwidFormatUswid"""
        uSwidFormatBase.__init__(self, "uSWID")
        self.compression: uSwidPayloadCompression = compression
        if self.compression == uSwidPayloadCompression.NONE and compress:
            self.compression = uSwidPayloadCompression.ZLIB

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

    def save(self, container: uSwidContainer) -> bytes:
        blob: bytes = b""
        for component in container:
            blob += uSwidFormatCoswid()._save_component(component)

        # v3 header specifies the compression type
        if self.compression == uSwidPayloadCompression.LZMA:
            payload = lzma.compress(blob, preset=9)
            return (
                struct.pack(
                    "<16sBHIBB",
                    USWID_HEADER_MAGIC,
                    3,  # version
                    25,  # hdrsz
                    len(payload),
                    uSwidHeaderFlags.COMPRESSED,
                    uSwidPayloadCompression.LZMA,
                )
                + payload
            )

        # v2 header specifies the flags
        if self.compression == uSwidPayloadCompression.ZLIB:
            payload = zlib.compress(blob)
            return (
                struct.pack(
                    "<16sBHIB",
                    USWID_HEADER_MAGIC,
                    2,  # version
                    24,  # hdrsz
                    len(payload),
                    uSwidHeaderFlags.COMPRESSED,  # flags
                )
                + payload
            )

        # old format
        return (
            struct.pack(
                "<16sBHIB",
                USWID_HEADER_MAGIC,
                2,  # version
                24,  # hdrsz
                len(blob),
                uSwidHeaderFlags.NONE,
            )
            + blob
        )

    def _load_bytes(self, container: uSwidContainer, blob: bytes, offset: int) -> int:
        _USWID_HEADER_FMT = "<BHI"

        # this is the most basic of headers
        (hdrver, hdrsz, payloadsz) = struct.unpack_from(
            _USWID_HEADER_FMT, blob, offset + len(USWID_HEADER_MAGIC)
        )
        if hdrver == 0:
            raise NotSupportedError("file does not have expected header version")
        payload = blob[offset + hdrsz : offset + hdrsz + payloadsz]

        # load flags and possibly decompress payload
        offset += struct.calcsize(_USWID_HEADER_FMT)
        if hdrver >= 3:
            (
                flags,
                compression,
            ) = struct.unpack_from("<BB", blob, len(USWID_HEADER_MAGIC) + offset)
            if flags & uSwidHeaderFlags.COMPRESSED:
                if compression in uSwidPayloadCompression:
                    self.compression = compression
                else:
                    raise NotSupportedError(
                        f"file has unknown compression type {compression}"
                    )
            else:
                self.compression = uSwidPayloadCompression.NONE
        elif hdrver == 2:
            (flags,) = struct.unpack_from("<B", blob, len(USWID_HEADER_MAGIC) + offset)
            if flags & uSwidHeaderFlags.COMPRESSED:
                self.compression = uSwidPayloadCompression.ZLIB
            else:
                self.compression = uSwidPayloadCompression.NONE

        # decompress
        if self.compression == uSwidPayloadCompression.ZLIB:
            payload = zlib.decompress(payload)
        elif self.compression == uSwidPayloadCompression.LZMA:
            payload = lzma.decompress(payload)

        # read each CBOR blob
        payload_offset = 0
        while payload_offset < len(payload):
            component = uSwidComponent()
            payload_offset += uSwidFormatCoswid()._load_component(
                component, payload, payload_offset
            )
            container.append(component)

        # consumed
        return hdrsz + payloadsz
