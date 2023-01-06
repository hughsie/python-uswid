#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=too-few-public-methods,protected-access

import struct
import zlib

from .enums import USWID_HEADER_MAGIC, USWID_HEADER_FLAG_COMPRESSED
from .container import uSwidContainer
from .format import uSwidFormatBase
from .errors import NotSupportedError
from .identity import uSwidIdentity
from .format_coswid import uSwidFormatCoswid


class uSwidFormatUswid(uSwidFormatBase):
    """uSWID file"""

    def __init__(self, compress: bool = True) -> None:

        uSwidFormatBase.__init__(self)
        self.compress: bool = compress

    def load(self, blob: bytes) -> uSwidContainer:

        container = uSwidContainer()

        # find magic GUIDs marking external uSWID sections
        offset: int = 0
        cnt: int = 0
        while 1:
            offset = blob.find(USWID_HEADER_MAGIC, offset)
            if offset == -1:
                break
            print("Found USWID header at offset: {}".format(offset))
            offset += self._load_bytes(container, blob, offset)
            cnt += 1
        if cnt == 0:
            raise NotSupportedError("file does not have expected magic GUID")
        return container

    def save(self, container: uSwidContainer) -> bytes:

        blob: bytes = b""
        for identity in container:
            blob += uSwidFormatCoswid()._save_identity(identity)

        # v2 header specifies the flags
        if self.compress:
            payload = zlib.compress(blob)
            return (
                struct.pack(
                    "<16sBHIB",
                    USWID_HEADER_MAGIC,
                    2,  # version
                    24,  # hdrsz
                    len(payload),
                    USWID_HEADER_FLAG_COMPRESSED,  # flags
                )
                + payload
            )

        # old format
        return (
            struct.pack(
                "<16sBHI",
                USWID_HEADER_MAGIC,
                1,  # version
                23,  # hdrsz
                len(blob),
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
        if hdrver >= 2:
            (flags,) = struct.unpack_from("<B", blob, len(USWID_HEADER_MAGIC) + offset)
            if flags & USWID_HEADER_FLAG_COMPRESSED:
                payload = zlib.decompress(payload)
                self.compress = True
            else:
                self.compress = False

        # read each CBOR blob
        payload_offset = 0
        while payload_offset < len(payload):
            identity = uSwidIdentity()
            payload_offset += uSwidFormatCoswid()._load_identity(
                identity, payload, payload_offset
            )
            container.append(identity)

        # consumed
        return hdrsz + payloadsz
