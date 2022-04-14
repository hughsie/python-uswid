#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2022 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=too-few-public-methods

from typing import List, Optional
import struct
import zlib

from .identity import uSwidIdentity
from .errors import NotSupportedError

from .enums import USWID_HEADER_MAGIC, USWID_HEADER_FLAG_COMPRESSED


class uSwidContainer:
    """represents a uSWID container"""

    def __init__(self):

        self.identities: List[uSwidIdentity] = []

    def append(self, identity: uSwidIdentity) -> None:

        self.identities.append(identity)

    def get_default(self) -> Optional[uSwidIdentity]:
        """returns the existing identity, or creates one if none already exist"""

        if len(self.identities) > 1:
            return None
        if not self.identities:
            self.identities.append(uSwidIdentity())
        return self.identities[0]

    def import_bytes(self, blob: bytes) -> None:
        """imports a uSWID container blob"""

        # find and discard magic GUID
        offset = blob.find(USWID_HEADER_MAGIC)
        if offset == -1:
            raise NotSupportedError("file does not have expected magic GUID")
        print("Found USWID header at offset: {}".format(offset))

        # this is the most basic of headers
        (hdrver, hdrsz, payloadsz) = struct.unpack(
            "<BHI", blob[offset + 16 : offset + 23]
        )
        if hdrver == 0:
            raise NotSupportedError("file does not have expected header version")
        payload = blob[offset + hdrsz : offset + hdrsz + payloadsz]

        # load flags and possibly decompress payload
        if hdrver >= 2:
            (flags,) = struct.unpack("<B", blob[offset + 23 : offset + 24])
            if flags | USWID_HEADER_FLAG_COMPRESSED:
                payload = zlib.decompress(payload)

        # read each CBOR blob
        offset = 0
        while offset < len(payload):
            identity = uSwidIdentity()
            offset += identity.import_bytes(payload, offset)
            self.append(identity)

    def export_bytes(self, compress: bool) -> bytes:
        """exports a uSWID container blob"""

        blob: bytes = b""
        for identity in self.identities:
            blob += identity.export_bytes()

        # v2 header specifies the flags
        if compress:
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

    def __repr__(self) -> str:
        return "uSwidContainer({})".format(self.identities)
