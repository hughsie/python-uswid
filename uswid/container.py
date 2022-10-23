#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2022 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=too-few-public-methods,protected-access

from typing import List, Optional
import struct
import zlib
import json

from .identity import uSwidIdentity
from .errors import NotSupportedError

from .enums import USWID_HEADER_MAGIC, USWID_HEADER_FLAG_COMPRESSED


class uSwidContainer:
    """represents a uSWID container"""

    def __init__(self, blob: Optional[bytes] = None):

        self._identities: List[uSwidIdentity] = []
        if blob:
            self.import_bytes(blob)

    def __iter__(self):
        for identity in self._identities:
            yield identity

    def append(self, identity: uSwidIdentity) -> None:

        self._identities.append(identity)

    def merge(self, identity: uSwidIdentity) -> Optional[uSwidIdentity]:
        """merges one identity into another, returning False if the tag_id does not exist"""

        # just patching the default (and only) identity
        if not identity.tag_id:
            identity_default = self.get_default()
            if not identity_default:
                raise NotSupportedError(
                    "cannot merge file without a tag_id and no default identity"
                )
            identity_default.merge(identity)
            return identity_default

        # does this tag ID already exist?
        identity_old = self._get_by_id(identity.tag_id)
        if identity_old:
            identity_old.merge(identity)
            return identity_old

        # new to us
        self.append(identity)
        return None

    def get_default(self) -> Optional[uSwidIdentity]:
        """returns the existing identity, or creates one if none already exist"""

        if len(self._identities) > 1:
            return None
        if not self._identities:
            self._identities.append(uSwidIdentity())
        return self._identities[0]

    def _get_by_id(self, tag_id: str) -> Optional[uSwidIdentity]:
        """returns the identity that matches the tag ID"""

        for identity in self._identities:
            if identity.tag_id == tag_id:
                return identity
        return None

    def _import_bytes(self, blob: bytes, offset: int) -> int:

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

        # read each CBOR blob
        payload_offset = 0
        while payload_offset < len(payload):
            identity = uSwidIdentity()
            payload_offset += identity.import_bytes(payload, payload_offset)
            self.append(identity)

        # consumed
        return hdrsz + payloadsz

    def import_bytes(self, blob: bytes) -> None:
        """imports a uSWID container blob"""

        # find magic GUIDs marking external uSWID sections
        offset: int = 0
        cnt: int = 0
        while 1:
            offset = blob.find(USWID_HEADER_MAGIC, offset)
            if offset == -1:
                break
            print("Found USWID header at offset: {}".format(offset))
            offset += self._import_bytes(blob, offset)
            cnt += 1
        if cnt == 0:
            raise NotSupportedError("file does not have expected magic GUID")

    def export_bytes(self, compress: bool) -> bytes:
        """exports a uSWID container blob"""

        blob: bytes = b""
        for identity in self._identities:
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

    def import_json(self, blob: bytes) -> None:
        """imports a JSON container blob"""

        try:
            identities = json.loads(blob)
        except json.decoder.JSONDecodeError as e:
            raise NotSupportedError("invalid JSON: {}".format(e)) from e
        for identity_json in identities:
            identity = uSwidIdentity()
            identity._import_json(identity_json)
            self.merge(identity)

    def export_json(self) -> bytes:
        """exports a JSON container blob"""

        root = []
        for identity in self._identities:
            root.append(identity._export_json())
        return json.dumps(root, indent=2).encode("utf-8")

    def __repr__(self) -> str:
        return "uSwidContainer({})".format(self._identities)
