#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2023 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=too-few-public-methods

from typing import Optional, List, Dict

import hashlib

from .hash import uSwidHash, uSwidHashAlg


class uSwidPayload:
    """Represents a SWID Payload"""

    def __init__(
        self,
        name: Optional[str] = None,
        size: Optional[int] = None,
    ):
        """Initializes uSwidPayload"""
        self.name: Optional[str] = name
        """File system name"""
        self.size: Optional[int] = size
        """Size in bytes"""
        self._hashes: Dict[uSwidHashAlg, uSwidHash] = {}

    def add_hash(self, ihash: uSwidHash) -> None:
        """Add a hash value, deduplicated by the algorithm ID"""
        self._hashes[ihash.alg_id or uSwidHashAlg.UNKNOWN] = ihash

    def remove_hash(self, alg_id: uSwidHashAlg) -> None:
        """Remove a hach value by the algorithm ID"""
        self._hashes.pop(alg_id)

    @property
    def hashes(self) -> List[uSwidHash]:
        """Returns all the added hashes"""
        return list(self._hashes.values())

    def ensure_from_filename(self, fn: str) -> None:
        """Set the size and SHA256 hash from a local filename"""
        with open(fn, "rb") as f:
            buf = f.read()
        self.size = len(buf)
        m = hashlib.sha256()
        m.update(buf)
        self.add_hash(uSwidHash(alg_id=uSwidHashAlg.SHA256, value=m.hexdigest()))

    def __repr__(self) -> str:
        tmp = f'uSwidPayload(name="{self.name}",size={self.size})'
        if self.hashes:
            tmp += "\n{}".format(
                "\n".join([f" - {str(e)}" for e in self.hashes]),
            )
        return tmp
