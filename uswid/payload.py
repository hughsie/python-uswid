#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2023 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=too-few-public-methods

from typing import Optional, List

from .hash import uSwidHash


class uSwidPayload:
    """represents a SWID Payload"""

    def __init__(
        self,
        name: Optional[str] = None,
        size: Optional[int] = None,
    ):
        self.name: Optional[str] = name
        self.size: Optional[int] = size
        self.hashes: List[uSwidHash] = []

    def add_hash(self, ihash: uSwidHash) -> None:
        self.hashes.append(ihash)

    def __repr__(self) -> str:
        tmp = f'uSwidPayload(name="{self.name}",size={self.size})'
        if self.hashes:
            tmp += "\n{}".format(
                "\n".join([f" - {str(e)}" for e in self.hashes]),
            )
        return tmp
