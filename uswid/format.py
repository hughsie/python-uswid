#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2023 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent

from typing import Optional

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .container import uSwidContainer


class uSwidFormatBase:
    """Baseclass for formats to subclass.

    Available formats are:

    * ``uSwidFormatCoswid``
    * ``uSwidFormatCycloneDX`` (``.save`` only)
    * ``uSwidFormatGoswid``
    * ``uSwidFormatIni``
    * ``uSwidFormatPkgconfig`` (``.load`` only)
    * ``uSwidFormatSwid``
    * ``uSwidFormatUswid``
    """

    def __init__(self, name: str) -> None:
        """Initializes uSwidFormatBase"""
        self.name: str = name

    def load(self, blob: bytes, path: Optional[str] = None) -> "uSwidContainer":
        """Load a blob of data"""
        raise NotImplementedError

    def save(self, container: "uSwidContainer") -> bytes:
        """Save into a blob of data"""
        raise NotImplementedError
