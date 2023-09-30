#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2023 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+

from typing import Optional

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .container import uSwidContainer


class uSwidFormatBase:
    def __init__(self) -> None:
        pass

    def load(self, blob: bytes, path: Optional[str] = None) -> "uSwidContainer":
        raise NotImplementedError

    def save(self, container: "uSwidContainer") -> bytes:
        raise NotImplementedError
