#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2023 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=too-few-public-methods

from enum import IntEnum

from typing import Optional


class uSwidHashAlg(IntEnum):
    UNKNOWN = 0
    SHA256 = 1
    SHA384 = 7
    SHA512 = 8

    @classmethod
    def from_string(cls, alg_id: str) -> "uSwidHashAlg":
        return cls(
            {
                "SHA256": uSwidHashAlg.SHA256,
                "SHA384": uSwidHashAlg.SHA384,
                "SHA512": uSwidHashAlg.SHA512,
            }[alg_id]
        )


class uSwidHash:
    """represents a SWID link"""

    def __init__(
        self,
        alg_id: Optional[uSwidHashAlg] = None,
        value: Optional[str] = None,
    ):
        self.alg_id: Optional[uSwidHashAlg] = alg_id
        self.value: Optional[str] = value

    @property
    def value(self) -> Optional[str]:
        return self._value

    @value.setter
    def value(self, value: Optional[str]) -> None:
        if self.alg_id is None and value:
            if len(value) == 64:
                self.alg_id = uSwidHashAlg.SHA256
            elif len(value) == 96:
                self.alg_id = uSwidHashAlg.SHA384
            elif len(value) == 128:
                self.alg_id = uSwidHashAlg.SHA512
        self._value = value

    def __repr__(self) -> str:
        alg_id_str = self.alg_id.name if self.alg_id else uSwidHashAlg.UNKNOWN.name
        return f'uSwidHash(alg_id={alg_id_str},value="{self.value}")'
