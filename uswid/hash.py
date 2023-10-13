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
    """Represents an enumerated type of hash"""

    UNKNOWN = 0
    SHA256 = 1
    SHA384 = 7
    SHA512 = 8

    @classmethod
    def from_string(cls, alg_id: str) -> "uSwidHashAlg":
        """Creates a uSwidHashAlg from a string identifier"""
        return cls(
            {
                "SHA256": uSwidHashAlg.SHA256,
                "SHA384": uSwidHashAlg.SHA384,
                "SHA512": uSwidHashAlg.SHA512,
            }[alg_id]
        )


class uSwidHash:
    """Represents a SWID link"""

    def __init__(
        self,
        alg_id: Optional[uSwidHashAlg] = None,
        value: Optional[str] = None,
    ):
        """Initializes uSwidHash"""
        self.alg_id: Optional[uSwidHashAlg] = alg_id
        """Algorigth ID, e.g. ``uSwidHashAlg.SHA256``"""
        self.value: Optional[str] = value
        """Checksum value"""

    @property
    def alg_id_for_display(self) -> Optional[str]:
        """Returns the value"""
        if not self.alg_id:
            return None
        return {
            uSwidHashAlg.SHA256: "SHA-256",
            uSwidHashAlg.SHA384: "SHA-384",
            uSwidHashAlg.SHA512: "SHA-512",
        }.get(self.alg_id)

    @property
    def value(self) -> Optional[str]:
        """Returns the value"""
        return self._value

    @value.setter
    def value(self, value: Optional[str]) -> None:
        """Sets the value, guessing the alg_id from the length if unset"""
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
