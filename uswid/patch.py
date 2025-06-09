#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# (c) Copyright 2025 HP Development Company, L.P.
# Copyright (C) 2025 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# pylint: disable=too-few-public-methods,redefined-builtin

from typing import List, Optional
from enum import Enum


class uSwidPatchType(str, Enum):
    """Represents an enumerated type of patch"""

    UNKNOWN = "unknown"
    BACKPORT = "backport"
    CHERRY_PICK = "cherry-pick"
    SECURITY = "security"
    # Add more types as needed

    def __str__(self):
        return self.name.lower().replace("_", "-")

    @staticmethod
    def from_str(value: str) -> "uSwidPatchType":
        """Creates a uSwidPatchType from a string identifier"""
        return uSwidPatchType[value.upper().replace("-", "_")]


class uSwidPatch:
    """Represents a patch"""

    def __init__(
        self,
        type: uSwidPatchType = uSwidPatchType.UNKNOWN,
        url: Optional[str] = None,
        description: Optional[str] = None,
        references: Optional[List[str]] = None,
    ):
        """
        Initializes uSwidPatch

        Args:
          type: Type of patch, e.g. uSwidPatchType.BACKPORT, uSwidPatchType.CHERRY_PICK, etc.
          url: URL to the patch/diff as a uSwidPurl object
          description: Description of the patch
          references: List of references to other patches
        """
        if type is not None and not isinstance(type, uSwidPatchType):
            raise ValueError(
                f"Invalid type: {type}. Must be one of {[e.value for e in uSwidPatchType]}"
            )

        self.type: uSwidPatchType = type
        self.url: Optional[str] = url
        self.description: Optional[str] = description or None
        self.references: List[str] = references or []

    def __repr__(self) -> str:
        return f'uSwidPatch(type="{self.type}", ' f'description="{self.description}")'
