#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# (c) Copyright 2025 HP Development Company, L.P.
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#

from typing import List, Optional
from enum import Enum
from .purl import uSwidPurl

class uSwidPatchType(str, Enum):
    """Represents an enumerated type of patch"""
    BACKPORT = "backport"
    CHERRY_PICK = "cherry-pick"
    SECURITY = "security"
    # Add more types as needed

    def __str__(self):
        return self.name.lower()

    @staticmethod
    def from_str(value: str) -> "uSwidPatchType":
        """Creates a uSwidPatchType from a string identifier"""
        return uSwidPatchType[value.upper()]

class uSwidPatch:
    """Represents a patch"""

    def __init__(
        self,
        patch_type: uSwidPatchType,  # e.g. uSwidPatchType.BACKPORT
        patch_url: Optional[uSwidPurl] = None,    # URL to the patch/diff
        description: Optional[str] = None,  # Details of the patch
        additional_refs: Optional[List[uSwidPurl]] = None,  # List of external references
        references: Optional[str] = None,  # List of references to other patches or issues
    ):
        """
        Initializes uSwidPatch

        Args:
          patch_type: Type of patch, e.g. uSwidPatchType.BACKPORT, uSwidPatchType.CHERRY_PICK, etc.
          patch_url: URL to the patch/diff as a uSwidPurl object
          description: Description of the patch
          additional_refs: List of external references as uSwidPurl objects
          references: List of references to other patches or issues as uSwidPurl objects
        """
        if patch_type is not None and not isinstance(patch_type, uSwidPatchType):
            raise ValueError(f"Invalid patch_type: {patch_type}. Must be one of {[e.value for e in uSwidPatchType]}")

        self.patch_type: uSwidPatchType = patch_type
        self.patch_url: Optional[uSwidPurl] = patch_url
        self.description: Optional[str] = description or None
        self.additional_refs: Optional[uSwidPurl] = additional_refs or []
        self.references: Optional[str] = references or None

    def __repr__(self) -> str:
        return (
            f'uSwidPatch(patch_type="{self.patch_type}", '
            f'description="{self.description}")'
        )
