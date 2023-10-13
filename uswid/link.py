#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=too-few-public-methods

from enum import IntEnum
import uuid

from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .identity import uSwidIdentity


class uSwidLinkRel(IntEnum):
    """Represents an enumerated types of link"""

    LICENSE = -2
    COMPILER = -1
    ANCESTOR = 1
    COMPONENT = 2
    FEATURE = 3
    INSTALLATIONMEDIA = 4
    PACKAGEINSTALLER = 5
    PARENT = 6
    PATCHES = 7
    REQUIRES = 8
    SEE_ALSO = 9
    SUPERSEDES = 10
    SUPPLEMENTAL = 11


class uSwidLink:
    """Represents a SWID link"""

    def __init__(
        self,
        href: Optional[str] = None,
        rel: Optional[str] = None,
    ):
        """Initializes uSwidLink"""
        self._href: Optional[str] = href
        self._rel: Optional[str] = rel
        self.identity: Optional[uSwidIdentity] = None
        """Identity, if the SWID reference in internally resolvable"""

    @property
    def rel(self) -> Optional[str]:
        """Returns rel, guessing from the ``href`` if not provided"""
        if not self._rel:
            if self.href and self.href.startswith("swid"):
                return "component"
            if self.href and self.href.startswith("https://spdx.org/"):
                return "license"
        return self._rel

    @rel.setter
    def rel(self, rel: Optional[str]) -> None:
        """Sets rel"""
        self._rel = rel

    @property
    def href(self) -> Optional[str]:
        """Returns href"""
        return self._href

    @href.setter
    def href(self, href: Optional[str]) -> None:
        """Sets href, converting it to a UUID as required"""
        if href and href.startswith("swid:"):
            maybe_uuid: str = href.split(":")[1]
            try:
                _ = uuid.UUID(maybe_uuid)
            except ValueError:
                href = f"swid:{str(uuid.uuid5(uuid.NAMESPACE_DNS, maybe_uuid))}"
        self._href = href

    @property
    def href_for_display(self) -> Optional[str]:
        """Returns href as an HTML URI"""
        if not self.href:
            return None
        return self.href.split("/")[-1].replace(".html", "")

    def __repr__(self) -> str:
        return f'uSwidLink(rel="{self.rel or "none"}",href="{self.href}")'
