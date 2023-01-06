#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=too-few-public-methods

from enum import IntEnum

from typing import Optional


class uSwidLinkRel(IntEnum):
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
    """represents a SWID link"""

    def __init__(
        self,
        href: Optional[str] = None,
        rel: Optional[str] = None,
    ):

        self.href: Optional[str] = href
        self._rel: Optional[str] = rel

    @property
    def rel(self) -> Optional[str]:
        if not self._rel:
            if self.href and self.href.startswith("swid"):
                return "component"
            if self.href and self.href.startswith("https://spdx.org/"):
                return "license"
        return self._rel

    @rel.setter
    def rel(self, rel: Optional[str]) -> None:
        self._rel = rel

    @property
    def href_for_display(self) -> Optional[str]:
        if not self.href:
            return None
        return self.href.split("/")[-1].replace(".html", "")

    def __repr__(self) -> str:
        return "uSwidLink({},{})".format(self.href, str(self.rel))
