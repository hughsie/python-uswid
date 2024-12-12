#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2023 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=too-few-public-methods


from typing import Optional, List


class uSwidPurl:
    """Represents a Package URL"""

    def __init__(self, value: Optional[str] = None):
        """Initializes uSwidPurl"""
        self.scheme: Optional[str] = None
        """Scheme"""
        self.protocol: Optional[str] = "pkg"
        """Protocol (required)"""
        self.namespace: Optional[str] = None
        """Namespace (optional)"""
        self.name: Optional[str] = None
        """Name"""
        self.version: Optional[str] = None
        """Version (optional)"""
        self.qualifiers: Optional[str] = None
        """Qualifiers (optional)"""
        self.subpath: Optional[str] = None
        """Subpath (optional)"""

        if value:
            self.parse(value)

    def parse(self, value: str) -> None:
        """
        Parse from a text ID, for example:
         * ``pkg:scheme/namespace/name@version?qualifiers#subpath``
         * ``pkg:foo``
        """

        # [#subpath]
        tmp_split = value.rsplit("#", maxsplit=1)
        if len(tmp_split) > 1:
            self.subpath = tmp_split[1]
            value = tmp_split[0]

        # [?qualifiers]
        tmp_split = value.rsplit("?", maxsplit=1)
        if len(tmp_split) > 1:
            self.qualifiers = tmp_split[1]
            value = tmp_split[0]

        # [@version]
        tmp_split = value.rsplit("@", maxsplit=1)
        if len(tmp_split) > 1:
            self.version = tmp_split[1]
            value = tmp_split[0]

        # [scheme:]protocol/namespace/name
        tmp_split = value.rsplit(":", maxsplit=1)
        pnn = tmp_split[0].split("/", maxsplit=3)
        if len(tmp_split) > 1:
            pnn = tmp_split[1].split("/", maxsplit=3)
            self.scheme = tmp_split[0]
        else:
            pnn = tmp_split[0].split("/", maxsplit=3)
        if len(pnn) > 2:
            self.protocol = pnn[0]
            self.namespace = pnn[1]
            self.name = pnn[2]
        elif len(pnn) > 1:
            self.protocol = pnn[0]
            self.namespace = None
            self.name = pnn[1]
        else:
            self.protocol = None
            self.namespace = None
            self.name = pnn[0]

    def _export(self) -> str:

        tmp: str = ""
        if self.scheme:
            tmp = f"{self.scheme}:"
        pnn: List[str] = []
        if self.protocol:
            pnn.append(self.protocol)
        if self.namespace:
            pnn.append(self.namespace)
        if self.name:
            pnn.append(self.name)
        if pnn:
            tmp += "/".join(pnn)
        if self.version:
            tmp += f"@{self.version}"
        if self.qualifiers:
            tmp += f"?{self.qualifiers}"
        if self.subpath:
            tmp += f"#{self.subpath}"
        return tmp

    def __str__(self) -> str:

        return self._export()

    def __repr__(self) -> str:
        return f'uSwidPurl("{self._export()}")'
