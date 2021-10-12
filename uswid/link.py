#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=too-few-public-methods

from enum import IntEnum

from typing import Dict, Any, Optional
import configparser

from lxml import etree as ET

from .errors import NotSupportedError
from .enums import uSwidGlobalMap


class uSwidRel(IntEnum):
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
        rel: Optional[uSwidRel] = None,
    ):

        self.href: Optional[str] = href
        self.rel: Optional[uSwidRel] = rel

    def _import_xml(self, node: ET.SubElement) -> None:
        """imports a uSwidLink XML blob"""

        LINK_MAP = {
            "ancestor": uSwidRel.ANCESTOR,
            "component": uSwidRel.COMPONENT,
            "feature": uSwidRel.FEATURE,
            "installationmedia": uSwidRel.INSTALLATIONMEDIA,
            "packageinstaller": uSwidRel.PACKAGEINSTALLER,
            "parent": uSwidRel.PARENT,
            "patches": uSwidRel.PATCHES,
            "requires": uSwidRel.REQUIRES,
            "seeAlso": uSwidRel.SEE_ALSO,
            "supersedes": uSwidRel.SUPERSEDES,
            "supplemental": uSwidRel.SUPPLEMENTAL,
        }
        self.href = node.get("href")
        rel_data = node.get("rel", None)
        if rel_data:
            try:
                self.rel = LINK_MAP[rel_data]
            except KeyError as e:
                raise NotSupportedError(
                    "{} not supported from {}".format(rel_data, ",".join(LINK_MAP))
                ) from e

    def _import_data(self, data: Dict[uSwidGlobalMap, Any]) -> None:
        """imports a uSwidLink data section"""

        self.href = data.get(uSwidGlobalMap.HREF)
        self.rel = data.get(uSwidGlobalMap.REL)

    def _import_ini(self, data: configparser.SectionProxy) -> None:
        """imports a uSwidLink INI section"""

        LINK_MAP = {
            "ancestor": uSwidRel.ANCESTOR,
            "component": uSwidRel.COMPONENT,
            "feature": uSwidRel.FEATURE,
            "installation-media": uSwidRel.INSTALLATIONMEDIA,
            "package-installer": uSwidRel.PACKAGEINSTALLER,
            "parent": uSwidRel.PARENT,
            "patches": uSwidRel.PATCHES,
            "requires": uSwidRel.REQUIRES,
            "see-also": uSwidRel.SEE_ALSO,
            "supersedes": uSwidRel.SUPERSEDES,
            "supplemental": uSwidRel.SUPPLEMENTAL,
        }
        for key, value in data.items():
            if key == "href":
                self.href = value
            elif key == "rel":
                try:
                    self.rel = LINK_MAP[value]
                except KeyError as e:
                    raise NotSupportedError(
                        "{} not supported from {}".format(value, ",".join(LINK_MAP))
                    ) from e
            else:
                print("unknown key {} found in ini file!".format(key))
        if not self.href:
            raise NotSupportedError("all entities MUST have a href")

    def _export_bytes(self) -> Dict[uSwidGlobalMap, Any]:
        """exports a uSwidLink CBOR blob"""

        data: Dict[uSwidGlobalMap, Any] = {}
        data[uSwidGlobalMap.HREF] = self.href
        if self.rel:
            data[uSwidGlobalMap.REL] = self.rel
        return data

    def __repr__(self) -> str:
        return "uSwidLink({},{})".format(self.href, str(self.rel))
