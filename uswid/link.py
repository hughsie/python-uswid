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


class uSwidLinkRel(IntEnum):
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
        self.rel: Optional[str] = rel

    def _import_xml(self, node: ET.SubElement) -> None:
        """imports a uSwidLink XML blob"""

        LINK_MAP: Dict[str, str] = {
            "seeAlso": "see-also",
        }
        self.href = node.get("href")
        rel_data = node.get("rel")
        self.rel = LINK_MAP.get(rel_data, rel_data)

    def _import_data(self, data: Dict[uSwidGlobalMap, Any]) -> None:
        """imports a uSwidLink data section"""

        # always a string
        self.href = data.get(uSwidGlobalMap.HREF)

        # rel can either be a uSwidLinkRel or a string
        rel_data = data.get(uSwidGlobalMap.REL)
        if isinstance(rel_data, str):
            self.rel = rel_data
        if isinstance(rel_data, uSwidLinkRel):
            LINK_MAP: Dict[uSwidLinkRel, str] = {
                uSwidLinkRel.ANCESTOR: "ancestor",
                uSwidLinkRel.COMPONENT: "component",
                uSwidLinkRel.FEATURE: "feature",
                uSwidLinkRel.INSTALLATIONMEDIA: "installation-media",
                uSwidLinkRel.PACKAGEINSTALLER: "package-installer",
                uSwidLinkRel.PARENT: "parent",
                uSwidLinkRel.PATCHES: "patches",
                uSwidLinkRel.REQUIRES: "requires",
                uSwidLinkRel.SEE_ALSO: "see-also",
                uSwidLinkRel.SUPERSEDES: "supersedes",
                uSwidLinkRel.SUPPLEMENTAL: "supplemental",
            }
            try:
                self.rel = LINK_MAP[rel_data]
            except KeyError as e:
                raise NotSupportedError(
                    "{} not supported from {}".format(
                        rel_data, ",".join(LINK_MAP.values())
                    )
                ) from e

    def _import_ini(self, data: configparser.SectionProxy) -> None:
        """imports a uSwidLink INI section"""

        for key, value in data.items():
            if key == "href":
                self.href = value
            elif key == "rel":
                self.rel = value
            else:
                print("unknown key {} found in ini file!".format(key))
        if not self.href:
            raise NotSupportedError("all entities MUST have a href")

    def _export_ini(self) -> Dict[str, Any]:
        """exports a uSwidLink INI section"""

        data: Dict[str, Any] = {}
        if self.rel:
            data["rel"] = self.rel
        if self.href:
            data["href"] = self.href
        return data

    def _export_xml(self, root: ET.Element) -> None:
        """exports a uSwidLink XML blob"""

        node = ET.SubElement(root, "Link")
        if self.href:
            node.set("href", self.href)
        if self.rel:
            node.set("rel", self.rel)

    def _export_bytes(self) -> Dict[uSwidGlobalMap, Any]:
        """exports a uSwidLink CBOR blob"""

        data: Dict[uSwidGlobalMap, Any] = {}
        data[uSwidGlobalMap.HREF] = self.href

        # map back into a uSwidLinkRel if possible
        if self.rel:
            LINK_MAP: Dict[str, uSwidLinkRel] = {
                "ancestor": uSwidLinkRel.ANCESTOR,
                "component": uSwidLinkRel.COMPONENT,
                "feature": uSwidLinkRel.FEATURE,
                "installation-media": uSwidLinkRel.INSTALLATIONMEDIA,
                "package-installer": uSwidLinkRel.PACKAGEINSTALLER,
                "parent": uSwidLinkRel.PARENT,
                "patches": uSwidLinkRel.PATCHES,
                "requires": uSwidLinkRel.REQUIRES,
                "see-also": uSwidLinkRel.SEE_ALSO,
                "supersedes": uSwidLinkRel.SUPERSEDES,
                "supplemental": uSwidLinkRel.SUPPLEMENTAL,
            }
            data[uSwidGlobalMap.REL] = LINK_MAP.get(self.rel, self.rel)
        return data

    def __repr__(self) -> str:
        return "uSwidLink({},{})".format(self.href, str(self.rel))
