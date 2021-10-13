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

        # rel can either be a uSwidRel or a string
        rel_data = data.get(uSwidGlobalMap.REL)
        if isinstance(rel_data, str):
            self.rel = rel_data
        if isinstance(rel_data, uSwidRel):
            LINK_MAP: Dict[uSwidRel, str] = {
                uSwidRel.ANCESTOR: "ancestor",
                uSwidRel.COMPONENT: "component",
                uSwidRel.FEATURE: "feature",
                uSwidRel.INSTALLATIONMEDIA: "installation-media",
                uSwidRel.PACKAGEINSTALLER: "package-installer",
                uSwidRel.PARENT: "parent",
                uSwidRel.PATCHES: "patches",
                uSwidRel.REQUIRES: "requires",
                uSwidRel.SEE_ALSO: "see-also",
                uSwidRel.SUPERSEDES: "supersedes",
                uSwidRel.SUPPLEMENTAL: "supplemental",
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

    def _export_bytes(self) -> Dict[uSwidGlobalMap, Any]:
        """exports a uSwidLink CBOR blob"""

        data: Dict[uSwidGlobalMap, Any] = {}
        data[uSwidGlobalMap.HREF] = self.href

        # map back into a uSwidRel if possible
        if self.rel:
            LINK_MAP: Dict[str, uSwidRel] = {
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
            data[uSwidGlobalMap.REL] = LINK_MAP.get(self.rel, self.rel)
        return data

    def __repr__(self) -> str:
        return "uSwidLink({},{})".format(self.href, str(self.rel))
