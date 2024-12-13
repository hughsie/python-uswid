#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# pylint: disable=too-few-public-methods

from enum import IntEnum
import uuid

from typing import List, Optional, TYPE_CHECKING

from .problem import uSwidProblem, _is_redacted

if TYPE_CHECKING:
    from .component import uSwidComponent


class uSwidLinkRel(IntEnum):
    """Represents an enumerated types of link"""

    LICENSE = -2
    COMPILER = -1
    UNKNOWN = 0
    ANCESTOR = 1
    COMPONENT = 2
    FEATURE = 3
    INSTALLATION_MEDIA = 4
    PACKAGE_INSTALLER = 5
    PARENT = 6
    PATCHES = 7
    REQUIRES = 8
    SEE_ALSO = 9
    SUPERSEDES = 10
    SUPPLEMENTAL = 11

    def __str__(self):
        return self.name.replace("_", "-").lower()

    @classmethod
    def from_string(cls, value: str) -> "uSwidLinkRel":
        """Creates a uSwidLinkRel from a string identifier"""
        return cls(
            {
                "license": uSwidLinkRel.LICENSE,
                "compiler": uSwidLinkRel.COMPILER,
                "ancestor": uSwidLinkRel.ANCESTOR,
                "unknown": uSwidLinkRel.UNKNOWN,
                "component": uSwidLinkRel.COMPONENT,
                "feature": uSwidLinkRel.FEATURE,
                "installation-media": uSwidLinkRel.INSTALLATION_MEDIA,
                "package-installer": uSwidLinkRel.PACKAGE_INSTALLER,
                "parent": uSwidLinkRel.PARENT,
                "patches": uSwidLinkRel.PATCHES,
                "requires": uSwidLinkRel.REQUIRES,
                "see-also": uSwidLinkRel.SEE_ALSO,
                "supersedes": uSwidLinkRel.SUPERSEDES,
                "supplemental": uSwidLinkRel.SUPPLEMENTAL,
            }[value]
        )


class uSwidLinkUse(IntEnum):
    """Represents an enumerated uses of link"""

    OPTIONAL = 1
    REQUIRED = 2
    RECOMMENDED = 3

    def __str__(self):
        return self.name.lower()


class uSwidLink:
    """Represents a SWID link"""

    def __init__(
        self,
        href: Optional[str] = None,
        rel: Optional[uSwidLinkRel] = None,
        use: Optional[uSwidLinkUse] = None,
        spdx_id: Optional[str] = None,
    ):
        """Initializes uSwidLink"""
        self._href: Optional[str] = href
        self._rel: Optional[uSwidLinkRel] = rel
        self.use: Optional[uSwidLinkUse] = use
        self.component: Optional[uSwidComponent] = None
        """Component, if the SWID reference in internally resolvable"""

        # be helpful
        if spdx_id:
            self._href = f"https://spdx.org/licenses/{spdx_id}.html"

    @property
    def spdx_id(self) -> Optional[str]:
        """Returns the SPDX ID from the URL, if possible"""
        if self.href and self.href.startswith("https://spdx.org/licenses/"):
            return self.href[26:].replace(".html", "")
        return None

    @property
    def rel(self) -> Optional[uSwidLinkRel]:
        """Returns rel, guessing from the ``href`` if not provided"""
        if not self._rel:
            if self.href and self.href.startswith("swid"):
                return uSwidLinkRel.COMPONENT
            if self.href and self.href.startswith("https://spdx.org/"):
                return uSwidLinkRel.LICENSE
        return self._rel

    @rel.setter
    def rel(self, rel: Optional[uSwidLinkRel]) -> None:
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

    def problems(self) -> List[uSwidProblem]:
        """Checks the link for common problems"""

        problems: List[uSwidProblem] = []
        if not self.href:
            problems += [uSwidProblem("link", "No href", since="0.4.7")]
        elif _is_redacted(self.href):
            problems += [uSwidProblem("link", "Redacted href", since="0.4.8")]
        if not self.rel:
            problems += [uSwidProblem("link", "No rel", since="0.4.7")]
        return problems

    def __repr__(self) -> str:
        attrs: List[str] = []
        if self.rel:
            attrs.append(f'rel="{str(self.rel)}"')
        if self.use:
            attrs.append(f'use="{self.use}"')
        if self.href:
            attrs.append(f'href="{self.href}"')
        return f'uSwidLink({",".join(attrs)})'
