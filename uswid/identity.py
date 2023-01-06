#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=protected-access,too-many-boolean-expressions

from typing import Dict, Optional, List

from .errors import NotSupportedError
from .enums import uSwidVersionScheme
from .entity import uSwidEntity
from .link import uSwidLink

_VERSION_SCHEME_TO_STRING = {
    uSwidVersionScheme.MULTIPARTNUMERIC: "multipartnumeric",
    uSwidVersionScheme.MULTIPARTNUMERIC_SUFFIX: "multipartnumeric+suffix",
    uSwidVersionScheme.ALPHANUMERIC: "alphanumeric",
    uSwidVersionScheme.DECIMAL: "decimal",
    uSwidVersionScheme.SEMVER: "semver",
}
_VERSION_SCHEME_FROM_STRING = {
    "multipartnumeric": uSwidVersionScheme.MULTIPARTNUMERIC,
    "multipartnumeric+suffix": uSwidVersionScheme.MULTIPARTNUMERIC_SUFFIX,
    "alphanumeric": uSwidVersionScheme.ALPHANUMERIC,
    "decimal": uSwidVersionScheme.DECIMAL,
    "semver": uSwidVersionScheme.SEMVER,
}


class uSwidIdentity:
    """represents a SWID identity"""

    def __init__(
        self,
        tag_id: Optional[str] = None,
        tag_version: int = 0,
        software_name: Optional[str] = None,
        software_version: Optional[str] = None,
    ):

        self._auto_increment_tag_version = False
        self.tag_id: Optional[str] = tag_id
        self.tag_version: int = tag_version
        self.software_name: Optional[str] = software_name
        self.software_version: Optional[str] = software_version
        self.version_scheme: Optional[uSwidVersionScheme] = None
        self.summary: Optional[str] = None
        self.product: Optional[str] = None
        self.colloquial_version: Optional[str] = None
        self.revision: Optional[str] = None
        self.edition: Optional[str] = None
        self.persistent_id: Optional[str] = None
        self.lang: Optional[str] = "en-US"
        self.generator = "uSWID"
        self._entities: Dict[str, uSwidEntity] = {}
        self._links: Dict[str, uSwidLink] = {}

    def merge(self, identity_new: "uSwidIdentity") -> None:
        """adds new things from the new identity into the current one"""
        if identity_new.tag_version:
            self.tag_version = identity_new.tag_version
        if identity_new.software_name:
            self.software_name = identity_new.software_name
        if identity_new.software_version:
            self.software_version = identity_new.software_version
        if identity_new.version_scheme:
            self.version_scheme = identity_new.version_scheme
        if identity_new.summary:
            self.summary = identity_new.summary
        if identity_new.product:
            self.product = identity_new.product
        if identity_new.colloquial_version:
            self.colloquial_version = identity_new.colloquial_version
        if identity_new.revision:
            self.revision = identity_new.revision
        if identity_new.edition:
            self.edition = identity_new.edition
        if identity_new.persistent_id:
            self.persistent_id = identity_new.persistent_id
        if identity_new.lang:
            self.lang = identity_new.lang
        for entity in identity_new.entities:
            self.add_entity(entity)
        for link in identity_new.links:
            self.add_link(link)

    def add_entity(self, entity: uSwidEntity) -> None:
        """only adds the latest entity"""
        if not entity.name:
            raise NotSupportedError("the entity name MUST be provided")
        self._entities[entity.name] = entity

    def add_link(self, link: uSwidLink) -> None:
        """only adds the deduped link"""
        if not link.href:
            raise NotSupportedError("the link href MUST be provided")
        self._links[link.href] = link

    @property
    def links(self) -> List[uSwidLink]:
        """returns all the added links"""
        return list(self._links.values())

    @property
    def entities(self) -> List[uSwidEntity]:
        """returns all the added entities"""
        return list(self._entities.values())

    def __repr__(self) -> str:
        tmp = "uSwidIdentity({},{},{},{})".format(
            self.tag_id, self.tag_version, self.software_name, self.software_version
        )
        if self._links or self._entities:
            tmp += ":"
        if self._links:
            tmp += "\n{}".format(
                "\n".join([str(e) for e in self._links.values()]),
            )
        if self._entities:
            tmp += "\n{}".format(
                "\n".join([str(e) for e in self._entities.values()]),
            )
        return tmp
