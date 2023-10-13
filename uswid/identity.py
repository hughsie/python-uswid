#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=protected-access,too-many-boolean-expressions

from typing import Dict, Optional, List
import uuid

from .errors import NotSupportedError
from .enums import uSwidVersionScheme
from .entity import uSwidEntity
from .link import uSwidLink
from .payload import uSwidPayload
from .evidence import uSwidEvidence

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
    """Represents a SWID identity"""

    def __init__(
        self,
        tag_id: Optional[str] = None,
        tag_version: int = 0,
        software_name: Optional[str] = None,
        software_version: Optional[str] = None,
        generator: Optional[str] = "uSWID",
    ):
        """Initializes uSwidIdentity"""
        self._auto_increment_tag_version = False
        self._tag_id: Optional[str] = None
        if tag_id:
            self.tag_id = tag_id
        self.tag_version: int = tag_version
        """Tag version"""
        self._software_name: Optional[str] = software_name
        self.software_version: Optional[str] = software_version
        """Software version"""
        self.version_scheme: Optional[uSwidVersionScheme] = None
        """Version scheme"""
        self.summary: Optional[str] = None
        """One line summary"""
        self.product: Optional[str] = None
        """Product"""
        self.colloquial_version: Optional[str] = None
        """Colloquial version, usually the source hash"""
        self.revision: Optional[str] = None
        """Revision"""
        self.edition: Optional[str] = None
        """Edition, usually the tree hash"""
        self.persistent_id: Optional[str] = None
        """Persistent AppStream ID"""
        self.lang: Optional[str] = "en-US"
        """Language code"""
        self.generator = generator
        """Generator, normally ``uSWID``"""
        self.payloads: List[uSwidPayload] = []
        """List of payloads"""
        self.evidences: List[uSwidEvidence] = []
        """List of evidences"""
        self._entities: Dict[str, uSwidEntity] = {}
        self._links: Dict[str, uSwidLink] = {}

    @property
    def software_name(self) -> Optional[str]:
        """Returns the software name"""
        return self._software_name

    @software_name.setter
    def software_name(self, software_name: Optional[str]) -> None:
        """Sets the software name, setting the ``tag_id`` automatically if unset"""
        if not self.tag_id and software_name:
            self.tag_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, software_name))
        self._software_name = software_name

    @property
    def generator_href(self) -> Optional[str]:
        """Returns the generator URL, if known"""
        if not self.generator:
            return None
        return {
            "goswid": "https://github.com/9elements/goswid",
            "LVFS": "https://fwupd.org/",
            "uSWID": "https://github.com/hughsie/python-uswid",
        }.get(self.generator)

    @property
    def tag_id(self) -> Optional[str]:
        """Returns the tag ID"""
        return self._tag_id

    @tag_id.setter
    def tag_id(self, tag_id: Optional[str]) -> None:
        """Sets the tag ID, converting to a generated GUID if required if @tag_id starts with ``swid:``"""
        if tag_id and tag_id.startswith("swid:"):
            try:
                self._tag_id = str(uuid.UUID(tag_id[5:]))
            except ValueError:
                self._tag_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, tag_id[5:]))
        else:
            self._tag_id = tag_id

    def merge(self, identity_new: "uSwidIdentity") -> None:
        """Add new things from the new identity into the current one"""
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
        for payload in identity_new.payloads:
            self.add_payload(payload)
        for evidence in identity_new.evidences:
            self.add_evidence(evidence)

    def add_entity(self, entity: uSwidEntity) -> None:
        """Add the latest entity"""
        if not entity.name:
            raise NotSupportedError("the entity name MUST be provided")
        self._entities[entity.name] = entity

    def add_link(self, link: uSwidLink) -> None:
        """Add the deduplicated link"""
        if not link.href:
            raise NotSupportedError("the link href MUST be provided")
        self._links[link.href] = link

    def add_payload(self, payload: uSwidPayload) -> None:
        """Add the payload"""
        if not payload.hashes:
            raise NotSupportedError(
                f"the hash value MUST be provided for {str(payload)}"
            )
        self.payloads.append(payload)

    def add_evidence(self, evidence: uSwidEvidence) -> None:
        """Add the evidence"""
        self.evidences.append(evidence)

    @property
    def links(self) -> List[uSwidLink]:
        """Returns all the added links"""
        return list(self._links.values())

    @property
    def entities(self) -> List[uSwidEntity]:
        """Returns all the added entities"""
        return list(self._entities.values())

    def __repr__(self) -> str:
        tmp = (
            f'uSwidIdentity(tag_id="{self.tag_id}",'
            + f'tag_version="{self.tag_version}",'
            + f'software_name="{self.software_name}",'
            + f'software_version="{self.software_version}")'
        )
        if self._links or self._entities:
            tmp += ":"
        if self._links:
            tmp += "\n{}".format(
                "\n".join([f" - {str(e)}" for e in self._links.values()]),
            )
        if self._entities:
            tmp += "\n{}".format(
                "\n".join([f" - {str(e)}" for e in self._entities.values()]),
            )
        if self.payloads:
            tmp += "\n{}".format(
                "\n".join([f" - {str(e)}" for e in self.payloads]),
            )
        if self.evidences:
            tmp += "\n{}".format(
                "\n".join([f" - {str(e)}" for e in self.evidences]),
            )
        return tmp
