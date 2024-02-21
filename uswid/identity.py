#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# pylint: disable=protected-access,too-many-boolean-expressions

from typing import Dict, Optional, List
import uuid
import fnmatch

from .errors import NotSupportedError
from .enums import uSwidVersionScheme
from .entity import uSwidEntity, uSwidEntityRole
from .link import uSwidLink, uSwidLinkRel
from .payload import uSwidPayload
from .evidence import uSwidEvidence
from .problem import uSwidProblem

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


def _fix_appstream_id(appstream_id: str) -> str:

    if not appstream_id:
        return None

    # remove protocol prefix
    if appstream_id.startswith("http://") or appstream_id.startswith("https://"):
        appstream_id = appstream_id.split("/")[2]

        # remove www
        if appstream_id.startswith("www."):
            appstream_id = appstream_id[4:]

        # make reverse DNS-style
        dns_prefix: str = appstream_id.split(".")[0]
        if dns_prefix in ["com", "org", "tw", "uk", "eu"]:
            appstream_id = ".".join(reversed(appstream_id.split(".")))

    return appstream_id


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

    def problems(self) -> List[uSwidProblem]:
        """Checks the identity for common problems"""

        problems: List[uSwidProblem] = []

        if self._tag_id:
            if fnmatch.fnmatch(self.tag_id, "????????_????_????_????_????????????"):
                problems += [
                    uSwidProblem(
                        "identity",
                        f"Tag GUID {self.tag_id} should use dashes",
                        since="0.4.7",
                    )
                ]
        if not self.software_name:
            problems += [uSwidProblem("identity", "No software name", since="0.4.7")]
        elif self.software_name.find("REDACTED") != -1:
            problems += [
                uSwidProblem("identity", "Redacted software name", since="0.4.8")
            ]
        if not self.software_version:
            problems += [uSwidProblem("identity", "No software version", since="0.4.7")]
        elif self.software_version.find("REDACTED") != -1:
            problems += [
                uSwidProblem("identity", "Redacted software version", since="0.4.8")
            ]
        if not self.version_scheme:
            problems += [uSwidProblem("identity", "No version scheme", since="0.4.7")]

        if self.summary and self.summary.find("REDACTED") != -1:
            problems += [uSwidProblem("identity", "Redacted summary", since="0.4.8")]
        if self.product and self.product.find("REDACTED") != -1:
            problems += [uSwidProblem("identity", "Redacted product", since="0.4.8")]
        if self.colloquial_version and self.colloquial_version.find("REDACTED") != -1:
            problems += [
                uSwidProblem("identity", "Redacted colloquial version", since="0.4.8")
            ]
        if self.revision and self.revision.find("REDACTED") != -1:
            problems += [uSwidProblem("identity", "Redacted revision", since="0.4.8")]
        if self.edition and self.edition.find("REDACTED") != -1:
            problems += [uSwidProblem("identity", "Redacted edition", since="0.4.8")]
        if self.persistent_id and self.persistent_id.find("REDACTED") != -1:
            problems += [
                uSwidProblem("identity", "Redacted persistent id", since="0.4.8")
            ]
        if self.generator and self.generator.find("REDACTED") != -1:
            problems += [uSwidProblem("identity", "Redacted generator", since="0.4.8")]

        # should be reverse-DNS name
        if self.persistent_id and self.persistent_id != _fix_appstream_id(
            self.persistent_id
        ):
            problems += [
                uSwidProblem(
                    "identity",
                    "Invalid persistent_id, should be reverse-DNS "
                    f"name {_fix_appstream_id(self.persistent_id)}",
                    since="0.4.7",
                )
            ]

        # entity
        entity_by_role: Dict[uSwidEntityRole:uSwidEntity] = {}
        for entity in self.entities:
            for role in entity.roles:
                entity_by_role[role] = entity
            problems += entity.problems()
        if uSwidEntityRole.TAG_CREATOR not in entity_by_role:
            problems += [
                uSwidProblem("entity", "No entity marked as TagCreator", since="0.4.7")
            ]
        if uSwidEntityRole.SOFTWARE_CREATOR not in entity_by_role:
            problems += [
                uSwidProblem(
                    "entity", "No entity marked as SoftwareCreator", since="0.4.7"
                )
            ]

        # link
        link_by_rel: Dict[uSwidLinkRel:uSwidLink] = {}
        for link in self.links:
            link_by_rel[link.rel] = link
            problems += link.problems()
        if uSwidLinkRel.LICENSE not in link_by_rel:
            problems += [uSwidProblem("link", "Has no LICENSE", since="0.4.7")]
        if self.colloquial_version and uSwidLinkRel.COMPILER not in link_by_rel:
            problems += [uSwidProblem("link", "Has no COMPILER", since="0.4.7")]
        if uSwidLinkRel.COMPILER in link_by_rel and not self.colloquial_version:
            problems += [
                uSwidProblem(
                    "identity",
                    "Has no colloquial_version (source code file hash)",
                    since="0.4.7",
                )
            ]
        if uSwidLinkRel.COMPILER in link_by_rel and not self.colloquial_version:
            problems += [
                uSwidProblem(
                    "identity", "Has no edition (source code tree hash)", since="0.4.7"
                )
            ]

        # payload
        for payload in self.payloads:
            problems += payload.problems()

        # evidence
        for evidence in self.evidences:
            problems += evidence.problems()
        return problems

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
