#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=protected-access

import configparser
import io

from typing import Dict, Any, Optional

import cbor
from lxml import etree as ET

from .errors import NotSupportedError
from .enums import uSwidGlobalMap
from .entity import uSwidEntity, uSwidEntityRole
from .link import uSwidLink


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
        self.summary: Optional[str] = None
        self.product: Optional[str] = None
        self.colloquial_version: Optional[str] = None
        self.revision: Optional[str] = None
        self.edition: Optional[str] = None
        self.generator = "uSWID"
        self._entities: Dict[str, uSwidEntity] = {}
        self._links: Dict[str, uSwidLink] = {}

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

    def import_bytes(self, blob: bytes) -> None:
        """imports a uSwidIdentity CBOR blob"""

        if not blob:
            return
        data = cbor.load(io.BytesIO(blob))

        # identity
        self.tag_id = data.get(uSwidGlobalMap.TAG_ID, None)
        self.tag_version = data.get(uSwidGlobalMap.TAG_VERSION, 0)
        self.software_name = data.get(uSwidGlobalMap.SOFTWARE_NAME, None)
        self.software_version = data.get(uSwidGlobalMap.SOFTWARE_VERSION, None)

        # optional metadata
        for key, value in data.get(uSwidGlobalMap.SOFTWARE_META, {}).items():
            if key == uSwidGlobalMap.GENERATOR:
                self.generator = value
            elif key == uSwidGlobalMap.SUMMARY:
                self.summary = value
            elif key == uSwidGlobalMap.REVISION:
                self.revision = value
            elif key == uSwidGlobalMap.PRODUCT:
                self.product = value
            elif key == uSwidGlobalMap.EDITION:
                self.edition = value
            elif key == uSwidGlobalMap.COLLOQUIAL_VERSION:
                self.colloquial_version = value

        # entities
        for entity_data in data.get(uSwidGlobalMap.ENTITY, []):
            entity = uSwidEntity()
            entity._import_data(entity_data)
            # skip invalid entries
            if not entity.roles:
                continue
            self.add_entity(entity)
        self._auto_increment_tag_version = True

    def import_xml(self, xml: bytes) -> None:
        """imports a SWID XML blob"""

        parser = ET.XMLParser()
        tree = ET.fromstring(xml, parser)
        namespaces = {"ns": "http://standards.iso.org/iso/19770/-2/2015/schema.xsd"}
        identity = tree.xpath("/ns:SoftwareIdentity", namespaces=namespaces)[0]

        # identity
        self.tag_id = identity.get("tagId")
        self.tag_version = identity.get("tagVersion")
        self.software_name = identity.get("name")
        self.software_version = identity.get("version")

        # optional metadata
        for meta in identity.xpath("ns:Meta", namespaces=namespaces):
            for attr_name, attrib_name in [
                ("summary", "summary"),
                ("revision", "revision"),
                ("product", "product"),
                ("edition", "edition"),
                ("colloquialVersion", "colloquial_version"),
            ]:
                if attr_name in meta.attrib:
                    setattr(self, attrib_name, meta.attrib[attr_name])

        # entities
        for node in identity.xpath("ns:Entity", namespaces=namespaces):
            entity = uSwidEntity()
            entity._import_xml(node)
            self.add_entity(entity)

        # links
        for node in identity.xpath("ns:Link", namespaces=namespaces):
            link = uSwidLink()
            link._import_xml(node)
            self.add_link(link)

    def import_ini(self, ini: str) -> None:
        """imports a ini file as overrides to the uSwidIdentity data"""
        config = configparser.ConfigParser()
        config.read_string(ini)
        for group in config.sections():
            if group == "uSWID":
                for key, value in config[group].items():
                    if key == "tag-id":
                        self.tag_id = value
                    elif key == "tag-version":
                        self.tag_version = int(value)
                        self._auto_increment_tag_version = False
                    elif key == "software-name":
                        self.software_name = value
                    elif key == "software-version":
                        self.software_version = value
                    elif key == "summary":
                        self.summary = value
                    elif key == "revision":
                        self.revision = value
                    elif key == "product":
                        self.product = value
                    elif key == "edition":
                        self.edition = value
                    elif key == "colloquial-version":
                        self.colloquial_version = value
                    else:
                        print("unknown key {} found in ini file!".format(key))
            if group.startswith("uSWID-Entity:"):
                entity = uSwidEntity()
                entity._import_ini(config[group], role_hint=group)
                self.add_entity(entity)
            if group.startswith("uSWID-Link"):
                link = uSwidLink()
                link._import_ini(config[group])
                self.add_link(link)

    def export_bytes(self) -> bytes:
        """exports a uSwidIdentity CBOR blob"""

        # general identity section
        data: Dict[uSwidGlobalMap, Any] = {}
        if self.tag_id:
            data[uSwidGlobalMap.TAG_ID] = self.tag_id
        if self.tag_version:
            tag_version = self.tag_version
            if self._auto_increment_tag_version:
                tag_version += 1
            data[uSwidGlobalMap.TAG_VERSION] = tag_version
        data[uSwidGlobalMap.CORPUS] = True  # is firmware installable?
        if self.software_name:
            data[uSwidGlobalMap.SOFTWARE_NAME] = self.software_name
        if not self.software_version:
            raise NotSupportedError("a software_version MUST be provided")
        data[uSwidGlobalMap.SOFTWARE_VERSION] = self.software_version

        # metadata section
        metadata: Dict[uSwidGlobalMap, Any] = {uSwidGlobalMap.GENERATOR: self.generator}
        if self.summary:
            metadata[uSwidGlobalMap.SUMMARY] = self.summary
        if self.revision:
            metadata[uSwidGlobalMap.REVISION] = self.revision
        if self.edition:
            metadata[uSwidGlobalMap.PRODUCT] = self.product
        if self.edition:
            metadata[uSwidGlobalMap.EDITION] = self.edition
        if self.colloquial_version:
            metadata[uSwidGlobalMap.COLLOQUIAL_VERSION] = self.colloquial_version
        data[uSwidGlobalMap.SOFTWARE_META] = metadata

        # entities
        if not self._entities:
            raise NotSupportedError("at least one entity MUST be provided")
        has_tag_creator = False
        for entity in self._entities.values():
            if not entity.roles:
                raise NotSupportedError(
                    "all entities MUST have at least one role: {}".format(str(entity))
                )
            if not entity.name:
                raise NotSupportedError("all entities MUST have a name")
            if uSwidEntityRole.TAG_CREATOR in entity.roles:
                has_tag_creator = True
        if not has_tag_creator:
            raise NotSupportedError("all entries MUST have a tag-creator")
        data[uSwidGlobalMap.ENTITY] = [
            entity._export_bytes() for entity in self._entities.values()
        ]
        data[uSwidGlobalMap.LINK] = [
            link._export_bytes() for link in self._links.values()
        ]

        return cbor.dumps(data)

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
