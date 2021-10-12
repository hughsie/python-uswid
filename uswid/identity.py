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
from .enums import uSwidGlobalMap, uSwidRole
from .entity import uSwidEntity


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
        self.tag_id: str = tag_id
        self.tag_version: int = tag_version
        self.software_name: str = software_name
        self.software_version: str = software_version
        self._entities: Dict[str, uSwidEntity] = {}

    def add_entity(self, entity: uSwidEntity) -> None:
        """only adds the latest entity"""
        if not entity.name:
            raise NotSupportedError("the entity name MUST be provided")
        self._entities[entity.name] = entity

    def import_bytes(self, blob: bytes) -> None:
        """imports a uSwidIdentity CBOR blob"""

        if not blob:
            return
        data = cbor.load(io.BytesIO(blob))
        self.tag_id = data.get(uSwidGlobalMap.TAG_ID, None)
        self.tag_version = data.get(uSwidGlobalMap.TAG_VERSION, 0)
        self.software_name = data.get(uSwidGlobalMap.SOFTWARE_NAME, None)
        self.software_version = data.get(uSwidGlobalMap.SOFTWARE_VERSION, None)
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

        self.tag_id = identity.get("tagId")
        self.tag_version = identity.get("tagVersion")
        self.software_name = identity.get("name")
        self.software_version = identity.get("version")
        for node in identity.xpath("ns:Entity", namespaces=namespaces):
            entity = uSwidEntity()
            entity._import_xml(node)
            self.add_entity(entity)

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
                    else:
                        print("unknown key {} found in ini file!".format(key))
            if group.startswith("uSWID-Entity:"):
                entity = uSwidEntity()
                entity._import_ini(config[group], role_hint=group)
                self.add_entity(entity)

    def export_bytes(self) -> bytes:
        """exports a uSwidIdentity CBOR blob"""

        data: Dict[int, Any] = {}
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
            if uSwidRole.TAG_CREATOR in entity.roles:
                has_tag_creator = True
        if not has_tag_creator:
            raise NotSupportedError("all entries MUST have a tag-creator")
        data[uSwidGlobalMap.ENTITY] = [
            entity._export_bytes() for entity in self._entities.values()
        ]
        return cbor.dumps(data)

    def __repr__(self) -> str:
        tmp = "uSwidIdentity({},{},{},{})".format(
            self.tag_id, self.tag_version, self.software_name, self.software_version
        )
        if self._entities:
            tmp += ":\n{}".format(
                "\n".join([str(e) for e in self._entities.values()]),
            )
        return tmp
