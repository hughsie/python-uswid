#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=protected-access,too-many-boolean-expressions

import configparser
import io
import os
import json
import uuid

from typing import Dict, Any, Optional, List

import cbor
from lxml import etree as ET

from .errors import NotSupportedError
from .enums import uSwidGlobalMap, uSwidVersionScheme
from .entity import uSwidEntity, uSwidEntityRole
from .link import uSwidLink


class uSwidIdentity:
    """represents a SWID identity"""

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

    def import_bytes(self, blob: bytes, offset: Optional[int] = 0) -> int:
        """imports a uSwidIdentity CBOR blob"""

        if not blob:
            return 0
        consumed: int = 0
        try:
            f = io.BytesIO(blob[offset:])
            data = cbor.load(f)
            consumed = f.tell()
        except EOFError as e:
            raise NotSupportedError("invalid header") from e

        # identity can be specified as a string or in binary
        tag_id_bytes = data.get(uSwidGlobalMap.TAG_ID, None)
        if isinstance(self.tag_id, str):
            self.tag_id = tag_id_bytes
        else:
            try:
                self.tag_id = str(uuid.UUID(bytes=tag_id_bytes))
            except ValueError:
                self.tag_id = tag_id_bytes.hex()

        self.tag_version = data.get(uSwidGlobalMap.TAG_VERSION, 0)
        self.software_name = data.get(uSwidGlobalMap.SOFTWARE_NAME, None)
        self.software_version = data.get(uSwidGlobalMap.SOFTWARE_VERSION, None)
        self.version_scheme = data.get(uSwidGlobalMap.VERSION_SCHEME, None)

        # optional metadata
        software_metas = data.get(uSwidGlobalMap.SOFTWARE_META, [])
        if isinstance(software_metas, dict):
            software_metas = [software_metas]
        for sm in software_metas:
            for key, value in sm.items():
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
                elif key == uSwidGlobalMap.PERSISTENT_ID:
                    self.persistent_id = value

        # entities
        entities = data.get(uSwidGlobalMap.ENTITY, [])
        if isinstance(entities, dict):
            entities = [entities]
        for entity_data in entities:
            entity = uSwidEntity()
            entity._import_data(entity_data)
            # skip invalid entries
            if not entity.roles:
                continue
            self.add_entity(entity)

        # links
        for link_data in data.get(uSwidGlobalMap.LINK, []):
            link = uSwidLink()
            link._import_data(link_data)
            self.add_link(link)

        self._auto_increment_tag_version = True

        # number of bytes consumed, i.e. where the next CBOR blob is found
        return consumed

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
        try:
            self.version_scheme = self._VERSION_SCHEME_FROM_STRING[
                identity.get("versionScheme")
            ]
        except KeyError:
            self.version_scheme = None

        # optional metadata
        for meta in identity.xpath("ns:Meta", namespaces=namespaces):
            for attr_name, attrib_name in [
                ("summary", "summary"),
                ("revision", "revision"),
                ("product", "product"),
                ("edition", "edition"),
                ("colloquialVersion", "colloquial_version"),
                ("persistentId", "persistent_id"),
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

    def import_json(self, blob: bytes) -> None:
        """imports a SWID JSON blob"""

        try:
            identity = json.loads(blob)
        except json.decoder.JSONDecodeError as e:
            raise NotSupportedError("invalid JSON: {}".format(e)) from e
        self._import_json(identity)

    def _import_json(self, identity: Dict[str, Any]) -> None:

        # identity
        self.tag_id = identity.get("tag-id")
        self.tag_version = identity.get("tag-version")
        self.software_name = identity.get("software-name")
        self.software_version = identity.get("software-version")
        self.version_scheme = self._VERSION_SCHEME_FROM_STRING[
            identity.get("version-scheme")
        ]

        # optional metadata
        for meta in identity["software-meta"]:
            for attr_name, attrib_name in [
                ("summary", "summary"),
                ("revision", "revision"),
                ("product", "product"),
                ("edition", "edition"),
                ("colloquial-version", "colloquial_version"),
            ]:
                if attr_name in meta:
                    setattr(self, attrib_name, meta[attr_name])

        # entities
        try:
            for node in identity["entity"]:
                entity = uSwidEntity()
                entity._import_json(node)
                self.add_entity(entity)
        except KeyError:
            pass

        # links
        try:
            for node in identity["links"]:
                link = uSwidLink()
                link._import_json(node)
                self.add_link(link)
        except KeyError:
            pass

    def _export_json(self) -> Dict[str, Any]:

        # identity
        root: Dict[str, Any] = {}
        if self.lang:
            root["lang"] = self.lang
        if self.tag_id:
            root["tag-id"] = self.tag_id
        if self.tag_version:
            root["tag-version"] = self.tag_version
        if self.software_name:
            root["software-name"] = self.software_name
        if self.software_version:
            root["software-version"] = self.software_version
        if self.version_scheme:
            root["version-scheme"] = self._VERSION_SCHEME_TO_STRING[self.version_scheme]

        # optional metadata
        if (
            self.summary
            or self.revision
            or self.product
            or self.edition
            or self.colloquial_version
            or self.persistent_id
        ):
            node: Dict[str, str] = {}
            if self.summary:
                node["summary"] = self.summary
            if self.revision:
                node["revision"] = self.revision
            if self.product:
                node["product"] = self.product
            if self.edition:
                node["edition"] = self.edition
            if self.colloquial_version:
                node["colloquial-version"] = self.colloquial_version
            if self.persistent_id:
                node["persistent-id"] = self.persistent_id
            # the CoSWID spec says: 'software-meta => one-or-more'
            root["software-meta"] = [node]

        # entities
        entities = self._entities.values()
        if entities:
            root["entity"] = []
            for entity in entities:
                root["entity"].append(entity._export_json())

        # links
        links = self._links.values()
        if links:
            root["link"] = []
            for link in links:
                root["link"].append(link._export_json())

        # success
        return root

    def export_json(self) -> bytes:

        # just proxy
        return json.dumps(self._export_json(), indent=2).encode("utf-8")

    def import_pkg_config(self, txt: str, filepath: Optional[str] = None) -> None:
        """imports a pkg-conifg file as overrides to the uSwidIdentity data"""

        # filename base is the ID
        if filepath:
            self.tag_id = os.path.basename(filepath)
            if self.tag_id.endswith(".pc"):
                self.tag_id = self.tag_id[:-3]

        # read out properties
        for line in txt.split("\n"):
            try:
                key, value = line.split(":", maxsplit=2)
            except ValueError:
                continue
            if key == "Name":
                self.software_name = value.strip()
                continue
            if key == "Description":
                self.summary = value.strip()
                continue
            if key == "Version":
                self.software_version = value.strip()
                continue
            if key == "AppstreamId":
                self.persistent_id = value.strip()
                continue

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
                    elif key == "version-scheme":
                        self.version_scheme = self._VERSION_SCHEME_FROM_STRING[value]
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
                    elif key == "persistent-id":
                        self.persistent_id = value
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

    def export_xml(self) -> bytes:

        # identity
        NSMAP = {
            None: "http://standards.iso.org/iso/19770/-2/2015/schema.xsd",
            "SHA256": "http://www.w3.org/2001/04/xmlenc#sha256",
            "SHA512": "http://www.w3.org/2001/04/xmlenc#sha512",
            "n8060": "http://csrc.nist.gov/ns/swid/2015-extensions/1.0",
        }
        root = ET.Element("SoftwareIdentity", nsmap=NSMAP)
        if self.lang:
            root.attrib["{http://www.w3.org/XML/1998/namespace}lang"] = self.lang
        if self.software_name:
            root.set("name", self.software_name)
        if self.tag_id:
            root.set("tagId", self.tag_id)
        if self.tag_version:
            root.set("tagVersion", str(self.tag_version))
        if self.software_version:
            root.set("version", self.software_version)
        if self.version_scheme:
            root.set(
                "versionScheme", self._VERSION_SCHEME_TO_STRING[self.version_scheme]
            )

        # entities
        for entity in self._entities.values():
            entity._export_xml(root)
        for link in self._links.values():
            link._export_xml(root)

        # optional metadata
        if (
            self.summary
            or self.revision
            or self.product
            or self.edition
            or self.colloquial_version
            or self.persistent_id
        ):
            node = ET.SubElement(root, "Meta")
            if self.revision:
                node.set("revision", self.revision)
            if self.product:
                node.set("product", self.product)
            if self.edition:
                node.set("edition", self.edition)
            if self.colloquial_version:
                node.set("colloquialVersion", self.colloquial_version)
            if self.persistent_id:
                node.set("persistentId", self.persistent_id)

        # success
        return ET.tostring(
            root, encoding="utf-8", xml_declaration=True, pretty_print=True
        )

    def export_ini(self) -> str:
        config = configparser.ConfigParser()

        # main section
        main = {}
        if self.tag_id:
            main["tag-id"] = self.tag_id
        if self.tag_version:
            main["tag-version"] = str(self.tag_version)
        if self.software_name:
            main["software-name"] = self.software_name
        if self.software_version:
            main["software-version"] = self.software_version
        if self.version_scheme:
            main["version-scheme"] = self._VERSION_SCHEME_TO_STRING[self.version_scheme]
        if self.summary:
            main["summary"] = self.summary
        if self.revision:
            main["revision"] = self.revision
        if self.product:
            main["product"] = self.product
        if self.edition:
            main["edition"] = self.edition
        if self.colloquial_version:
            main["colloquial-version"] = self.colloquial_version
        if self.persistent_id:
            main["persistent-id"] = self.persistent_id
        config["uSWID"] = main

        # entity
        if self._entities:
            config["uSWID-Entity:TagCreator"] = list(self._entities.values())[
                0
            ]._export_ini()

        # link
        if self._links:
            config["uSWID-Link"] = list(self._links.values())[0]._export_ini()

        # as string
        with io.StringIO() as f:
            config.write(f)
            f.seek(0)
            return f.read()

    def export_bytes(self) -> bytes:
        """exports a uSwidIdentity CBOR blob"""

        # general identity section
        data: Dict[uSwidGlobalMap, Any] = {}

        if self.lang:
            data[uSwidGlobalMap.LANG] = self.lang
        if self.tag_id:
            try:
                data[uSwidGlobalMap.TAG_ID] = uuid.UUID(hex=self.tag_id).bytes
            except (KeyError, ValueError):
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
        if self.version_scheme:
            data[uSwidGlobalMap.VERSION_SCHEME] = self.version_scheme.value

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
        if self.persistent_id:
            metadata[uSwidGlobalMap.PERSISTENT_ID] = self.persistent_id
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
