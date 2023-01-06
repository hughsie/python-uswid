#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=too-few-public-methods,protected-access,too-many-boolean-expressions

from typing import Dict, List

from lxml import etree as ET

from .container import uSwidContainer
from .format import uSwidFormatBase
from .errors import NotSupportedError
from .identity import (
    uSwidIdentity,
    _VERSION_SCHEME_FROM_STRING,
    _VERSION_SCHEME_TO_STRING,
)
from .entity import uSwidEntity, uSwidEntityRole
from .link import uSwidLink

_ENTITY_MAP_FROM_XML = {
    "tagCreator": uSwidEntityRole.TAG_CREATOR,
    "softwareCreator": uSwidEntityRole.SOFTWARE_CREATOR,
    "aggregator": uSwidEntityRole.AGGREGATOR,
    "distributor": uSwidEntityRole.DISTRIBUTOR,
    "licensor": uSwidEntityRole.LICENSOR,
    "maintainer": uSwidEntityRole.MAINTAINER,
}
_ENTITY_MAP_TO_XML = {
    uSwidEntityRole.TAG_CREATOR: "tagCreator",
    uSwidEntityRole.SOFTWARE_CREATOR: "softwareCreator",
    uSwidEntityRole.AGGREGATOR: "aggregator",
    uSwidEntityRole.DISTRIBUTOR: "distributor",
    uSwidEntityRole.LICENSOR: "licensor",
    uSwidEntityRole.MAINTAINER: "maintainer",
}


class uSwidFormatSwid(uSwidFormatBase):
    """SWID file"""

    def __init__(self) -> None:

        uSwidFormatBase.__init__(self)

    def load(self, blob: bytes) -> uSwidContainer:

        identity = uSwidIdentity()
        self._load_identity(identity, blob)
        return uSwidContainer([identity])

    def save(self, container: uSwidContainer) -> bytes:

        identity = container.get_default()
        if not identity:
            raise NotSupportedError("cannot save when no default identity")
        return self._save_identity(identity)

    def _save_link(self, link: uSwidLink, root: ET.Element) -> None:
        """exports a uSwidLink SWID section"""

        node = ET.SubElement(root, "Link")
        if link.href:
            node.set("href", link.href)
        if link.rel:
            node.set("rel", link.rel)

    def _save_entity(self, entity: uSwidEntity, root: ET.Element) -> None:
        """exports a uSwidEntity SWID section"""

        node = ET.SubElement(root, "Entity")
        if entity.name:
            node.set("name", entity.name)
        if entity.regid:
            node.set("regid", entity.regid)
        roles: List[str] = []
        for role in entity.roles:
            try:
                roles.append(_ENTITY_MAP_TO_XML[role])
            except KeyError as e:
                raise NotSupportedError(
                    "{} not supported from {}".format(
                        role, ",".join(_ENTITY_MAP_TO_XML.values())
                    )
                ) from e
        if roles:
            node.set("role", " ".join(roles))

    def _save_identity(self, identity: uSwidIdentity) -> bytes:
        """exports a uSwidIdentity SWID blob"""

        # identity
        NSMAP = {
            None: "http://standards.iso.org/iso/19770/-2/2015/schema.xsd",
            "SHA256": "http://www.w3.org/2001/04/xmlenc#sha256",
            "SHA512": "http://www.w3.org/2001/04/xmlenc#sha512",
            "n8060": "http://csrc.nist.gov/ns/swid/2015-extensions/1.0",
        }
        root = ET.Element("SoftwareIdentity", nsmap=NSMAP)
        if identity.lang:
            root.attrib["{http://www.w3.org/XML/1998/namespace}lang"] = identity.lang
        if identity.software_name:
            root.set("name", identity.software_name)
        if identity.tag_id:
            root.set("tagId", identity.tag_id)
        if identity.tag_version:
            root.set("tagVersion", str(identity.tag_version))
        if identity.software_version:
            root.set("version", identity.software_version)
        if identity.version_scheme:
            root.set(
                "versionScheme", _VERSION_SCHEME_TO_STRING[identity.version_scheme]
            )

        # entities
        for entity in identity._entities.values():
            self._save_entity(entity, root)
        for link in identity._links.values():
            self._save_link(link, root)

        # optional metadata
        if (
            identity.summary
            or identity.revision
            or identity.product
            or identity.edition
            or identity.colloquial_version
            or identity.persistent_id
        ):
            node = ET.SubElement(root, "Meta")
            if identity.revision:
                node.set("revision", identity.revision)
            if identity.product:
                node.set("product", identity.product)
            if identity.edition:
                node.set("edition", identity.edition)
            if identity.colloquial_version:
                node.set("colloquialVersion", identity.colloquial_version)
            if identity.persistent_id:
                node.set("persistentId", identity.persistent_id)

        # success
        return ET.tostring(
            root, encoding="utf-8", xml_declaration=True, pretty_print=True
        )

    def _load_link(self, link: uSwidLink, node: ET.SubElement) -> None:
        """imports a uSwidLink SWID section"""

        LINK_MAP: Dict[str, str] = {
            "seeAlso": "see-also",
        }
        link.href = node.get("href")
        rel_data = node.get("rel")
        link.rel = LINK_MAP.get(rel_data, rel_data)

    def _load_entity(
        self,
        entity: uSwidEntity,
        node: ET.SubElement,
    ) -> None:
        """imports a uSwidEntity SWID section"""

        entity.name = node.get("name")
        entity.regid = node.get("regid", None)
        for role_str in node.get("role", "").split(" "):
            try:
                entity.roles.append(_ENTITY_MAP_FROM_XML[role_str])
            except KeyError as e:
                raise NotSupportedError(
                    "{} not supported from {}".format(
                        role_str, ",".join(_ENTITY_MAP_FROM_XML)
                    )
                ) from e

    def _load_identity(self, identity: uSwidIdentity, blob: bytes) -> None:
        """imports a uSwidIdentity SWID blob"""

        parser = ET.XMLParser()
        tree = ET.fromstring(blob, parser)
        namespaces = {"ns": "http://standards.iso.org/iso/19770/-2/2015/schema.xsd"}
        element = tree.xpath("/ns:SoftwareIdentity", namespaces=namespaces)[0]

        # identity
        identity.tag_id = element.get("tagId")
        identity.tag_version = element.get("tagVersion")
        identity.software_name = element.get("name")
        identity.software_version = element.get("version")
        try:
            identity.version_scheme = _VERSION_SCHEME_FROM_STRING[
                element.get("versionScheme")
            ]
        except KeyError:
            identity.version_scheme = None

        # optional metadata
        for meta in element.xpath("ns:Meta", namespaces=namespaces):
            for attr_name, attrib_name in [
                ("summary", "summary"),
                ("revision", "revision"),
                ("product", "product"),
                ("edition", "edition"),
                ("colloquialVersion", "colloquial_version"),
                ("persistentId", "persistent_id"),
            ]:
                if attr_name in meta.attrib:
                    setattr(identity, attrib_name, meta.attrib[attr_name])

        # entities
        for node in element.xpath("ns:Entity", namespaces=namespaces):
            entity = uSwidEntity()
            self._load_entity(entity, node)
            identity.add_entity(entity)

        # links
        for node in element.xpath("ns:Link", namespaces=namespaces):
            link = uSwidLink()
            self._load_link(link, node)
            identity.add_link(link)
