#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# pylint: disable=too-few-public-methods,protected-access,too-many-boolean-expressions

from typing import Dict, List, Optional

from datetime import datetime
from lxml import etree as ET

from .container import uSwidContainer
from .format import uSwidFormatBase
from .errors import NotSupportedError
from .component import (
    uSwidComponent,
    uSwidComponentType,
    _VERSION_SCHEME_FROM_STRING,
    _VERSION_SCHEME_TO_STRING,
)
from .entity import uSwidEntity, uSwidEntityRole
from .link import uSwidLink, uSwidLinkRel
from .hash import uSwidHash, uSwidHashAlg
from .payload import uSwidPayload
from .evidence import uSwidEvidence

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
        """Initializes uSwidFormatSwid"""
        uSwidFormatBase.__init__(self, "SWID")

    def load(self, blob: bytes, path: Optional[str] = None) -> uSwidContainer:
        component = uSwidComponent()
        self._load_component(component, blob)
        return uSwidContainer([component])

    def save(self, container: uSwidContainer) -> bytes:
        acc: bytes = b""
        xml_declaration: bool = True
        for component in container:
            acc += self._save_component(component, xml_declaration)
            xml_declaration = False
        return acc

    def _save_link(self, link: uSwidLink, root: ET.Element) -> None:
        """Exports a uSwidLink SWID section"""

        node = ET.SubElement(root, "Link")
        if link.href:
            node.set("href", link.href)
        if link.rel:
            node.set("rel", str(link.rel))

    def _save_payload(self, payload: uSwidPayload, root: ET.Element) -> None:
        """Exports a uSwidHash SWID section"""
        node = ET.SubElement(
            root,
            "File",
            nsmap={
                "SHA256": "http://www.w3.org/2001/04/xmlenc#sha256",
                "SHA512": "http://www.w3.org/2001/04/xmlenc#sha512",
            },
        )
        if payload.name:
            node.set("name", payload.name)
        if payload.size:
            node.set("size", str(payload.size))
        for ihash in payload.hashes:
            if ihash.alg_id == uSwidHashAlg.SHA256:
                node.set("{http://www.w3.org/2001/04/xmlenc#sha256}hash", ihash.value)
            elif ihash.alg_id == uSwidHashAlg.SHA512:
                node.set("{http://www.w3.org/2001/04/xmlenc#sha512}hash", ihash.value)

    def _save_evidence(self, evidence: uSwidEvidence, root: ET.Element) -> None:
        """Exports a uSwidEvidence SWID section"""
        node = ET.SubElement(
            root,
            "Evidence",
        )
        if evidence.date:
            node.set("date", evidence.date.isoformat())
        if evidence.device_id:
            node.set("deviceId", evidence.device_id)

    def _save_entity(self, entity: uSwidEntity, root: ET.Element) -> None:
        """Exports a uSwidEntity SWID section"""

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
                    f"{role} not supported from {','.join(_ENTITY_MAP_TO_XML.values())}"
                ) from e
        if roles:
            node.set("role", " ".join(roles))

    def _save_component(
        self, component: uSwidComponent, xml_declaration: bool = True
    ) -> bytes:
        """Exports a uSwidComponent SWID blob"""

        # component
        NSMAP = {
            None: "http://standards.iso.org/iso/19770/-2/2015/schema.xsd",
            "SHA256": "http://www.w3.org/2001/04/xmlenc#sha256",
            "SHA512": "http://www.w3.org/2001/04/xmlenc#sha512",
            "n8060": "http://csrc.nist.gov/ns/swid/2015-extensions/1.0",
        }
        root = ET.Element("SoftwareIdentity", nsmap=NSMAP)
        if component.lang:
            root.attrib["{http://www.w3.org/XML/1998/namespace}lang"] = component.lang
        if component.software_name:
            root.set("name", component.software_name)
        if component.tag_id:
            root.set("tagId", component.tag_id)
        if component.tag_version:
            root.set("tagVersion", str(component.tag_version))
        if component.software_version:
            root.set("version", component.software_version)
        if component.version_scheme:
            root.set(
                "versionScheme", _VERSION_SCHEME_TO_STRING[component.version_scheme]
            )

        # entities
        for entity in component._entities.values():
            self._save_entity(entity, root)
        for link in component._links.values():
            self._save_link(link, root)

        # payloads
        if component.payloads:
            node = ET.SubElement(root, "Payload", nsmap=NSMAP)
            node2 = ET.SubElement(node, "Directory", nsmap=NSMAP)
            for payload in component.payloads:
                self._save_payload(payload, node2)

        # evidences
        if component.evidences:
            for evidence in component.evidences:
                self._save_evidence(evidence, root)

        # optional metadata
        if (
            component.summary
            or component.cpe
            or component.type
            or component.revision
            or component.product
            or component.edition
            or component.colloquial_version
            or component.persistent_id
            or component.activation_status
        ):
            node = ET.SubElement(root, "Meta")
            if component.summary:
                node.set("summary", component.summary)
            if component.revision:
                node.set("revision", component.revision)
            if component.product:
                node.set("product", component.product)
            if component.edition:
                node.set("edition", component.edition)
            if component.colloquial_version:
                node.set("colloquialVersion", component.colloquial_version)
            if component.persistent_id:
                node.set("persistentId", component.persistent_id)
            if component.activation_status:
                node.set("activationStatus", component.activation_status)
            if component.cpe:
                node.set("cpe", component.cpe)
            if component.type:
                node.set("type", str(component.type))

        # success
        return ET.tostring(
            root, encoding="utf-8", xml_declaration=xml_declaration, pretty_print=True
        )

    def _load_link(self, link: uSwidLink, node: ET.SubElement) -> None:
        """Imports a uSwidLink SWID section"""

        LINK_MAP: Dict[str, str] = {
            "seeAlso": "see-also",
        }
        link.href = node.get("href")
        rel_data = node.get("rel")
        link.rel = uSwidLinkRel.from_string(LINK_MAP.get(rel_data, rel_data))

    def _load_payload(self, payload: uSwidPayload, node: ET.SubElement) -> None:
        """Imports a uSwidPayload SWID section"""

        payload.name = node.get("name")
        try:
            payload.size = int(node.get("size"))
        except TypeError:
            pass
        try:
            value = node.attrib["{http://www.w3.org/2001/04/xmlenc#sha256}hash"]
            if value:
                payload.add_hash(uSwidHash(alg_id=uSwidHashAlg.SHA256, value=value))
        except KeyError:
            pass
        try:
            value = node.attrib["{http://www.w3.org/2001/04/xmlenc#sha512}hash"]
            if value:
                payload.add_hash(uSwidHash(alg_id=uSwidHashAlg.SHA512, value=value))
        except KeyError:
            pass

    def _load_evidence(self, evidence: uSwidEvidence, node: ET.SubElement) -> None:
        """Imports a uSwidEvidence SWID section"""

        iso_date = node.get("date")
        if iso_date:
            evidence.date = datetime.fromisoformat(iso_date)
        try:
            evidence.device_id = node.get("deviceId")
        except TypeError:
            pass

    def _load_entity(
        self,
        entity: uSwidEntity,
        node: ET.SubElement,
    ) -> None:
        """Imports a uSwidEntity SWID section"""

        entity.name = node.get("name")
        entity.regid = node.get("regid", None)
        for role_str in node.get("role", "").split(" "):
            try:
                entity.roles.append(_ENTITY_MAP_FROM_XML[role_str])
            except KeyError as e:
                raise NotSupportedError(
                    f"{role_str} not supported from {','.join(_ENTITY_MAP_FROM_XML)}"
                ) from e

    def _load_component(self, component: uSwidComponent, blob: bytes) -> None:
        """Imports a uSwidComponent SWID blob"""

        parser = ET.XMLParser()
        try:
            tree = ET.fromstring(blob, parser)
        except ET.XMLSyntaxError as e:
            raise NotSupportedError("Invalid syntax") from e
        namespaces = {
            "ns": "http://standards.iso.org/iso/19770/-2/2015/schema.xsd",
            "ds": "http://www.w3.org/2000/09/xmldsig#",
            "SHA256": "http://www.w3.org/2001/04/xmlenc#sha256",
            "SHA512": "http://www.w3.org/2001/04/xmlenc#sha512",
        }

        # strip off digital signature
        if tree.xpath("/ds:Signature", namespaces=namespaces):
            element = tree.xpath(
                "/ds:Signature/ds:Object/ns:SoftwareIdentity", namespaces=namespaces
            )[0]
        else:
            element = tree.xpath("/ns:SoftwareIdentity", namespaces=namespaces)[0]

        # component
        component.tag_id = element.get("tagId")
        try:
            component.tag_version = int(element.get("tagVersion"))
        except TypeError:
            pass
        component.software_name = element.get("name")
        component.software_version = element.get("version")
        try:
            component.version_scheme = _VERSION_SCHEME_FROM_STRING[
                element.get("versionScheme")
            ]
        except KeyError:
            component.version_scheme = None

        # optional metadata
        for meta in element.xpath("ns:Meta", namespaces=namespaces):
            for attr_name, attrib_name in [
                ("summary", "summary"),
                ("revision", "revision"),
                ("product", "product"),
                ("edition", "edition"),
                ("colloquialVersion", "colloquial_version"),
                ("persistentId", "persistent_id"),
                ("activationStatus", "activation_status"),
                ("cpe", "cpe"),
            ]:
                if attr_name in meta.attrib:
                    setattr(component, attrib_name, meta.attrib[attr_name])
            if "type" in meta.attrib:
                component.type = uSwidComponentType.from_str(meta.attrib["type"])

        # entities
        for node in element.xpath("ns:Entity", namespaces=namespaces):
            entity = uSwidEntity()
            self._load_entity(entity, node)
            component.add_entity(entity)

        # links
        for node in element.xpath("ns:Link", namespaces=namespaces):
            link = uSwidLink()
            self._load_link(link, node)
            component.add_link(link)

        # payloads
        for node in element.xpath(
            "ns:Payload/ns:Directory/ns:File", namespaces=namespaces
        ):
            payload = uSwidPayload()
            self._load_payload(payload, node)
            component.add_payload(payload)

        # evidences
        for node in element.xpath("ns:Evidence", namespaces=namespaces):
            evidence = uSwidEvidence()
            self._load_evidence(evidence, node)
            component.add_evidence(evidence)
