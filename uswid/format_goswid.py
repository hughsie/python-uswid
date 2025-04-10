#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# pylint: disable=too-few-public-methods,protected-access,too-many-boolean-expressions

from typing import Dict, Any, Optional, List

import json
from datetime import datetime

from .container import uSwidContainer
from .format import uSwidFormatBase
from .errors import NotSupportedError
from .component import (
    uSwidComponent,
    _VERSION_SCHEME_TO_STRING,
    _VERSION_SCHEME_FROM_STRING,
)
from .entity import uSwidEntity
from .link import uSwidLink, uSwidLinkRel
from .hash import uSwidHash, uSwidHashAlg
from .payload import uSwidPayload
from .evidence import uSwidEvidence
from .format_swid import _ENTITY_MAP_FROM_XML, _ENTITY_MAP_TO_XML


def _get_one_or_more(data: Dict[str, Any], key: str) -> List[Any]:
    value = data.get(key, [])
    if isinstance(value, list):
        return value
    return [value]


class uSwidFormatGoswid(uSwidFormatBase):
    """goSWID file"""

    def __init__(self) -> None:
        """Initializes uSwidFormatGoswid"""
        uSwidFormatBase.__init__(self, "goSWID")

    def load(self, blob: bytes, path: Optional[str] = None) -> uSwidContainer:
        try:
            data = json.loads(blob)
        except json.decoder.JSONDecodeError as e:
            raise NotSupportedError(f"invalid GoSWID: {e}") from e
        container = uSwidContainer()
        if "corim_id" in data:
            data = data["corim_tags"]
        for component_json in data:
            component = uSwidComponent()
            self._load_component_internal(component, component_json)
            container.merge(component)
        return container

    def save(self, container: uSwidContainer) -> bytes:
        root = []
        for component in container:
            root.append(self._save_component_internal(component))
        return json.dumps(root, indent=2, ensure_ascii=False).encode()

    def _save_link(self, link: uSwidLink) -> Dict[str, str]:
        """Exports a uSwidLink goSWID section"""

        node: Dict[str, str] = {}
        if link.href:
            node["href"] = link.href
        if link.rel:
            node["rel"] = str(link.rel)
        return node

    def _save_payload(self, payload: uSwidPayload) -> Dict[str, Any]:
        """Exports a uSwidLink goSWID section"""

        node: Dict[str, Any] = {}
        if payload.name:
            node["fs-name"] = payload.name
        if payload.size:
            node["size"] = str(payload.size)
        if payload.hashes:
            node["hash"] = [payload.hashes[0].alg_id or 0, payload.hashes[0].value]
        return {"file": [node]}

    def _save_evidence(self, evidence: uSwidEvidence) -> Dict[str, Any]:
        """Exports a uSwidLink goSWID section"""

        node: Dict[str, str] = {}
        if evidence.date:
            node["date"] = evidence.date.isoformat()
        if evidence.device_id:
            node["device_id"] = evidence.device_id
        return node

    def _save_entity(self, entity: uSwidEntity) -> Dict[str, Any]:
        """Exports a uSwidEntity goSWID section"""

        node: Dict[str, Any] = {}
        if entity.name:
            node["entity-name"] = entity.name
        if entity.regid:
            node["reg-id"] = entity.regid
        roles = []
        for role in entity.roles:
            try:
                roles.append(_ENTITY_MAP_TO_XML[role])
            except KeyError as e:
                raise NotSupportedError(
                    f"{role} not supported from {','.join(_ENTITY_MAP_TO_XML.values())}"
                ) from e
        # use string if only one role
        if len(roles) == 1:
            node["role"] = roles[0]
        else:
            node["role"] = roles
        return node

    def _save_component_internal(self, component: uSwidComponent) -> Dict[str, Any]:
        # component
        root: Dict[str, Any] = {}
        if component.lang:
            root["lang"] = component.lang
        if component.tag_id:
            root["tag-id"] = component.tag_id
        if component.tag_version:
            root["tag-version"] = component.tag_version
        if component.software_name:
            root["software-name"] = component.software_name
        if component.software_version:
            root["software-version"] = component.software_version
        if component.version_scheme:
            root["version-scheme"] = _VERSION_SCHEME_TO_STRING[component.version_scheme]

        # optional metadata
        if (
            component.summary
            or component.revision
            or component.product
            or component.edition
            or component.colloquial_version
            or component.persistent_id
        ):
            node: Dict[str, str] = {}
            if component.summary:
                node["summary"] = component.summary
            if component.revision:
                node["revision"] = component.revision
            if component.product:
                node["product"] = component.product
            if component.edition:
                node["edition"] = component.edition
            if component.colloquial_version:
                node["colloquial-version"] = component.colloquial_version
            if component.persistent_id:
                node["persistent-id"] = component.persistent_id
            # the CoSWID spec says: 'software-meta => one-or-more'
            root["software-meta"] = [node]

        # checksum
        if component.payloads:
            root["payload"] = []
            for payload in component.payloads:
                root["payload"].append(self._save_payload(payload))

        # evidences
        if component.evidences:
            root["evidence"] = []
            for evidence in component.evidences:
                root["evidence"].append(self._save_evidence(evidence))

        # entities
        if component.entities:
            root["entity"] = []
            for entity in component.entities:
                root["entity"].append(self._save_entity(entity))

        # links
        if component.links:
            root["links"] = []
            for link in component.links:
                root["links"].append(self._save_link(link))

        # success
        return root

    def _save_component(self, component: uSwidComponent) -> bytes:
        """Exports a uSwidComponent goSWID blob"""
        return json.dumps(self._save_component_internal(component), indent=2).encode(
            "utf-8"
        )

    def _load_link(self, link: uSwidLink, node: Dict[str, str]) -> None:
        """Imports a uSwidLink goSWID section"""

        link.href = node.get("href")
        link.rel = uSwidLinkRel.from_string(node.get("rel", "unknown"))

    def _load_evidence(self, evidence: uSwidEvidence, node: Dict[str, str]) -> None:
        """Imports a uSwidEvidence goSWID section"""

        iso_date = node.get("date")
        if iso_date:
            evidence.date = datetime.fromisoformat(iso_date)
        evidence.device_id = node.get("device_id")

    def _load_file(self, payload: uSwidPayload, node: Dict[str, Any]) -> None:
        """Imports a uSwidPayload goSWID section"""

        # sanity check
        if not isinstance(node, dict):
            raise NotSupportedError("No component data")

        # for compat with Intel FSP template
        for key in list(node):
            node[key.replace("_", "-")] = node.pop(key)

        payload.name = node.get("fs-name")
        try:
            payload.size = int(node["size"])
        except (ValueError, KeyError):
            pass
        if "hash" in node:
            ihash = uSwidHash()
            # Intel FSP order is reversed
            try:
                ihash.alg_id = uSwidHashAlg(int(node["hash"][0]))
                ihash.value = node["hash"][1]
            except ValueError:
                ihash.value = node["hash"][0]
                ihash.alg_id = uSwidHashAlg(int(node["hash"][1]))
            payload.add_hash(ihash)

    def _load_entity(
        self,
        entity: uSwidEntity,
        node: Dict[str, str],
    ) -> None:
        """Imports a uSwidEntity goSWID section"""

        # sanity check
        if not isinstance(node, dict):
            raise NotSupportedError("No component data")

        # for compat with Intel FSP template
        for key in list(node):
            node[key.replace("_", "-")] = node.pop(key)

        entity.name = node.get("entity-name")
        entity.regid = node.get("reg-id")
        roles = node.get("role")
        if roles and isinstance(roles, str):
            roles = [roles]  # type: ignore
        for role_str in roles:  # type: ignore
            try:
                entity.roles.append(_ENTITY_MAP_FROM_XML[role_str])
            except KeyError as e:
                raise NotSupportedError(
                    f"{role_str} not supported from {','.join(_ENTITY_MAP_FROM_XML)}"
                ) from e

    def _load_component_internal(
        self, component: uSwidComponent, data: Dict[str, Any]
    ) -> None:

        # sanity check
        if not isinstance(data, dict):
            raise NotSupportedError("No component data")

        # for compat with Intel FSP template
        for key in list(data):
            data[key.replace("_", "-")] = data.pop(key)

        # component
        component.tag_id = data.get("tag-id")
        tag_version = data.get("tag-version")
        if tag_version:
            component.tag_version = int(tag_version)
        component.software_name = data.get("software-name")
        component.software_version = data.get("software-version")
        version_scheme = data.get("version-scheme")
        if version_scheme:
            component.version_scheme = _VERSION_SCHEME_FROM_STRING[version_scheme]

        # optional metadata
        for meta in _get_one_or_more(data, "software-meta"):
            for attr_name, attrib_name in [
                ("summary", "summary"),
                ("revision", "revision"),
                ("product", "product"),
                ("edition", "edition"),
                ("colloquial-version", "colloquial_version"),
            ]:
                if attr_name in meta:
                    setattr(component, attrib_name, meta[attr_name])

        # entities
        for node in _get_one_or_more(data, "entity"):
            entity = uSwidEntity()
            self._load_entity(entity, node)
            component.add_entity(entity)

        # links
        for node in _get_one_or_more(data, "links"):
            link = uSwidLink()
            self._load_link(link, node)
            component.add_link(link)

        # payloads
        for node in _get_one_or_more(data, "payload"):
            for node_file in _get_one_or_more(node, "file"):
                payload = uSwidPayload()
                self._load_file(payload, node_file)
                component.add_payload(payload)
            for node_directory in _get_one_or_more(node, "directory"):
                for node_path_elements in _get_one_or_more(
                    node_directory, "path_elements"
                ):
                    for node_file in _get_one_or_more(node_path_elements, "file"):
                        payload = uSwidPayload()
                        self._load_file(payload, node_file)
                        component.add_payload(payload)

        # evidences
        for node in _get_one_or_more(data, "evidence"):
            evidence = uSwidEvidence()
            self._load_evidence(evidence, node)
            component.add_evidence(evidence)

    def _load_component(self, component: uSwidComponent, blob: bytes) -> None:
        """Imports a uSwidComponent goSWID blob"""

        try:
            data: Dict[str, Any] = json.loads(blob)
        except json.decoder.JSONDecodeError as e:
            raise NotSupportedError(f"invalid goSWID: {e}") from e
        self._load_component_internal(component, data)
