#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2023 Richard Hughes <richard@hughsie.com>
# (c) Copyright 2025 - 2026 HP Development Company, L.P.
#
# SPDX-License-Identifier: BSD-2-Clause-Patent

from typing import Dict, Any, Optional, List

import json
import uuid
from datetime import datetime

from .container import uSwidContainer
from .format import uSwidFormatBase
from .component import uSwidComponent
from .entity import uSwidEntity, uSwidEntityRole
from .errors import NotSupportedError
from .hash import uSwidHashAlg
from .link import uSwidLink, uSwidLinkRel
from .purl import uSwidPurl


def _convert_hash_alg_id(alg_id: uSwidHashAlg) -> str:
    return {
        uSwidHashAlg.SHA256: "SHA256",
        uSwidHashAlg.SHA384: "SHA384",
        uSwidHashAlg.SHA512: "SHA512",
    }.get(alg_id, "UNKNOWN")


def _normalize_spdx_namespace(namespace: Optional[str]) -> Optional[str]:
    if not namespace:
        return None
    namespace = namespace.rstrip("#/")
    if namespace.startswith("urn:uuid:"):
        namespace = namespace[len("urn:uuid:") :]
    return namespace


def _namespaced_tag_id(spdx_id: Optional[str], namespace: Optional[str]) -> Optional[str]:
    if not spdx_id:
        return None
    if spdx_id.startswith("SPDXRef-"):
        spdx_id = spdx_id[8:]
    if namespace:
        return f"{namespace}:{spdx_id}"
    return spdx_id


def _get_graph_nodes_by_type(data: Dict[str, Any], node_type: str) -> Optional[List[Dict[str, Any]]]:
    """Get all nodes of a given type from an SPDX 3.0 JSON-LD document."""
    if "@graph" not in data:
        return None
    graph = data["@graph"]
    if not isinstance(graph, list):
        return None
    nodes: List[Dict[str, Any]] = []
    for node in graph:
        if not isinstance(node, dict):
            continue
        curr_node_type = node.get("type")
        if curr_node_type:
            if isinstance(curr_node_type, str) and curr_node_type == node_type:
                nodes.append(node)
    return nodes


def _detect_spdx_json_version(data: Dict[str, Any]) -> str:
    """Best-effort detection of SPDX JSON serialization version."""
    # SPDX 3.0
    # Check CreationInfo node for specVersion field 
    creation_info_node = _get_graph_nodes_by_type(data, "CreationInfo")
    if creation_info_node:
        spec_version = creation_info_node[0].get("specVersion")
        if isinstance(spec_version, str) and "3.0" in spec_version:
            return "3.0"

    # Fallback - assume that the presence of "@graph" indicates SPDX 3.0, even if specVersion is missing or malformed.
    if "@graph" in data:
        return "3.0"

    # SPDX 2.3
    spdx_version = data.get("spdxVersion")
    if isinstance(spdx_version, str) and spdx_version == "SPDX-2.3":
        return "2.3"

    # Some SPDX 2.x JSON documents may omit spdxVersion in malformed cases.
    if "packages" in data or "SPDXID" in data:
        return "2.3"

    raise NotSupportedError("unrecognized SPDX JSON format")


def _spdx30_node_id(node: Dict[str, Any]) -> Optional[str]:
    return node.get("spdxId") or node.get("@id")


class uSwidFormatSpdx(uSwidFormatBase):
    """SPDX file"""

    def _load_single_package(
        self,
        pkg: Dict[str, Any],
        data_root: Dict[str, Any],
        namespace: Optional[str],
    ) -> uSwidComponent:
        """Load a single package from SPDX 2.3 JSON data"""
        component = uSwidComponent()
        # tag_id
        component.tag_id = _namespaced_tag_id(pkg.get("SPDXID"), namespace)
        # externalRefs (purl)
        external_refs = pkg.get("externalRefs") or pkg.get("externalReferences") or []
        if isinstance(external_refs, list):
            for ref in external_refs:
                if not isinstance(ref, dict):
                    continue
                if ref.get("referenceType") != "purl":
                    continue
                locator = ref.get("referenceLocator")
                if locator:
                    component.purl = uSwidPurl(locator)
                    break
        # basic fields
        component.software_name = pkg.get("name")
        component.summary = pkg.get("summary")
        component.software_version = pkg.get("versionInfo")

        # licenseDeclared (best-effort extraction of SPDX IDs)
        spdx_license_ids = pkg.get("licenseDeclared")
        if spdx_license_ids:
            for spdx_license_id in spdx_license_ids.split(" AND "):
                component.add_link(
                    uSwidLink(
                        rel=uSwidLinkRel.LICENSE,
                        spdx_id=spdx_license_id,
                    )
                )

        # originator / supplier
        originator = pkg.get("originator")
        supplier = pkg.get("supplier")
        if supplier:
            if supplier.startswith("Organization: "):
                supplier = supplier[14:]
            component.add_entity(
                uSwidEntity(name=supplier, roles=[uSwidEntityRole.LICENSOR])
            )
        if originator:
            if originator.startswith("Organization: "):
                originator = originator[14:]
            component.add_entity(
                uSwidEntity(name=originator, roles=[uSwidEntityRole.SOFTWARE_CREATOR])
            )

        # creationInfo creators (tag creators)
        try:
            creators = data_root["creationInfo"]["creators"]
            for creator in creators:
                if creator.startswith("Organization: "):
                    component.add_entity(
                        uSwidEntity(
                            name=creator[14:], roles=[uSwidEntityRole.TAG_CREATOR]
                        )
                    )
                    break
                if creator.startswith("Person: "):
                    component.add_entity(
                        uSwidEntity(
                            name=creator[8:], roles=[uSwidEntityRole.TAG_CREATOR]
                        )
                    )
                    break
        except KeyError:
            pass

        return component

    def _load_single_node(
        self,
        node: Dict[str, Any],
        nodes_by_id: Dict[str, Dict[str, Any]],
    ) -> uSwidComponent:
        """Load a single SPDX 3.0 node from JSON data."""
        component = uSwidComponent()
        # tag_id
        component.tag_id = _namespaced_tag_id(node.get("spdxId"), None)

        # externalRefs (purl) - not implemented yet

        # basic fields
        component.software_name = node.get("name")

        # component.summary = pkg.get("summary")
        component.software_version = node.get("software_packageVersion")

        # licenseDeclared (best-effort extraction of SPDX IDs) - not implemented yet

        # originator / supplier
        self._add_spdx30_agent_entities(
            component,
            node.get("suppliedBy"),
            nodes_by_id,
            uSwidEntityRole.LICENSOR,
        )
        self._add_spdx30_agent_entities(
            component,
            node.get("originatedBy"),
            nodes_by_id,
            uSwidEntityRole.SOFTWARE_CREATOR,
        )
        # creationInfo creators (tag creators)
        self._load_spdx30_creation_info(component, node, nodes_by_id)
        return component

    def _add_spdx30_agent_entities(
        self,
        component: uSwidComponent,
        entities: Any,
        nodes_by_id: Dict[str, Dict[str, Any]],
        role: uSwidEntityRole,
    ) -> None:
        if isinstance(entities, str):
            entity_refs = [entities]
        elif isinstance(entities, list):
            entity_refs = entities
        else:
            return
        for entity in entity_refs:
            if not isinstance(entity, str):
                continue
            node = nodes_by_id.get(entity)
            if node:
                name = node.get("name")
            else:
                # Keep unresolved references as-is for visibility rather than
                # silently dropping creators.
                name = entity
            if name and isinstance(name, str):
                component.add_entity(uSwidEntity(name=name, roles=[role]))

    def _load_spdx30_creation_info(
        self,
        component: uSwidComponent,
        node: Dict[str, Any],
        nodes_by_id: Dict[str, Dict[str, Any]],
    ) -> None:
        creation_info_ref = node.get("creationInfo")
        if not isinstance(creation_info_ref, str):
            return
        creation_info = nodes_by_id.get(creation_info_ref)
        if not creation_info:
            return
        self._add_spdx30_agent_entities(
            component,
            creation_info.get("createdBy"),
            nodes_by_id,
            uSwidEntityRole.TAG_CREATOR,
        )

    def __init__(self) -> None:
        """Initializes uSwidFormatSpdx"""
        uSwidFormatBase.__init__(self, "SPDX")
        self.version = None

    def load(self, blob: bytes, path: Optional[str] = None) -> uSwidContainer:
        try:
            data = json.loads(blob)
        except json.JSONDecodeError as e:
            raise NotSupportedError(f"invalid JSON file: {e}") from e

        self.version = _detect_spdx_json_version(data)
        if self.version == "2.3":
            return self._load_spdx23(data)
        if self.version == "3.0":
            return self._load_spdx30(data)

        raise NotSupportedError(f"unsupported SPDX JSON version {self.version}")

    def _load_spdx23(self, data: Dict[str, Any]) -> uSwidContainer:
        packages = data.get("packages")
        if not packages:
            # return empty container vs raising, depending on policy
            return uSwidContainer()

        # build components
        namespace = _normalize_spdx_namespace(data.get("documentNamespace"))
        components_by_spdxid = {}
        container = uSwidContainer()
        for pkg in packages:
            comp = self._load_single_package(pkg, data, namespace)
            pkg_spdxid = pkg.get("SPDXID")
            if pkg_spdxid:
                components_by_spdxid[pkg_spdxid] = comp
            container.append(comp)

        # relationships (dependencies)
        for rel in data.get("relationships", []):
            try:
                if rel.get("relationshipType") != "DEPENDS_ON":
                    continue
                src = rel["spdxElementId"]
                tgt = rel["relatedSpdxElement"]
                if src in components_by_spdxid and tgt in components_by_spdxid:
                    # add link from src -> tgt
                    csrc = components_by_spdxid[src]
                    ctgt = components_by_spdxid[tgt]
                    csrc.add_link(
                        uSwidLink(rel=uSwidLinkRel.COMPONENT, href=ctgt.tag_id)
                    )
            except KeyError:
                continue  # skip malformed relationship objects

        return container

    def _load_spdx30(self, data: Dict[str, Any]) -> uSwidContainer:
        graph = data.get("@graph")
        if not isinstance(graph, list):
            raise NotSupportedError("SPDX 3.0 JSON-LD document missing @graph list")
        raise NotSupportedError("SPDX 3.0 JSON-LD loading is not implemented")
    def save(self, container: uSwidContainer) -> bytes:
        # header
        root: Dict[str, Any] = {}
        root["SPDXID"] = "SPDXRef-DOCUMENT"
        root["spdxVersion"] = "SPDX-2.3"
        root["dataLicense"] = "CC0-1.0"
        root["documentNamespace"] = f"urn:uuid:{str(uuid.uuid4())}"
        # root["name"] = "uSWID SBOM")
        root["name"] = "NOASSERTION"

        # this has to be defined
        root["files"] = []

        # generator
        root["creationInfo"] = {
            "creators": ["Tool: uSWID"],
            "created": datetime.now().strftime("%FT%TZ"),
        }

        # tag creator
        creator: Optional[str] = None
        for component in container:
            for entity in component.entities:
                if uSwidEntityRole.TAG_CREATOR in entity.roles:
                    if entity.name:
                        creator = entity.name
        if creator:
            root["creationInfo"]["creators"].append(f"Organization: {creator}")

        # what packages are we describing
        document_describes: List[str] = []
        for component in container:
            document_describes.append(f"SPDXRef-{component.tag_id}")
        if document_describes:
            root["documentDescribes"] = document_describes

        # optional
        packages: List[Dict[str, Any]] = []
        for component in container:
            packages.append(self._save_component(component))
        if packages:
            root["packages"] = packages

        return json.dumps(root, indent=2, ensure_ascii=False).encode()

    def _save_component(self, component: uSwidComponent) -> Dict[str, Any]:
        root: Dict[str, Any] = {}

        # attrs
        root["SPDXID"] = f"SPDXRef-{component.tag_id}"
        root["downloadLocation"] = "NOASSERTION"
        if component.product:
            root["name"] = component.product
        if component.summary:
            root["summary"] = component.summary
        if component.software_version:
            root["versionInfo"] = component.software_version
        # not sure where to store component.persistent_id or component.colloquial_version

        # checksums
        checksums: List[Dict[str, str]] = []
        if component.payloads:
            if component.payloads[0].name:
                root["packageFileName"] = component.payloads[0].name
            for ihash in component.payloads[0].hashes:
                checksum: Dict[str, str] = {}
                if ihash.value:
                    checksum["checksumValue"] = ihash.value
                if ihash.alg_id:
                    checksum["algorithm"] = _convert_hash_alg_id(ihash.alg_id)
                checksums.append(checksum)
        if checksums:
            root["checksums"] = checksums

        # supplier and authors
        originator: Optional[str] = None
        supplier: Optional[str] = None
        for entity in component.entities:
            if uSwidEntityRole.LICENSOR in entity.roles:
                if entity.name:
                    supplier = entity.name
            if uSwidEntityRole.SOFTWARE_CREATOR in entity.roles:
                if entity.name:
                    originator = entity.name
        if supplier:
            root["supplier"] = f"Organization: {supplier}"
        if originator:
            root["originator"] = f"Organization: {originator}"

        # annotations
        annotations = []
        for evidence in component.evidences:
            annotation = {"annotationType": "OTHER", "comment": "NOASSERTION"}
            if evidence.date:
                annotation["annotationDate"] = evidence.date.strftime("%FT%TZ")
            if evidence.device_id:
                annotation["annotator"] = f"Tool: {evidence.device_id}"
            annotations.append(annotation)
        if annotations:
            root["annotations"] = annotations

        # license
        license_spdx_ids = []
        for link in component.links:
            if link.rel != uSwidLinkRel.LICENSE:
                continue
            if link.spdx_id:
                license_spdx_ids.append(link.spdx_id)
        if license_spdx_ids:
            root["licenseDeclared"] = " AND ".join(license_spdx_ids)

        return root
