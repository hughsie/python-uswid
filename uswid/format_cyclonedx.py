#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent

from typing import Dict, Any, Optional, List

import json
import uuid
from datetime import datetime

from .container import uSwidContainer
from .format import uSwidFormatBase
from .component import uSwidComponent
from .entity import uSwidEntityRole
from .hash import uSwidHashAlg


def _convert_hash_alg_id(alg_id: uSwidHashAlg) -> str:
    return {
        uSwidHashAlg.SHA256: "SHA-256",
        uSwidHashAlg.SHA384: "SHA-384",
        uSwidHashAlg.SHA512: "SHA-512",
    }.get(alg_id, "UNKNOWN")


class uSwidFormatCycloneDX(uSwidFormatBase):
    """CycloneDX file"""

    def __init__(self) -> None:
        """Initializes uSwidFormatCycloneDX"""
        uSwidFormatBase.__init__(self)

    def save(self, container: uSwidContainer) -> bytes:
        # header
        root: Dict[str, Any] = {}
        root["bomFormat"] = "CycloneDX"
        root["specVersion"] = "1.4"
        root["serialNumber"] = f"urn:uuid:{str(uuid.uuid4())}"
        root["version"] = 1

        # metadata
        metadata: Dict[str, Any] = {}
        metadata["timestamp"] = datetime.now().isoformat()
        root["metadata"] = metadata

        # generator
        metadata["tools"] = [
            {"vendor": "uSWID Authors", "name": "uSWID", "version": "0.4.0"}
        ]

        # find components
        components: List[Dict[str, Any]] = []
        licenses: List[Dict[str, Any]] = []
        dependencies: List[Dict[str, str]] = []
        for component in container:
            components.append(self._save_component(component))
            for link in component.links:
                if not link.href:
                    continue
                if link.rel == "license":
                    license_choice: Dict[str, Any] = {}
                    license_choice["license"] = {"url": link.href}
                    licenses.append(license_choice)
                if link.rel in ["component", "compiler"]:
                    dependencies.append({"ref": link.href})

        # optional
        if components:
            root["components"] = components
        if dependencies:
            root["dependencies"] = dependencies
        if licenses:
            root["licenses"] = licenses

        return json.dumps(root, indent=2).encode()

    def _save_component(self, component: uSwidComponent) -> Dict[str, Any]:
        root: Dict[str, Any] = {}
        root["type"] = "firmware"
        if component.persistent_id:
            root["group"] = component.persistent_id
        if component.product:
            root["name"] = component.product
        if component.summary:
            root["description"] = component.summary

        swid: Dict[str, Any] = {}
        if component.tag_id:
            swid["tagId"] = component.tag_id
        if component.software_name:
            swid["name"] = component.software_name
        if component.software_version:
            swid["version"] = component.software_version
        if component.tag_version:
            swid["tagVersion"] = component.tag_version
        root["swid"] = swid

        if component.colloquial_version:
            commit: Dict[str, str] = {}
            commit["uid"] = component.colloquial_version
            root["commit"] = commit

        # supplier and authors
        supplier: Dict[str, Any] = {}
        publisher: Optional[str] = None
        author: Optional[str] = None
        for entity in component.entities:
            if uSwidEntityRole.LICENSOR in entity.roles:
                if entity.name:
                    supplier["name"] = entity.name
                if entity.regid:
                    supplier["url"] = [entity.regid]
            if uSwidEntityRole.DISTRIBUTOR in entity.roles:
                if entity.name:
                    publisher = entity.name
            if uSwidEntityRole.SOFTWARE_CREATOR in entity.roles:
                if entity.name:
                    author = entity.name
        if supplier:
            root["supplier"] = supplier
        if publisher:
            root["publisher"] = publisher
        if author:
            root["author"] = author
        hashes: List[Any] = []
        for payload in component.payloads:
            for ihash in payload.hashes:
                if not ihash.alg_id:
                    continue
                hashes.append(
                    {"alg": _convert_hash_alg_id(ihash.alg_id), "content": ihash.value}
                )
        if hashes:
            root["hashes"] = hashes

        # annotations
        annotations: List[Dict[str, Any]] = []
        for evidence in component.evidences:
            annotation = {"subjects": [component.tag_id], "annotator": "component"}
            if evidence.date:
                annotation["timestamp"] = evidence.date.isoformat()
            if evidence.device_id:
                annotation["text"] = evidence.device_id
            annotations.append(annotation)
        if annotations:
            root["annotations"] = annotations

        return root
