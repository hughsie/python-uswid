#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2023 Richard Hughes <richard@hughsie.com>
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
        uSwidHashAlg.SHA256: "SHA256",
        uSwidHashAlg.SHA384: "SHA384",
        uSwidHashAlg.SHA512: "SHA512",
    }.get(alg_id, "UNKNOWN")


class uSwidFormatSpdx(uSwidFormatBase):
    """SPDX file"""

    def __init__(self) -> None:
        """Initializes uSwidFormatSpdx"""
        uSwidFormatBase.__init__(self)

    def save(self, container: uSwidContainer) -> bytes:
        # header
        root: Dict[str, Any] = {}
        root["SPDXID"] = "SPDXRef-DOCUMENT"
        root["spdxVersion"] = "SPDX-2.3"
        root["dataLicense"] = "CC0-1.0"
        root["documentNamespace"] = f"urn:uuid:{str(uuid.uuid4())}"
        # root["name"] = "uSWID SBoM")
        root["name"] = "NOASSERTION"

        # this has to be defined
        root["files"] = []

        # generator
        root["creationInfo"] = {
            "creators": ["Tool: uSWID"],
            "created": datetime.now().strftime("%FT%TZ"),
        }

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

        return json.dumps(root, indent=2).encode()

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

        return root
