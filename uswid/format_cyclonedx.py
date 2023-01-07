#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+

from typing import Dict, Any, Optional, List

import json
import uuid
from datetime import datetime

from .container import uSwidContainer
from .format import uSwidFormatBase
from .identity import uSwidIdentity
from .entity import uSwidEntityRole


class uSwidFormatCycloneDX(uSwidFormatBase):
    """CycloneDX file"""

    def __init__(self) -> None:

        uSwidFormatBase.__init__(self)

    def save(self, container: uSwidContainer) -> bytes:

        # header
        root: Dict[str, Any] = {}
        root["bomFormat"] = "CycloneDX"
        root["specVersion"] = "1.4"
        root["serialNumber"] = "urn:uuid:{}".format(str(uuid.uuid4()))
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
        for identity in container:
            components.append(self._save_identity(identity))
            for link in identity.links:
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

    def _save_identity(self, identity: uSwidIdentity) -> Dict[str, Any]:

        component: Dict[str, Any] = {}
        component["type"] = "firmware"
        if identity.persistent_id:
            component["group"] = identity.persistent_id
        if identity.product:
            component["name"] = identity.product
        if identity.summary:
            component["description"] = identity.summary

        swid: Dict[str, Any] = {}
        if identity.tag_id:
            swid["tagId"] = identity.tag_id
        if identity.software_name:
            swid["name"] = identity.software_name
        if identity.software_version:
            swid["version"] = identity.software_version
        if identity.tag_version:
            swid["tagVersion"] = identity.tag_version
        component["swid"] = swid

        if identity.colloquial_version:
            commit: Dict[str, str] = {}
            commit["uid"] = identity.colloquial_version
            component["commit"] = commit

        # supplier and authors
        supplier: Dict[str, Any] = {}
        publisher: Optional[str] = None
        author: Optional[str] = None
        for entity in identity.entities:
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
            component["supplier"] = supplier
        if publisher:
            component["publisher"] = publisher
        if author:
            component["author"] = author

        return component
