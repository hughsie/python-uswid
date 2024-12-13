#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# pylint: disable=too-few-public-methods,protected-access

from typing import Dict, List, Any, Optional, Union

import configparser
import io
import os
from datetime import datetime

from .container import uSwidContainer
from .format import uSwidFormatBase
from .errors import NotSupportedError
from .component import (
    uSwidComponent,
    uSwidComponentType,
    _VERSION_SCHEME_TO_STRING,
    _VERSION_SCHEME_FROM_STRING,
)
from .entity import uSwidEntity, uSwidEntityRole
from .link import uSwidLink, uSwidLinkRel
from .hash import uSwidHash
from .payload import uSwidPayload
from .evidence import uSwidEvidence

_ENTITY_MAP_FROM_INI = {
    "TagCreator": uSwidEntityRole.TAG_CREATOR,
    "SoftwareCreator": uSwidEntityRole.SOFTWARE_CREATOR,
    "Aggregator": uSwidEntityRole.AGGREGATOR,
    "Distributor": uSwidEntityRole.DISTRIBUTOR,
    "Licensor": uSwidEntityRole.LICENSOR,
    "Maintainer": uSwidEntityRole.MAINTAINER,
}
_ENTITY_MAP_TO_INI = {
    uSwidEntityRole.TAG_CREATOR: "TagCreator",
    uSwidEntityRole.SOFTWARE_CREATOR: "SoftwareCreator",
    uSwidEntityRole.AGGREGATOR: "Aggregator",
    uSwidEntityRole.DISTRIBUTOR: "Distributor",
    uSwidEntityRole.LICENSOR: "Licensor",
    uSwidEntityRole.MAINTAINER: "Maintainer",
}


class uSwidFormatIni(uSwidFormatBase):
    """INI file"""

    def __init__(self) -> None:
        """Initializes uSwidFormatIni"""
        uSwidFormatBase.__init__(self, "INI")

    def load(self, blob: bytes, path: Optional[str] = None) -> uSwidContainer:
        component = uSwidComponent()
        self._load_component(component, blob, path=path)
        return uSwidContainer([component])

    def save(self, container: uSwidContainer) -> bytes:
        component = container.get_default()
        if not component:
            raise NotSupportedError("cannot save when no default component")
        return self._save_component(component)

    def _save_link(self, link: uSwidLink) -> Dict[str, Any]:
        """Exports a uSwidLink INI section"""

        data: Dict[str, Any] = {}
        if link.rel:
            data["rel"] = str(link.rel)
        if link.href:
            data["href"] = link.href
        return data

    def _save_payload(self, payload: uSwidPayload) -> Dict[str, Any]:
        """Exports a uSwidLink INI section"""

        data: Dict[str, Any] = {}
        if payload.name:
            data["name"] = payload.name
        if payload.size:
            data["size"] = payload.size
        if payload.hashes:
            data["hash"] = payload.hashes[0].value
        return data

    def _save_evidence(self, evidence: uSwidEvidence) -> Dict[str, Any]:
        """Exports a uSwidLink INI section"""

        data: Dict[str, Any] = {}
        if evidence.date:
            data["date"] = evidence.date.isoformat()
        if evidence.device_id:
            data["device-id"] = evidence.device_id
        return data

    def _save_entity(self, entity: uSwidEntity) -> Dict[str, Any]:
        """Exports a uSwidEntity INI section"""

        data: Dict[str, Any] = {}
        if entity.name:
            data["name"] = entity.name
        if entity.regid:
            data["regid"] = entity.regid
        extra_roles: List[str] = []
        for role in entity.roles:
            if role == uSwidEntityRole.TAG_CREATOR:
                continue
            extra_roles.append(_ENTITY_MAP_TO_INI[role])
        if extra_roles:
            data["extra-roles"] = ",".join(extra_roles)
        return data

    def _save_component(self, component: uSwidComponent) -> bytes:
        config = configparser.ConfigParser()

        # main section
        main = {}
        if component.tag_id:
            main["tag-id"] = component.tag_id
        if component.tag_version:
            main["tag-version"] = str(component.tag_version)
        if component.type:
            main["type"] = str(component.type)
        if component.software_name:
            main["software-name"] = component.software_name
        if component.software_version:
            main["software-version"] = component.software_version
        if component.version_scheme:
            main["version-scheme"] = _VERSION_SCHEME_TO_STRING[component.version_scheme]
        if component.summary:
            main["summary"] = component.summary
        if component.revision:
            main["revision"] = component.revision
        if component.product:
            main["product"] = component.product
        if component.edition:
            main["edition"] = component.edition
        if component.colloquial_version:
            main["colloquial-version"] = component.colloquial_version
        if component.persistent_id:
            main["persistent-id"] = component.persistent_id
        if component.activation_status:
            main["activation-status"] = component.activation_status
        if component.cpe:
            main["cpe"] = component.cpe
        config["uSWID"] = main

        # entity
        if component.entities:
            config["uSWID-Entity:TagCreator"] = self._save_entity(component.entities[0])

        # link
        for i, link in enumerate(component.links):
            key = "uSWID-Link"
            if i > 0:
                key += f":{i}"
            config[key] = self._save_link(link)

        # payload
        for i, payload in enumerate(component.payloads):
            key = "uSWID-Payload"
            if i > 0:
                key += f":{i}"
            config[key] = self._save_payload(payload)

        # evidence
        for i, evidence in enumerate(component.evidences):
            key = "uSWID-Evidence"
            if i > 0:
                key += f":{i}"
            config[key] = self._save_evidence(evidence)

        # as string
        with io.StringIO() as f:
            config.write(f)
            f.seek(0)
            return f.read().encode()

    def _load_link(
        self, link: uSwidLink, data: Union[configparser.SectionProxy, Dict[str, str]]
    ) -> None:
        """Imports a uSwidLink INI section"""

        for key, value in data.items():
            if key == "href":
                link.href = value
            elif key == "rel":
                link.rel = uSwidLinkRel.from_string(value)
            else:
                print(f"unknown key {key} found in ini file!")
        if not link.href:
            raise NotSupportedError("all entities MUST have a href")

    def _load_payload(
        self,
        payload: uSwidPayload,
        data: Union[configparser.SectionProxy, Dict[str, str]],
        path: Optional[str] = None,
    ) -> None:
        """Imports a uSwidPayload INI section"""

        for key, value in data.items():
            if key == "name":
                payload.name = value
            elif key == "size":
                payload.size = int(value)
            elif key == "hash":
                payload.add_hash(uSwidHash(value=value))
            elif key == "path":
                payload.name = os.path.basename(value)
                if os.path.exists(value):
                    payload.ensure_from_filename(value)
            else:
                print(f"unknown key {key} found in ini file!")

        # can we load this and work it out
        if path and payload.name:
            fn = os.path.join(path, payload.name)
            if os.path.exists(fn):
                payload.ensure_from_filename(fn)
        if not payload.hashes:
            raise NotSupportedError("all payloads MUST have at least one hash")

    def _load_evidence(
        self,
        evidence: uSwidEvidence,
        data: Union[configparser.SectionProxy, Dict[str, str]],
    ) -> None:
        """Imports a uSwidEvidence INI section"""

        for key, value in data.items():
            if key == "date":
                evidence.date = datetime.fromisoformat(value)
            elif key == "device-id":
                evidence.device_id = value
            else:
                print(f"unknown key {key} found in ini file!")

    def _load_entity(
        self,
        entity: uSwidEntity,
        data: Union[configparser.SectionProxy, Dict[str, str]],
        role_hint: Optional[str] = None,
    ) -> None:
        """Imports a uSwidEntity INI section"""

        if role_hint:
            try:
                entity.roles.append(_ENTITY_MAP_FROM_INI[role_hint.split(":")[1]])
            except (KeyError, TypeError, IndexError):
                pass
        for key, value in data.items():
            if key == "name":
                entity.name = value
            elif key == "regid":
                entity.regid = value
            elif key == "extra-roles":
                for role_str in value.split(","):
                    try:
                        entity.roles.append(_ENTITY_MAP_FROM_INI[role_str])
                    except KeyError as e:
                        raise NotSupportedError(
                            "{} not supported from {}".format(
                                role_str, ",".join(_ENTITY_MAP_FROM_INI)
                            )
                        ) from e
            else:
                print(f"unknown key {key} found in ini file!")
        if not entity.name:
            raise NotSupportedError("all entities MUST have a name")
        if not entity.roles:
            raise NotSupportedError(f"entity {entity.name} MUST have at least one role")

    def _load_component(
        self, component: uSwidComponent, blob: bytes, path: Optional[str]
    ) -> None:
        config = configparser.ConfigParser()
        config.read_string(blob.decode())
        for group in config.sections():
            if group == "uSWID":
                for key, value in config[group].items():
                    if key == "tag-id":
                        component.tag_id = value
                    elif key == "tag-version":
                        component.tag_version = int(value)
                        component._auto_increment_tag_version = False
                    elif key == "type":
                        component.type = uSwidComponentType.from_str(value)
                    elif key == "software-name":
                        component.software_name = value
                    elif key == "software-version":
                        component.software_version = value
                    elif key == "version-scheme":
                        component.version_scheme = _VERSION_SCHEME_FROM_STRING[value]
                    elif key == "summary":
                        component.summary = value
                    elif key == "revision":
                        component.revision = value
                    elif key == "product":
                        component.product = value
                    elif key == "edition":
                        component.edition = value
                    elif key == "colloquial-version":
                        component.colloquial_version = value
                    elif key == "persistent-id":
                        component.persistent_id = value
                    elif key == "activation-status":
                        component.activation_status = value
                    elif key == "cpe":
                        component.cpe = value
                    else:
                        print(f"unknown key {key} found in ini file!")
            if group.startswith("uSWID-Entity:"):
                entity = uSwidEntity()
                self._load_entity(entity, config[group], role_hint=group)
                component.add_entity(entity)
            if group.startswith("uSWID-Link"):
                link = uSwidLink()
                self._load_link(link, config[group])
                component.add_link(link)
            if group.startswith("uSWID-Payload"):
                payload = uSwidPayload()
                self._load_payload(payload, config[group], path=path)
                component.add_payload(payload)
            if group.startswith("uSWID-Evidence"):
                evidence = uSwidEvidence()
                self._load_evidence(evidence, config[group])
                component.add_evidence(evidence)
