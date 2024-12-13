#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# pylint: disable=too-few-public-methods,protected-access

from typing import Dict, Any, Optional, List, Tuple, Union

import io
import uuid
from datetime import datetime
from enum import IntEnum

import cbor2

from .container import uSwidContainer
from .format import uSwidFormatBase
from .errors import NotSupportedError
from .component import uSwidComponent, uSwidComponentType
from .entity import uSwidEntity, uSwidEntityRole
from .link import uSwidLink, uSwidLinkRel
from .hash import uSwidHash, uSwidHashAlg
from .payload import uSwidPayload
from .evidence import uSwidEvidence


class uSwidGlobalMap(IntEnum):
    """Represents an enumerated tag ID"""

    TAG_ID = 0
    SOFTWARE_NAME = 1
    ENTITY = 2
    EVIDENCE = 3
    LINK = 4
    SOFTWARE_META = 5
    PAYLOAD = 6
    HASH = 7
    CORPUS = 8
    PATCH = 9
    MEDIA = 10
    SUPPLEMENTAL = 11
    TAG_VERSION = 12
    SOFTWARE_VERSION = 13
    VERSION_SCHEME = 14
    LANG = 15
    DIRECTORY = 16
    FILE = 17
    PROCESS = 18
    RESOURCE = 19
    SIZE = 20
    FILE_VERSION = 21
    KEY = 22
    LOCATION = 23
    FS_NAME = 24
    ROOT = 25
    PATH_ELEMENTS = 26
    PROCESS_NAME = 27
    PID = 28
    TYPE = 29
    ENTITY_NAME = 31
    REG_ID = 32
    ROLE = 33
    THUMBPRINT = 34
    DATE = 35
    DEVICE_ID = 36
    ARTIFACT = 37
    HREF = 38
    OWNERSHIP = 39
    REL = 40
    MEDIA_TYPE = 41
    USE = 42
    ACTIVATION_STATUS = 43
    CHANNEL_TYPE = 44
    COLLOQUIAL_VERSION = 45
    DESCRIPTION = 46
    EDITION = 47
    ENTITLEMENT_DATA_REQUIRED = 48
    ENTITLEMENT_KEY = 49
    GENERATOR = 50
    PERSISTENT_ID = 51
    PRODUCT = 52
    PRODUCT_FAMILY = 53
    REVISION = 54
    SUMMARY = 55
    UNSPSC_CODE = 56
    UNSPSC_VERSION = 57

    def __str__(self):
        return self.name.lower()


def _get_one_or_more(data: Dict[uSwidGlobalMap, Any], key: uSwidGlobalMap) -> List[Any]:
    value = data.get(key, [])
    if isinstance(value, dict):
        return [value]
    return value


def _set_one_or_more(
    data: Dict[uSwidGlobalMap, Any], key: uSwidGlobalMap, value: List[Any]
) -> None:
    if not value:
        return
    data[key] = value if len(value) > 1 else value[0]


def _to_perhaps_hex_bytes(value: str) -> Union[bytes, str]:

    try:
        return bytes.fromhex(value)
    except ValueError:
        return value


def _from_perhaps_hex_bytes(value: Union[bytes, str]) -> str:

    try:
        return value.hex()  # type: ignore
    except AttributeError:
        return value  # type: ignore


class uSwidFormatCoswid(uSwidFormatBase):
    """CoSWID file"""

    def __init__(self) -> None:
        """Initializes uSwidFormatCoswid"""
        uSwidFormatBase.__init__(self, "CoSWID")

    def load(self, blob: bytes, path: Optional[str] = None) -> uSwidContainer:
        component = uSwidComponent()
        container = uSwidContainer([component])
        self._load_component(component, blob)
        return container

    def save(self, container: uSwidContainer) -> bytes:
        component = container.get_default()
        if not component:
            raise NotSupportedError("cannot save when no default component")
        return self._save_component(component)

    def _save_link(self, link: uSwidLink) -> Dict[uSwidGlobalMap, Any]:
        """Exports a uSwidLink CoSWID section"""

        data: Dict[uSwidGlobalMap, Any] = {}
        data[uSwidGlobalMap.HREF] = link.href
        if link.rel:
            data[uSwidGlobalMap.REL] = link.rel
        return data

    def _save_hash(self, ihash: uSwidHash) -> Tuple[int, bytes]:
        """Exports a uSwidHash CoSWID section"""
        return (ihash.alg_id or 0, bytes.fromhex(ihash.value or ""))

    def _save_payload(self, payload: uSwidPayload) -> Dict[uSwidGlobalMap, Any]:
        """Exports a uSwidPayload CoSWID section"""

        data: Dict[uSwidGlobalMap, Any] = {}
        if payload.name:
            data[uSwidGlobalMap.FS_NAME] = payload.name
        if payload.size:
            data[uSwidGlobalMap.SIZE] = int(payload.size)
        if payload.hashes:
            payload_hashes = []
            for ihash in payload.hashes:
                payload_hashes.append(self._save_hash(ihash))
            _set_one_or_more(data, uSwidGlobalMap.HASH, payload_hashes)
        return {uSwidGlobalMap.FILE: data}

    def _save_evidence(self, evidence: uSwidEvidence) -> Dict[uSwidGlobalMap, Any]:
        """Exports a uSwidEvidence CoSWID section"""

        data: Dict[uSwidGlobalMap, Any] = {}
        if evidence.date:
            data[uSwidGlobalMap.DATE] = evidence.date.timestamp()
        if evidence.device_id:
            data[uSwidGlobalMap.DEVICE_ID] = evidence.device_id
        return data

    def _save_entity(self, entity: uSwidEntity) -> Dict[uSwidGlobalMap, Any]:
        """Exports a uSwidEntity CoSWID section"""

        data: Dict[uSwidGlobalMap, Any] = {}
        data[uSwidGlobalMap.ENTITY_NAME] = entity.name
        if entity.regid:
            data[uSwidGlobalMap.REG_ID] = entity.regid
        _set_one_or_more(data, uSwidGlobalMap.ROLE, entity.roles)
        return data

    def _save_component(self, component: uSwidComponent) -> bytes:
        """Exports a uSwidComponent CoSWID blob"""

        # general component section
        data: Dict[uSwidGlobalMap, Any] = {}

        if component.lang:
            data[uSwidGlobalMap.LANG] = component.lang
        if component.tag_id:
            try:
                data[uSwidGlobalMap.TAG_ID] = uuid.UUID(hex=component.tag_id).bytes
            except (KeyError, ValueError):
                data[uSwidGlobalMap.TAG_ID] = component.tag_id
        if component.tag_version:
            tag_version = component.tag_version
            if component._auto_increment_tag_version:
                tag_version += 1
            data[uSwidGlobalMap.TAG_VERSION] = tag_version
        data[uSwidGlobalMap.CORPUS] = True  # is firmware installable?
        if component.software_name:
            data[uSwidGlobalMap.SOFTWARE_NAME] = component.software_name
        if not component.software_version:
            raise NotSupportedError("a software_version MUST be provided")
        data[uSwidGlobalMap.SOFTWARE_VERSION] = component.software_version
        if component.version_scheme:
            data[uSwidGlobalMap.VERSION_SCHEME] = component.version_scheme

        # metadata section
        metadata: Dict[Union[uSwidGlobalMap, str], Any] = {
            uSwidGlobalMap.GENERATOR: component.generator
        }
        if component.type and component.type != uSwidComponentType.FIRMWARE:
            metadata[uSwidGlobalMap.MEDIA] = str(component.type)
        if component.summary:
            metadata[uSwidGlobalMap.SUMMARY] = component.summary
        if component.revision:
            metadata[uSwidGlobalMap.REVISION] = component.revision
        if component.product:
            metadata[uSwidGlobalMap.PRODUCT] = component.product
        if component.activation_status:
            metadata[uSwidGlobalMap.ACTIVATION_STATUS] = component.activation_status
        if component.edition:
            metadata[uSwidGlobalMap.EDITION] = _to_perhaps_hex_bytes(component.edition)
        if component.colloquial_version:
            metadata[uSwidGlobalMap.COLLOQUIAL_VERSION] = _to_perhaps_hex_bytes(
                component.colloquial_version
            )
        if component.persistent_id:
            metadata[uSwidGlobalMap.PERSISTENT_ID] = component.persistent_id
        if component.cpe:
            metadata["cpe"] = component.cpe
        data[uSwidGlobalMap.SOFTWARE_META] = metadata

        # payloads
        if component.payloads:
            _set_one_or_more(
                data,
                uSwidGlobalMap.PAYLOAD,
                [self._save_payload(payload) for payload in component.payloads],
            )

        # evidences
        if component.evidences:
            _set_one_or_more(
                data,
                uSwidGlobalMap.EVIDENCE,
                [self._save_evidence(evidence) for evidence in component.evidences],
            )

        # entities
        if not component._entities:
            raise NotSupportedError("at least one entity MUST be provided")
        has_tag_creator = False
        for entity in component._entities.values():
            if not entity.roles:
                raise NotSupportedError(
                    f"all entities MUST have at least one role: {str(entity)}"
                )
            if not entity.name:
                raise NotSupportedError("all entities MUST have a name")
            if uSwidEntityRole.TAG_CREATOR in entity.roles:
                has_tag_creator = True
        if not has_tag_creator:
            raise NotSupportedError("all entries MUST have a tag-creator")
        _set_one_or_more(
            data,
            uSwidGlobalMap.ENTITY,
            [self._save_entity(entity) for entity in component._entities.values()],
        )
        _set_one_or_more(
            data,
            uSwidGlobalMap.LINK,
            [self._save_link(link) for link in component._links.values()],
        )
        return cbor2.dumps(data)

    def _load_link(self, link: uSwidLink, data: Dict[uSwidGlobalMap, Any]) -> None:
        """Imports a uSwidLink CoSWID section"""

        # always a string
        link.href = data.get(uSwidGlobalMap.HREF)

        # rel can either be a uSwidLinkRel or a string
        rel_data = data.get(uSwidGlobalMap.REL)
        if isinstance(rel_data, str):
            link.rel = uSwidLinkRel.from_string(rel_data)
        elif isinstance(rel_data, int):
            link.rel = uSwidLinkRel(rel_data)
        elif isinstance(rel_data, uSwidLinkRel):
            link.rel = rel_data

    def _load_hash(self, ihash: uSwidHash, data: Any) -> None:
        """Imports a uSwidHash CoSWID section"""
        ihash.alg_id = uSwidHashAlg(data[0])
        if isinstance(data[1], bytes):
            ihash.value = bytes.hex(data[1])
        else:
            ihash.value = data[1]

    def _load_payload(
        self,
        payload: uSwidPayload,
        data: Dict[uSwidGlobalMap, Any],
    ) -> None:
        """Imports a uSwidPayload CoSWID section"""
        for key, value in data.items():
            if key == uSwidGlobalMap.FS_NAME:
                payload.name = value
            if key == uSwidGlobalMap.SIZE:
                payload.size = value
            if key == uSwidGlobalMap.HASH:
                if not isinstance(value[0], list):
                    value = [value]
                for hash_data in value:
                    ihash = uSwidHash()
                    self._load_hash(ihash, hash_data)
                    payload.add_hash(ihash)

    def _load_evidence(
        self,
        evidence: uSwidEvidence,
        data: Dict[uSwidGlobalMap, Any],
    ) -> None:
        """Imports a uSwidEvidence CoSWID section"""
        for key, value in data.items():
            if key == uSwidGlobalMap.DATE:
                evidence.date = datetime.utcfromtimestamp(value)
            if key == uSwidGlobalMap.DEVICE_ID:
                evidence.device_id = value

    def _load_entity(
        self,
        entity: uSwidEntity,
        data: Dict[uSwidGlobalMap, Any],
    ) -> None:
        """Imports a uSwidEntity CoSWID section"""

        entity.name = data.get(uSwidGlobalMap.ENTITY_NAME)
        entity.regid = data.get(uSwidGlobalMap.REG_ID, None)
        entity_roles = data.get(uSwidGlobalMap.ROLE, [])
        if isinstance(entity_roles, int):
            entity_roles = [entity_roles]
        for role in entity_roles:
            try:
                entity.roles.append(uSwidEntityRole(int(role)))
            except KeyError:
                print(f"ignoring invalid role of {role}")
                continue

    def _load_component(
        self, component: uSwidComponent, blob: bytes, offset: Optional[int] = 0
    ) -> int:
        """Imports a uSwidComponent CoSWID blob"""

        if not blob:
            return 0
        consumed: int = 0
        try:
            f = io.BytesIO(blob[offset:])
            data = cbor2.load(f)
            consumed = f.tell()
        except EOFError as e:
            raise NotSupportedError("invalid header") from e

        # strip off digital signature
        if isinstance(data, cbor2.CBORTag):
            if data.tag != 98:
                raise NotSupportedError("invalid digital signature")
            data = cbor2.loads(data.value[2])

        # component can be specified as a string or in binary
        tag_id_bytes = data.get(uSwidGlobalMap.TAG_ID, None)
        if isinstance(tag_id_bytes, str):
            component.tag_id = tag_id_bytes
        else:
            try:
                component.tag_id = str(uuid.UUID(bytes=tag_id_bytes))
            except ValueError:
                component.tag_id = tag_id_bytes.hex()

        component.tag_version = data.get(uSwidGlobalMap.TAG_VERSION, 0)
        component.software_name = data.get(uSwidGlobalMap.SOFTWARE_NAME, None)
        component.software_version = data.get(uSwidGlobalMap.SOFTWARE_VERSION, None)
        component.version_scheme = data.get(uSwidGlobalMap.VERSION_SCHEME, None)

        # optional metadata
        for sm in _get_one_or_more(data, uSwidGlobalMap.SOFTWARE_META):
            for key, value in sm.items():
                if key == uSwidGlobalMap.GENERATOR:
                    component.generator = value
                elif key == uSwidGlobalMap.SUMMARY:
                    component.summary = value
                elif key == uSwidGlobalMap.REVISION:
                    component.revision = value
                elif key == uSwidGlobalMap.PRODUCT:
                    component.product = value
                elif key == uSwidGlobalMap.ACTIVATION_STATUS:
                    component.activation_status = value
                elif key == uSwidGlobalMap.EDITION:
                    component.edition = _from_perhaps_hex_bytes(value)
                elif key == uSwidGlobalMap.COLLOQUIAL_VERSION:
                    component.colloquial_version = _from_perhaps_hex_bytes(value)
                elif key == uSwidGlobalMap.PERSISTENT_ID:
                    component.persistent_id = value
                elif key == uSwidGlobalMap.MEDIA:
                    component.type = uSwidComponentType.from_str(value)
                elif key == "cpe":
                    component.cpe = value

        # payload
        file_datas = []
        for payload_data in _get_one_or_more(data, uSwidGlobalMap.PAYLOAD):
            file_datas.extend(_get_one_or_more(payload_data, uSwidGlobalMap.FILE))
            for directory_data in _get_one_or_more(
                payload_data, uSwidGlobalMap.DIRECTORY
            ):
                for path_data in _get_one_or_more(
                    directory_data, uSwidGlobalMap.PATH_ELEMENTS
                ):
                    file_datas.extend(_get_one_or_more(path_data, uSwidGlobalMap.FILE))
        for file_data in file_datas:
            payload = uSwidPayload()
            self._load_payload(payload, file_data)
            component.add_payload(payload)

        # evidence
        for evidence_data in _get_one_or_more(data, uSwidGlobalMap.EVIDENCE):
            evidence = uSwidEvidence()
            self._load_evidence(evidence, evidence_data)
            component.add_evidence(evidence)

        # entities
        for entity_data in _get_one_or_more(data, uSwidGlobalMap.ENTITY):
            entity = uSwidEntity()
            self._load_entity(entity, entity_data)
            # skip invalid entries
            if not entity.roles:
                continue
            component.add_entity(entity)

        # links
        for link_data in _get_one_or_more(data, uSwidGlobalMap.LINK):
            link = uSwidLink()
            self._load_link(link, link_data)
            component.add_link(link)

        component._auto_increment_tag_version = True

        # number of bytes consumed, i.e. where the next CBOR blob is found
        return consumed
