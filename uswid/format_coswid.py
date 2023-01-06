#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=too-few-public-methods,protected-access

from typing import Dict, Any, Optional

import io
import uuid
import cbor

from .enums import uSwidGlobalMap
from .container import uSwidContainer
from .format import uSwidFormatBase
from .errors import NotSupportedError
from .identity import uSwidIdentity
from .entity import uSwidEntity, uSwidEntityRole
from .link import uSwidLink, uSwidLinkRel


class uSwidFormatCoswid(uSwidFormatBase):
    """CoSWID file"""

    def __init__(self) -> None:

        uSwidFormatBase.__init__(self)

    def load(self, blob: bytes) -> uSwidContainer:

        identity = uSwidIdentity()
        container = uSwidContainer([identity])
        self._load_identity(identity, blob)
        return container

    def save(self, container: uSwidContainer) -> bytes:

        identity = container.get_default()
        if not identity:
            raise NotSupportedError("cannot save when no default identity")
        return self._save_identity(identity)

    def _save_link(self, link: uSwidLink) -> Dict[uSwidGlobalMap, Any]:
        """exports a uSwidLink CoSWID section"""

        data: Dict[uSwidGlobalMap, Any] = {}
        data[uSwidGlobalMap.HREF] = link.href

        # map back into a uSwidLinkRel if possible
        if link.rel:
            LINK_MAP: Dict[str, uSwidLinkRel] = {
                "license": uSwidLinkRel.LICENSE,
                "compiler": uSwidLinkRel.COMPILER,
                "ancestor": uSwidLinkRel.ANCESTOR,
                "component": uSwidLinkRel.COMPONENT,
                "feature": uSwidLinkRel.FEATURE,
                "installation-media": uSwidLinkRel.INSTALLATIONMEDIA,
                "package-installer": uSwidLinkRel.PACKAGEINSTALLER,
                "parent": uSwidLinkRel.PARENT,
                "patches": uSwidLinkRel.PATCHES,
                "requires": uSwidLinkRel.REQUIRES,
                "see-also": uSwidLinkRel.SEE_ALSO,
                "supersedes": uSwidLinkRel.SUPERSEDES,
                "supplemental": uSwidLinkRel.SUPPLEMENTAL,
            }
            data[uSwidGlobalMap.REL] = LINK_MAP.get(link.rel, link.rel)
        return data

    def _save_entity(self, entity: uSwidEntity) -> Dict[uSwidGlobalMap, Any]:
        """exports a uSwidEntity CoSWID section"""

        data: Dict[uSwidGlobalMap, Any] = {}
        data[uSwidGlobalMap.ENTITY_NAME] = entity.name
        if entity.regid:
            data[uSwidGlobalMap.REG_ID] = entity.regid
        if len(entity.roles) == 1:
            data[uSwidGlobalMap.ROLE] = entity.roles[0]
        else:
            data[uSwidGlobalMap.ROLE] = entity.roles
        return data

    def _save_identity(self, identity: uSwidIdentity) -> bytes:
        """exports a uSwidIdentity CoSWID blob"""

        # general identity section
        data: Dict[uSwidGlobalMap, Any] = {}

        if identity.lang:
            data[uSwidGlobalMap.LANG] = identity.lang
        if identity.tag_id:
            try:
                data[uSwidGlobalMap.TAG_ID] = uuid.UUID(hex=identity.tag_id).bytes
            except (KeyError, ValueError):
                data[uSwidGlobalMap.TAG_ID] = identity.tag_id
        if identity.tag_version:
            tag_version = identity.tag_version
            if identity._auto_increment_tag_version:
                tag_version += 1
            data[uSwidGlobalMap.TAG_VERSION] = tag_version
        data[uSwidGlobalMap.CORPUS] = True  # is firmware installable?
        if identity.software_name:
            data[uSwidGlobalMap.SOFTWARE_NAME] = identity.software_name
        if not identity.software_version:
            raise NotSupportedError("a software_version MUST be provided")
        data[uSwidGlobalMap.SOFTWARE_VERSION] = identity.software_version
        if identity.version_scheme:
            data[uSwidGlobalMap.VERSION_SCHEME] = identity.version_scheme.value

        # metadata section
        metadata: Dict[uSwidGlobalMap, Any] = {
            uSwidGlobalMap.GENERATOR: identity.generator
        }
        if identity.summary:
            metadata[uSwidGlobalMap.SUMMARY] = identity.summary
        if identity.revision:
            metadata[uSwidGlobalMap.REVISION] = identity.revision
        if identity.edition:
            metadata[uSwidGlobalMap.PRODUCT] = identity.product
        if identity.edition:
            metadata[uSwidGlobalMap.EDITION] = identity.edition
        if identity.colloquial_version:
            metadata[uSwidGlobalMap.COLLOQUIAL_VERSION] = identity.colloquial_version
        if identity.persistent_id:
            metadata[uSwidGlobalMap.PERSISTENT_ID] = identity.persistent_id
        data[uSwidGlobalMap.SOFTWARE_META] = metadata

        # entities
        if not identity._entities:
            raise NotSupportedError("at least one entity MUST be provided")
        has_tag_creator = False
        for entity in identity._entities.values():
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
            self._save_entity(entity) for entity in identity._entities.values()
        ]
        data[uSwidGlobalMap.LINK] = [
            self._save_link(link) for link in identity._links.values()
        ]
        return cbor.dumps(data)

    def _load_link(self, link: uSwidLink, data: Dict[uSwidGlobalMap, Any]) -> None:
        """imports a uSwidLink CoSWID section"""

        # always a string
        link.href = data.get(uSwidGlobalMap.HREF)

        # rel can either be a uSwidLinkRel or a string
        rel_data = data.get(uSwidGlobalMap.REL)
        if isinstance(rel_data, str):
            link.rel = rel_data
        if isinstance(rel_data, uSwidLinkRel):
            LINK_MAP: Dict[uSwidLinkRel, str] = {
                uSwidLinkRel.LICENSE: "license",
                uSwidLinkRel.COMPILER: "compiler",
                uSwidLinkRel.ANCESTOR: "ancestor",
                uSwidLinkRel.COMPONENT: "component",
                uSwidLinkRel.FEATURE: "feature",
                uSwidLinkRel.INSTALLATIONMEDIA: "installation-media",
                uSwidLinkRel.PACKAGEINSTALLER: "package-installer",
                uSwidLinkRel.PARENT: "parent",
                uSwidLinkRel.PATCHES: "patches",
                uSwidLinkRel.REQUIRES: "requires",
                uSwidLinkRel.SEE_ALSO: "see-also",
                uSwidLinkRel.SUPERSEDES: "supersedes",
                uSwidLinkRel.SUPPLEMENTAL: "supplemental",
            }
            try:
                link.rel = LINK_MAP[rel_data]
            except KeyError as e:
                raise NotSupportedError(
                    "{} not supported from {}".format(
                        rel_data, ",".join(LINK_MAP.values())
                    )
                ) from e

    def _load_entity(
        self,
        entity: uSwidEntity,
        data: Dict[uSwidGlobalMap, Any],
    ) -> None:
        """imports a uSwidEntity CoSWID section"""

        entity.name = data.get(uSwidGlobalMap.ENTITY_NAME)
        entity.regid = data.get(uSwidGlobalMap.REG_ID, None)
        entity_roles = data.get(uSwidGlobalMap.ROLE, [])
        if isinstance(entity_roles, int):
            entity_roles = [entity_roles]
        for role in entity_roles:
            try:
                entity.roles.append(uSwidEntityRole(int(role)))
            except KeyError:
                print("ignoring invalid role of {}".format(role))
                continue

    def _load_identity(
        self, identity: uSwidIdentity, blob: bytes, offset: Optional[int] = 0
    ) -> int:
        """imports a uSwidIdentity CoSWID blob"""

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
        if isinstance(identity.tag_id, str):
            identity.tag_id = tag_id_bytes
        else:
            try:
                identity.tag_id = str(uuid.UUID(bytes=tag_id_bytes))
            except ValueError:
                identity.tag_id = tag_id_bytes.hex()

        identity.tag_version = data.get(uSwidGlobalMap.TAG_VERSION, 0)
        identity.software_name = data.get(uSwidGlobalMap.SOFTWARE_NAME, None)
        identity.software_version = data.get(uSwidGlobalMap.SOFTWARE_VERSION, None)
        identity.version_scheme = data.get(uSwidGlobalMap.VERSION_SCHEME, None)

        # optional metadata
        software_metas = data.get(uSwidGlobalMap.SOFTWARE_META, [])
        if isinstance(software_metas, dict):
            software_metas = [software_metas]
        for sm in software_metas:
            for key, value in sm.items():
                if key == uSwidGlobalMap.GENERATOR:
                    identity.generator = value
                elif key == uSwidGlobalMap.SUMMARY:
                    identity.summary = value
                elif key == uSwidGlobalMap.REVISION:
                    identity.revision = value
                elif key == uSwidGlobalMap.PRODUCT:
                    identity.product = value
                elif key == uSwidGlobalMap.EDITION:
                    identity.edition = value
                elif key == uSwidGlobalMap.COLLOQUIAL_VERSION:
                    identity.colloquial_version = value
                elif key == uSwidGlobalMap.PERSISTENT_ID:
                    identity.persistent_id = value

        # entities
        entities = data.get(uSwidGlobalMap.ENTITY, [])
        if isinstance(entities, dict):
            entities = [entities]
        for entity_data in entities:
            entity = uSwidEntity()
            self._load_entity(entity, entity_data)
            # skip invalid entries
            if not entity.roles:
                continue
            identity.add_entity(entity)

        # links
        for link_data in data.get(uSwidGlobalMap.LINK, []):
            link = uSwidLink()
            self._load_link(link, link_data)
            identity.add_link(link)

        identity._auto_increment_tag_version = True

        # number of bytes consumed, i.e. where the next CBOR blob is found
        return consumed
