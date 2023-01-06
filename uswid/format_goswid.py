#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=too-few-public-methods,protected-access,too-many-boolean-expressions

from typing import Dict, Any

import json

from .container import uSwidContainer
from .format import uSwidFormatBase
from .errors import NotSupportedError
from .identity import (
    uSwidIdentity,
    _VERSION_SCHEME_TO_STRING,
    _VERSION_SCHEME_FROM_STRING,
)
from .entity import uSwidEntity
from .link import uSwidLink
from .format_swid import _ENTITY_MAP_FROM_XML, _ENTITY_MAP_TO_XML


class uSwidFormatGoswid(uSwidFormatBase):
    """goSWID file"""

    def __init__(self) -> None:

        uSwidFormatBase.__init__(self)

    def load(self, blob: bytes) -> uSwidContainer:

        try:
            data = json.loads(blob)
        except json.decoder.JSONDecodeError as e:
            raise NotSupportedError("invalid GoSWID: {}".format(e)) from e
        container = uSwidContainer()
        for identity_json in data:
            identity = uSwidIdentity()
            self._load_identity(identity, identity_json)
            container.merge(identity)
        return container

    def save(self, container: uSwidContainer) -> bytes:
        root = []
        for identity in container:
            root.append(self._save_identity(identity))
        return json.dumps(root, indent=2).encode()

    def _save_link(self, link: uSwidLink) -> Dict[str, str]:
        """exports a uSwidLink goSWID section"""

        node: Dict[str, str] = {}
        if link.href:
            node["href"] = link.href
        if link.rel:
            node["rel"] = link.rel
        return node

    def _save_entity(self, entity: uSwidEntity) -> Dict[str, Any]:
        """exports a uSwidEntity goSWID section"""

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
                    "{} not supported from {}".format(
                        role, ",".join(_ENTITY_MAP_TO_XML.values())
                    )
                ) from e
        # use string if only one role
        if len(roles) == 1:
            node["role"] = roles[0]
        else:
            node["role"] = roles
        return node

    def _save_identity(self, identity: uSwidIdentity) -> bytes:
        """exports a uSwidIdentity goSWID blob"""

        # identity
        root: Dict[str, Any] = {}
        if identity.lang:
            root["lang"] = identity.lang
        if identity.tag_id:
            root["tag-id"] = identity.tag_id
        if identity.tag_version:
            root["tag-version"] = identity.tag_version
        if identity.software_name:
            root["software-name"] = identity.software_name
        if identity.software_version:
            root["software-version"] = identity.software_version
        if identity.version_scheme:
            root["version-scheme"] = _VERSION_SCHEME_TO_STRING[identity.version_scheme]

        # optional metadata
        if (
            identity.summary
            or identity.revision
            or identity.product
            or identity.edition
            or identity.colloquial_version
            or identity.persistent_id
        ):
            node: Dict[str, str] = {}
            if identity.summary:
                node["summary"] = identity.summary
            if identity.revision:
                node["revision"] = identity.revision
            if identity.product:
                node["product"] = identity.product
            if identity.edition:
                node["edition"] = identity.edition
            if identity.colloquial_version:
                node["colloquial-version"] = identity.colloquial_version
            if identity.persistent_id:
                node["persistent-id"] = identity.persistent_id
            # the CoSWID spec says: 'software-meta => one-or-more'
            root["software-meta"] = [node]

        # entities
        if identity.entities:
            root["entity"] = []
            for entity in identity.entities:
                root["entity"].append(self._save_entity(entity))

        # links
        if identity.links:
            root["link"] = []
            for link in identity.links:
                root["link"].append(self._save_link(link))

        # success
        return json.dumps(root, indent=2).encode("utf-8")

    def _load_link(self, link: uSwidLink, node: Dict[str, str]) -> None:
        """imports a uSwidLink goSWID section"""

        link.href = node.get("href")
        link.rel = node.get("rel")

    def _load_entity(
        self,
        entity: uSwidEntity,
        node: Dict[str, str],
    ) -> None:
        """imports a uSwidEntity goSWID section"""

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
                    "{} not supported from {}".format(
                        role_str, ",".join(_ENTITY_MAP_FROM_XML)
                    )
                ) from e

    def _load_identity(self, identity: uSwidIdentity, blob: bytes) -> None:
        """imports a uSwidIdentity goSWID blob"""

        try:
            data: Dict[str, Any] = json.loads(blob)
        except json.decoder.JSONDecodeError as e:
            raise NotSupportedError("invalid goSWID: {}".format(e)) from e

        # identity
        identity.tag_id = data.get("tag-id")
        tag_version = data.get("tag-version")
        if tag_version:
            identity.tag_version = int(tag_version)
        identity.software_name = data.get("software-name")
        identity.software_version = data.get("software-version")
        version_scheme = data.get("version-scheme")
        if version_scheme:
            identity.version_scheme = _VERSION_SCHEME_FROM_STRING[version_scheme]

        # optional metadata
        for meta in data["software-meta"]:
            for attr_name, attrib_name in [
                ("summary", "summary"),
                ("revision", "revision"),
                ("product", "product"),
                ("edition", "edition"),
                ("colloquial-version", "colloquial_version"),
            ]:
                if attr_name in meta:
                    setattr(identity, attrib_name, meta[attr_name])

        # entities
        try:
            for node in data["entity"]:
                entity = uSwidEntity()
                self._load_entity(entity, node)
                identity.add_entity(entity)
        except KeyError:
            pass

        # links
        try:
            for node in data["links"]:
                link = uSwidLink()
                self._load_link(link, node)
                identity.add_link(link)
        except KeyError:
            pass
