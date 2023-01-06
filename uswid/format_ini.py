#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=too-few-public-methods,protected-access

from typing import Dict, List, Any, Optional, Union

import configparser
import io

from .container import uSwidContainer
from .format import uSwidFormatBase
from .errors import NotSupportedError
from .identity import (
    uSwidIdentity,
    _VERSION_SCHEME_TO_STRING,
    _VERSION_SCHEME_FROM_STRING,
)
from .entity import uSwidEntity, uSwidEntityRole
from .link import uSwidLink

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

        uSwidFormatBase.__init__(self)

    def load(self, blob: bytes) -> uSwidContainer:

        identity = uSwidIdentity()
        self._load_identity(identity, blob)
        return uSwidContainer([identity])

    def save(self, container: uSwidContainer) -> bytes:

        identity = container.get_default()
        if not identity:
            raise NotSupportedError("cannot save when no default identity")
        return self._save_identity(identity)

    def _save_link(self, link: uSwidLink) -> Dict[str, Any]:
        """exports a uSwidLink INI section"""

        data: Dict[str, Any] = {}
        if link.rel:
            data["rel"] = link.rel
        if link.href:
            data["href"] = link.href
        return data

    def _save_entity(self, entity: uSwidEntity) -> Dict[str, Any]:
        """exports a uSwidEntity INI section"""

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

    def _save_identity(self, identity: uSwidIdentity) -> bytes:

        config = configparser.ConfigParser()

        # main section
        main = {}
        if identity.tag_id:
            main["tag-id"] = identity.tag_id
        if identity.tag_version:
            main["tag-version"] = str(identity.tag_version)
        if identity.software_name:
            main["software-name"] = identity.software_name
        if identity.software_version:
            main["software-version"] = identity.software_version
        if identity.version_scheme:
            main["version-scheme"] = _VERSION_SCHEME_TO_STRING[identity.version_scheme]
        if identity.summary:
            main["summary"] = identity.summary
        if identity.revision:
            main["revision"] = identity.revision
        if identity.product:
            main["product"] = identity.product
        if identity.edition:
            main["edition"] = identity.edition
        if identity.colloquial_version:
            main["colloquial-version"] = identity.colloquial_version
        if identity.persistent_id:
            main["persistent-id"] = identity.persistent_id
        config["uSWID"] = main

        # entity
        if identity.entities:
            config["uSWID-Entity:TagCreator"] = self._save_entity(identity.entities[0])

        # link
        if identity.links:
            config["uSWID-Link"] = self._save_link(identity.links[0])

        # as string
        with io.StringIO() as f:
            config.write(f)
            f.seek(0)
            return f.read().encode()

    def _load_link(
        self, link: uSwidLink, data: Union[configparser.SectionProxy, Dict[str, str]]
    ) -> None:
        """imports a uSwidLink INI section"""

        for key, value in data.items():
            if key == "href":
                link.href = value
            elif key == "rel":
                link.rel = value
            else:
                print("unknown key {} found in ini file!".format(key))
        if not link.href:
            raise NotSupportedError("all entities MUST have a href")

    def _load_entity(
        self,
        entity: uSwidEntity,
        data: Union[configparser.SectionProxy, Dict[str, str]],
        role_hint: Optional[str] = None,
    ) -> None:
        """imports a uSwidEntity INI section"""

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
                print("unknown key {} found in ini file!".format(key))
        if not entity.name:
            raise NotSupportedError("all entities MUST have a name")
        if not entity.roles:
            raise NotSupportedError(
                "entity {} MUST have at least one role".format(entity.name)
            )

    def _load_identity(self, identity: uSwidIdentity, blob: bytes) -> None:

        config = configparser.ConfigParser()
        config.read_string(blob.decode())
        for group in config.sections():
            if group == "uSWID":
                for key, value in config[group].items():
                    if key == "tag-id":
                        identity.tag_id = value
                    elif key == "tag-version":
                        identity.tag_version = int(value)
                        identity._auto_increment_tag_version = False
                    elif key == "software-name":
                        identity.software_name = value
                    elif key == "software-version":
                        identity.software_version = value
                    elif key == "version-scheme":
                        identity.version_scheme = _VERSION_SCHEME_FROM_STRING[value]
                    elif key == "summary":
                        identity.summary = value
                    elif key == "revision":
                        identity.revision = value
                    elif key == "product":
                        identity.product = value
                    elif key == "edition":
                        identity.edition = value
                    elif key == "colloquial-version":
                        identity.colloquial_version = value
                    elif key == "persistent-id":
                        identity.persistent_id = value
                    else:
                        print("unknown key {} found in ini file!".format(key))
            if group.startswith("uSWID-Entity:"):
                entity = uSwidEntity()
                self._load_entity(entity, config[group], role_hint=group)
                identity.add_entity(entity)
            if group.startswith("uSWID-Link"):
                link = uSwidLink()
                self._load_link(link, config[group])
                identity.add_link(link)
