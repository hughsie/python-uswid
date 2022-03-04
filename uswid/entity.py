#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=too-few-public-methods

from enum import IntEnum
from typing import Dict, List, Any, Optional
import configparser

from lxml import etree as ET

from .errors import NotSupportedError
from .enums import uSwidGlobalMap


class uSwidEntityRole(IntEnum):
    TAG_CREATOR = 1
    SOFTWARE_CREATOR = 2
    AGGREGATOR = 3
    DISTRIBUTOR = 4
    LICENSOR = 5
    MAINTAINER = 6


class uSwidEntity:
    """represents a SWID entity"""

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
    _ENTITY_MAP_FROM_XML = {
        "tagCreator": uSwidEntityRole.TAG_CREATOR,
        "softwareCreator": uSwidEntityRole.SOFTWARE_CREATOR,
        "aggregator": uSwidEntityRole.AGGREGATOR,
        "distributor": uSwidEntityRole.DISTRIBUTOR,
        "licensor": uSwidEntityRole.LICENSOR,
        "maintainer": uSwidEntityRole.MAINTAINER,
    }
    _ENTITY_MAP_TO_XML = {
        uSwidEntityRole.TAG_CREATOR: "tagCreator",
        uSwidEntityRole.SOFTWARE_CREATOR: "softwareCreator",
        uSwidEntityRole.AGGREGATOR: "aggregator",
        uSwidEntityRole.DISTRIBUTOR: "distributor",
        uSwidEntityRole.LICENSOR: "licensor",
        uSwidEntityRole.MAINTAINER: "maintainer",
    }

    def __init__(
        self,
        name: Optional[str] = None,
        regid: Optional[str] = None,
        roles: Optional[List[uSwidEntityRole]] = None,
    ):

        self.name: Optional[str] = name
        self.regid: Optional[str] = regid
        self.roles: List[uSwidEntityRole] = []
        if roles:
            self.roles.extend(roles)

    def _import_xml(self, node: ET.SubElement) -> None:
        """imports a uSwidEntity XML blob"""

        self.name = node.get("name")
        self.regid = node.get("regid", None)
        for role_str in node.get("role", "").split(" "):
            try:
                self.roles.append(self._ENTITY_MAP_FROM_XML[role_str])
            except KeyError as e:
                raise NotSupportedError(
                    "{} not supported from {}".format(
                        role_str, ",".join(self._ENTITY_MAP_FROM_XML)
                    )
                ) from e

    def _export_xml(self, root: ET.Element) -> None:
        """exports a uSwidEntity XML blob"""

        node = ET.SubElement(root, "Entity")
        if self.name:
            node.set("name", self.name)
        if self.regid:
            node.set("regid", self.regid)
        roles: List[str] = []
        for role in self.roles:
            try:
                roles.append(self._ENTITY_MAP_TO_XML[role])
            except KeyError as e:
                raise NotSupportedError(
                    "{} not supported from {}".format(
                        role, ",".join(self._ENTITY_MAP_TO_XML)
                    )
                ) from e
        if roles:
            node.set("role", " ".join(roles))

    def _import_data(self, data: Dict[uSwidGlobalMap, Any]) -> None:
        """imports a uSwidEntity data section"""

        self.name = data.get(uSwidGlobalMap.SOFTWARE_NAME)
        self.regid = data.get(uSwidGlobalMap.REG_ID, None)
        for role in data.get(uSwidGlobalMap.ROLE, []):
            try:
                self.roles.append(uSwidEntityRole(int(role)))
            except KeyError:
                print("ignoring invalid role of {}".format(role))
                continue

    def _import_ini(
        self, data: configparser.SectionProxy, role_hint: Optional[str] = None
    ) -> None:
        """imports a uSwidEntity INI section"""

        if role_hint:
            try:
                self.roles.append(self._ENTITY_MAP_FROM_INI[role_hint.split(":")[1]])
            except (KeyError, TypeError, IndexError):
                pass
        for key, value in data.items():
            if key == "name":
                self.name = value
            elif key == "regid":
                self.regid = value
            elif key == "extra-roles":
                for role_str in value.split(","):
                    try:
                        self.roles.append(self._ENTITY_MAP_FROM_INI[role_str])
                    except KeyError as e:
                        raise NotSupportedError(
                            "{} not supported from {}".format(
                                role_str, ",".join(self._ENTITY_MAP_FROM_INI)
                            )
                        ) from e
            else:
                print("unknown key {} found in ini file!".format(key))
        if not self.name:
            raise NotSupportedError("all entities MUST have a name")
        if not self.roles:
            raise NotSupportedError(
                "entity {} MUST have at least one role".format(self.name)
            )

    def _export_ini(self) -> Dict[str, Any]:
        """exports a uSwidEntity INI section"""

        data: Dict[str, Any] = {}
        if self.name:
            data["name"] = self.name
        if self.regid:
            data["regid"] = self.regid
        extra_roles: List[str] = []
        for role in self.roles:
            if role == uSwidEntityRole.TAG_CREATOR:
                continue
            extra_roles.append(self._ENTITY_MAP_TO_INI[role])
        if extra_roles:
            data["extra-roles"] = ",".join(extra_roles)
        return data

    def _export_bytes(self) -> Dict[uSwidGlobalMap, Any]:
        """exports a uSwidEntity CBOR blob"""

        data: Dict[uSwidGlobalMap, Any] = {}
        data[uSwidGlobalMap.SOFTWARE_NAME] = self.name
        if self.regid:
            data[uSwidGlobalMap.REG_ID] = self.regid
        data[uSwidGlobalMap.ROLE] = self.roles
        return data

    def __repr__(self) -> str:
        return "uSwidEntity({},{}->{})".format(
            self.name, self.regid, ",".join([role.name for role in self.roles])
        )
