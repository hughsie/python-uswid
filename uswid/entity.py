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

        ENTITY_MAP = {
            "tagCreator": uSwidEntityRole.TAG_CREATOR,
            "softwareCreator": uSwidEntityRole.SOFTWARE_CREATOR,
            "aggregator": uSwidEntityRole.AGGREGATOR,
            "distributor": uSwidEntityRole.DISTRIBUTOR,
            "licensor": uSwidEntityRole.LICENSOR,
            "maintainer": uSwidEntityRole.MAINTAINER,
        }
        self.name = node.get("name")
        self.regid = node.get("regid", None)
        for role_str in node.get("role", "").split(" "):
            try:
                self.roles.append(ENTITY_MAP[role_str])
            except KeyError as e:
                raise NotSupportedError(
                    "{} not supported from {}".format(role_str, ",".join(ENTITY_MAP))
                ) from e

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

        ENTITY_MAP = {
            "TagCreator": uSwidEntityRole.TAG_CREATOR,
            "SoftwareCreator": uSwidEntityRole.SOFTWARE_CREATOR,
            "Aggregator": uSwidEntityRole.AGGREGATOR,
            "Distributor": uSwidEntityRole.DISTRIBUTOR,
            "Licensor": uSwidEntityRole.LICENSOR,
            "Maintainer": uSwidEntityRole.MAINTAINER,
        }
        if role_hint:
            try:
                self.roles.append(ENTITY_MAP[role_hint.split(":")[1]])
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
                        self.roles.append(ENTITY_MAP[role_str])
                    except KeyError as e:
                        raise NotSupportedError(
                            "{} not supported from {}".format(
                                role_str, ",".join(ENTITY_MAP)
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
