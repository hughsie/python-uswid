#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=too-few-public-methods

from enum import IntEnum
from typing import List, Optional


class uSwidEntityRole(IntEnum):
    """Represents an enumerated role"""

    TAG_CREATOR = 1
    SOFTWARE_CREATOR = 2
    AGGREGATOR = 3
    DISTRIBUTOR = 4
    LICENSOR = 5
    MAINTAINER = 6


class uSwidEntity:
    """Represents a SWID entity"""

    def __init__(
        self,
        name: Optional[str] = None,
        regid: Optional[str] = None,
        roles: Optional[List[uSwidEntityRole]] = None,
    ):
        """Initializes uSwidEntity"""
        self.name: Optional[str] = name
        """Name"""
        self.regid: Optional[str] = regid
        """Registration ID, e.g. com.intel"""
        self.roles: List[uSwidEntityRole] = []
        """Role of the entity, e.g. ``uSwidEntityRole.MAINTAINER``"""
        if roles:
            self.roles.extend(roles)

    def __repr__(self) -> str:
        role_str = ",".join([role.name for role in self.roles])
        return f'uSwidEntity(regid="{self.regid}",name="{self.name}",roles={role_str})'
