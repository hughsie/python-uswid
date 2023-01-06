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

    def __repr__(self) -> str:
        return "uSwidEntity({},{}->{})".format(
            self.name, self.regid, ",".join([role.name for role in self.roles])
        )
