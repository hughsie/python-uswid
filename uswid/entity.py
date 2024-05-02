#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# pylint: disable=too-few-public-methods

from enum import IntEnum
from typing import List, Optional

from .problem import uSwidProblem


class uSwidEntityRole(IntEnum):
    """Represents an enumerated role"""

    TAG_CREATOR = 1
    SOFTWARE_CREATOR = 2
    AGGREGATOR = 3
    DISTRIBUTOR = 4
    LICENSOR = 5
    MAINTAINER = 6

    def __str__(self):
        return self.name.lower()


def _fix_vendor_id(dns: str) -> Optional[str]:

    if not dns:
        return None

    # remove protocol prefix
    if dns.startswith("http://") or dns.startswith("https://"):
        dns = dns.split("/")[2]

    # remove www
    if dns.startswith("www."):
        dns = dns[4:]

    # make sure not reverse DNS-style
    dns_prefix: str = dns.split(".")[0]
    if dns_prefix in ["com", "org", "tw", "uk", "eu"]:
        dns = ".".join(reversed(dns.split(".")))
    return dns


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

    def problems(self) -> List[uSwidProblem]:
        """Checks the entity for common problems"""

        problems: List[uSwidProblem] = []
        if not self.name:
            problems += [uSwidProblem("entity", "No name", since="0.4.7")]
        elif self.name.find("REDACTED") != -1:
            problems += [uSwidProblem("entity", "Redacted name", since="0.4.8")]
        if not self.regid:
            problems += [uSwidProblem("entity", "No regid", since="0.4.7")]
        elif self.regid.find("REDACTED") != -1:
            problems += [uSwidProblem("entity", "Redacted regid", since="0.4.8")]

        # should be DNS name
        elif self.regid != _fix_vendor_id(self.regid):
            problems += [
                uSwidProblem(
                    "entity",
                    f"Invalid regid {self.regid}, "
                    f"should be DNS name {_fix_vendor_id(self.regid)}",
                    since="0.4.7",
                )
            ]
        if not self.roles:
            problems += [uSwidProblem("entity", "No roles", since="0.4.7")]
        return problems

    def __repr__(self) -> str:
        role_str = ",".join([role.name for role in self.roles])
        return f'uSwidEntity(regid="{self.regid}",name="{self.name}",roles={role_str})'
