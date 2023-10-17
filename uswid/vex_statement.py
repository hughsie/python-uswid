#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2023 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=too-few-public-methods,protected-access

from typing import Optional, Any, Dict, List, TYPE_CHECKING

from enum import Enum

from .vex_product import uSwidVexProduct
from .entity import uSwidEntity

if TYPE_CHECKING:
    from .vex_document import uSwidVexDocument


class uSwidVexStatementStatus(Enum):
    """Represents an enumerated status label"""

    UNKNOWN = "unknown"
    NOT_AFFECTED = "not_affected"
    AFFECTED = "affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"

    @classmethod
    def from_string(cls, status: str) -> "uSwidVexStatementStatus":
        """Creates a uSwidVexStatementStatus from a string identifier"""
        return cls(
            {
                "not_affected": uSwidVexStatementStatus.NOT_AFFECTED,
                "affected": uSwidVexStatementStatus.AFFECTED,
                "fixed": uSwidVexStatementStatus.FIXED,
                "under_investigation": uSwidVexStatementStatus.UNDER_INVESTIGATION,
            }[status.replace("-", "_").lower()]
        )


class uSwidVexStatementJustification(Enum):
    """Represents an enumerated status justification"""

    UNKNOWN = "unknown"
    COMPONENT_NOT_PRESENT = "component_not_present"
    VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present"
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY = (
        "vulnerable_code_cannot_be_controlled_by_adversary"
    )
    INLINE_MITIGATIONS_ALREADY_EXIST = "inline_mitigations_already_exist"

    @classmethod
    def from_string(cls, status: str) -> "uSwidVexStatementJustification":
        """Creates a uSwidVexStatementStatus from a string identifier"""
        return cls(
            {
                "component_not_present": uSwidVexStatementJustification.COMPONENT_NOT_PRESENT,
                "vulnerable_code_not_present": uSwidVexStatementJustification.VULNERABLE_CODE_NOT_PRESENT,
                "vulnerable_code_not_in_execute_path": uSwidVexStatementJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
                "vulnerable_code_cannot_be_controlled_by_adversary": uSwidVexStatementJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY,
                "inline_mitigations_already_exist": uSwidVexStatementJustification.INLINE_MITIGATIONS_ALREADY_EXIST,
            }[status.replace("-", "_").lower()]
        )


class uSwidVexStatement:
    """Represents a VEX statement"""

    def __init__(self):

        self._document: Optional[uSwidVexDocument] = None

        """Initializes uSwidVexDocument"""
        self.vulnerability_name: Optional[str] = None
        """Vulnerability name, e.g. CVE-2022-40982"""
        self.status: Optional[uSwidVexStatementStatus] = None
        """Status"""
        self.justification: Optional[uSwidVexStatementJustification] = None
        """Justification"""
        self.impact_statement: Optional[str] = None
        """Impact statement"""
        self.products: List[uSwidVexProduct] = []
        """Affected products"""

    @property
    def trusted_entity(self) -> Optional[uSwidEntity]:
        """The entity that produced the document that contained this statement"""
        if not self._document:
            return None
        return self._document.trusted_entity

    def _load_csa2(self, data: Dict[str, Any]) -> None:

        try:
            self.vulnerability_name = data["cve"]
        except KeyError:
            pass
        try:
            self.status = uSwidVexStatementStatus.from_string(data["product_status"][0])
        except KeyError:
            pass
        try:
            self.impact_statement = data["remediations"][0]["details"]
        except KeyError:
            pass

    def _load_openvex(self, data: Dict[str, Any]) -> None:

        self.vulnerability_name = data["vulnerability"]["name"]
        self.status = uSwidVexStatementStatus.from_string(data["status"])
        try:
            self.justification = uSwidVexStatementJustification.from_string(
                data["justification"]
            )
        except KeyError:
            pass
        try:
            self.impact_statement = data.get("impact_statement")
        except KeyError:
            pass
        try:
            for product_data in data["products"]:
                product = uSwidVexProduct()
                product._load_openvex(product_data)
                self.products.append(product)
        except KeyError:
            pass

    def __repr__(self) -> str:
        tmp = (
            f'uSwidVexStatement(vulnerability_name="{self.vulnerability_name}",'
            + f'status="{self.status}",'
            + f'justification="{self.justification}",'
            + f'impact_statement="{self.impact_statement}")'
        )
        if self.products:
            tmp += ":"
            tmp += "\n{}".format(
                "\n".join([f"   - {str(e)}" for e in self.products]),
            )
        return tmp
