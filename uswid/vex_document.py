#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2023 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=too-few-public-methods,protected-access

from typing import Optional, Any, Dict, List

from datetime import datetime

from .entity import uSwidEntity
from .vex_statement import uSwidVexStatement


class uSwidVexDocument:
    """Represents a VEX document that can contain multiple statements"""

    def __init__(self, data: Optional[Dict[str, Any]] = None):
        """Initializes uSwidVexDocument, optionally with JSON data"""
        self.id: Optional[str] = None
        """Document ID"""
        self.author: Optional[str] = None
        """VEX author, typically an email address"""
        self.date: Optional[datetime] = None
        """Timestamp"""
        self.version: Optional[str] = None
        """VEX document version"""
        self._statements: List[uSwidVexStatement] = []
        self.trusted_entity: Optional[uSwidEntity] = None
        """
        The entity that produced this document.
        NOTE: This is not necessarily the vex document author, this is explitly the vendor that
        uploaded the VEX document
        """

        # optional
        if data:
            self.load(data)

    @property
    def statements(self) -> List[uSwidVexStatement]:
        """VEX statements"""
        return self._statements

    def add_statement(self, statement: uSwidVexStatement) -> None:
        """Add a statement to the document"""
        statement._document = self
        self._statements.append(statement)

    def load(self, data: Dict[str, Any]) -> None:
        """Load from a JSON dictionary"""

        # OpenVEX
        try:
            self.id = data["@id"]
        except KeyError:
            pass
        try:
            self.author = data["author"]
        except KeyError:
            pass
        try:
            self.version = data["version"]
        except KeyError:
            pass
        try:
            self.date = datetime.fromisoformat(data["timestamp"])
        except KeyError:
            pass
        try:
            for statement_data in data["statements"]:
                vex_statement = uSwidVexStatement()
                vex_statement._load_openvex(statement_data)
                self.add_statement(vex_statement)
        except KeyError:
            pass

        # CSAF 2.0
        try:
            self.id = data["document"]["tracking"]["id"]
        except KeyError:
            pass
        try:
            self.version = data["document"]["tracking"]["version"]
        except KeyError:
            pass
        try:
            self.date = datetime.fromisoformat(
                data["document"]["tracking"]["current_release_date"]
            )
        except KeyError:
            pass
        try:
            for statement_data in data["vulnerabilities"]:
                vex_statement = uSwidVexStatement()
                vex_statement._load_csa2(statement_data)
                self.add_statement(vex_statement)
        except KeyError:
            pass

    def __repr__(self) -> str:
        tmp = (
            f'uSwidVexDocument(id="{self.id}",'
            + f'author="{self.author}",'
            + f'date="{self.date}",'
            + f'version="{self.version}")'
        )
        if self.statements:
            tmp += ":"
            tmp += "\n{}".format(
                "\n".join([f" - {str(e)}" for e in self.statements]),
            )
        return tmp
