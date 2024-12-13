#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2022 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# pylint: disable=too-few-public-methods,protected-access

from typing import List, Optional, Generator, Dict

from .component import uSwidComponent
from .errors import NotSupportedError

from .vex_document import uSwidVexDocument
from .vex_statement import uSwidVexStatement


class uSwidContainer:
    """Represents a uSWID container"""

    def __init__(self, components: Optional[List[uSwidComponent]] = None) -> None:
        """Initializes uSwidContainer"""
        self._components: List[uSwidComponent] = []
        self.vex_documents: List[uSwidVexDocument] = []
        if components:
            for component in components:
                self.append(component)

    def __iter__(self) -> Generator:
        yield from self._components

    def __len__(self) -> int:
        return len(self._components)

    def __getitem__(self, item):
        return self._components[item]

    def depsolve(self) -> None:
        """Sets Link.component using internally-resolvable SWID entries"""

        data: Dict[str, uSwidComponent] = {}
        for component in self._components:
            if component.tag_id:
                data[component.tag_id] = component
        for component in self._components:
            for link in component.links:
                if link.href:
                    if link.href.startswith("swid:"):
                        link.component = data.get(link.href[5:])
                    if link.href.startswith("pkg:"):
                        link.component = data.get(link.href)

        # add VEX statements to components
        vex_by_hash: Dict[str, uSwidVexStatement] = {}
        vex_by_tag_version: Dict[str, uSwidVexStatement] = {}
        for vex_document in self.vex_documents:
            for vex_statement in vex_document.statements:
                for vex_product in vex_statement.products:
                    for vex_hash in vex_product.hashes:
                        if not vex_hash.value:
                            continue
                        vex_by_hash[vex_hash.value] = vex_statement
                    for vex_purl in vex_product.tag_ids:
                        vex_by_tag_version[
                            f"{vex_purl.name}:{vex_purl.version}"
                        ] = vex_statement
        for component in self._components:
            try:
                component.add_vex_statement(
                    vex_by_tag_version[
                        f"{component.tag_id}:{component.software_version}"
                    ]
                )
            except KeyError:
                pass
            for payload in component.payloads:
                for ihash in payload.hashes:
                    if not ihash.value:
                        continue
                    try:
                        component.add_vex_statement(vex_by_hash[ihash.value])
                    except KeyError:
                        pass

    def append(self, component: uSwidComponent) -> None:
        """Add an component to the container"""
        self._components.append(component)

    def add_vex_document(self, vex_document: uSwidVexDocument) -> None:
        """Add a VEX document"""
        self.vex_documents.append(vex_document)

    def merge(self, component: uSwidComponent) -> Optional[uSwidComponent]:
        """Merges one component into another, returning None if the ``tag_id`` does not exist"""

        # short cut because container is empty
        if not len(self):
            self.append(component)
            return None

        # just patching the default (and only) component
        if not component.tag_id:
            component_default = self.get_default()
            if not component_default:
                raise NotSupportedError(
                    "cannot merge file without a tag_id and no default component"
                )
            component_default.merge(component)
            return component_default

        # does this tag ID already exist?
        component_old = self.get_by_id(component.tag_id)
        if component_old:
            component_old.merge(component)
            return component_old

        # new to us
        self.append(component)
        return None

    def get_default(self) -> Optional[uSwidComponent]:
        """Returns the existing component, or creates one if none already exist"""

        if len(self._components) > 1:
            return None
        if not self._components:
            self._components.append(uSwidComponent())
        return self._components[0]

    def get_by_id(self, tag_id: str) -> Optional[uSwidComponent]:
        """Returns the component that matches the tag ID"""

        for component in self._components:
            if component.tag_id == tag_id:
                return component
        return None

    def get_by_link_href(self, url: str) -> Optional[uSwidComponent]:
        """Returns the component that matches the URL href"""

        for component in self._components:
            for link in component.links:
                if link.href == url:
                    return component
        return None

    def __repr__(self) -> str:
        return f"uSwidContainer({self._components})"
