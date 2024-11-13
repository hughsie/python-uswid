#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# pylint: disable=too-few-public-methods,protected-access

from typing import Optional

import os

from .container import uSwidContainer
from .format import uSwidFormatBase
from .component import uSwidComponent, uSwidComponentType
from .entity import uSwidEntityRole

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


class uSwidFormatPkgconfig(uSwidFormatBase):
    """INI file"""

    def __init__(self, filepath: Optional[str] = None) -> None:
        """Initializes uSwidFormatPkgconfig"""
        uSwidFormatBase.__init__(self, "pkgconfig")
        self.filepath: Optional[str] = filepath

    def load(self, blob: bytes, path: Optional[str] = None) -> uSwidContainer:
        component = uSwidComponent()
        self._load_component(component, blob)
        return uSwidContainer([component])

    def _load_component(self, component: uSwidComponent, blob: bytes) -> None:
        """Imports a pkg-conifg file as overrides to the uSwidComponent data"""

        # filename base is the ID
        if self.filepath:
            component.type = uSwidComponentType.LIBRARY
            component.tag_id = os.path.basename(self.filepath)
            if component.tag_id.endswith(".pc"):
                component.tag_id = component.tag_id[:-3]

        # read out properties
        for line in blob.decode().split("\n"):
            try:
                key, value = line.split(":", maxsplit=2)
            except ValueError:
                continue
            if key == "Name":
                component.software_name = value.strip()
                continue
            if key == "Description":
                component.summary = value.strip()
                continue
            if key == "Version":
                component.software_version = value.strip()
                continue
            if key == "AppstreamId":
                component.persistent_id = value.strip()
                continue
