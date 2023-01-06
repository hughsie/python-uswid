#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=too-few-public-methods,protected-access

from typing import Optional

import os

from .container import uSwidContainer
from .format import uSwidFormatBase
from .identity import uSwidIdentity
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

        uSwidFormatBase.__init__(self)
        self.filepath: Optional[str] = filepath

    def load(self, blob: bytes) -> uSwidContainer:

        identity = uSwidIdentity()
        self._load_identity(identity, blob)
        return uSwidContainer([identity])

    def _load_identity(self, identity: uSwidIdentity, blob: bytes) -> None:
        """imports a pkg-conifg file as overrides to the uSwidIdentity data"""

        # filename base is the ID
        if self.filepath:
            identity.tag_id = os.path.basename(self.filepath)
            if identity.tag_id.endswith(".pc"):
                identity.tag_id = identity.tag_id[:-3]

        # read out properties
        for line in blob.decode().split("\n"):
            try:
                key, value = line.split(":", maxsplit=2)
            except ValueError:
                continue
            if key == "Name":
                identity.software_name = value.strip()
                continue
            if key == "Description":
                identity.summary = value.strip()
                continue
            if key == "Version":
                identity.software_version = value.strip()
                continue
            if key == "AppstreamId":
                identity.persistent_id = value.strip()
                continue
