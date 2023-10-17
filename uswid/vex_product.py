#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2023 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=too-few-public-methods

from typing import Any, Dict, List

from .hash import uSwidHash, uSwidHashAlg

from .purl import uSwidPurl


class uSwidVexProduct:
    """Represents a VEX product"""

    def __init__(self):
        """Initializes uSwidVexDocument"""
        self.tag_ids: List[uSwidPurl] = []
        """SWID identifiers"""
        self.hashes: List[uSwidHash] = []
        """Hashes of affected components"""

    def _load_openvex(self, data: Dict[str, Any]) -> None:

        self.tag_ids.append(uSwidPurl(data["@id"]))
        try:
            self.tag_ids.append(uSwidPurl(data["identifiers"]["purl"]))
        except KeyError:
            pass
        try:
            for alg_id, value in data["hashes"].items():
                self.hashes.append(
                    uSwidHash(alg_id=uSwidHashAlg.from_string(alg_id), value=value)
                )
        except KeyError:
            pass

    def __repr__(self) -> str:
        tmp = f'uSwidVexProduct(tag_ids="{self.tag_ids}")'
        if self.hashes:
            tmp += ":"
            tmp += "\n{}".format(
                "\n".join([f"     - {str(e)}" for e in self.hashes]),
            )
        return tmp
