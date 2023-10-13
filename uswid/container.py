#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2022 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=too-few-public-methods,protected-access

from typing import List, Optional, Generator, Dict

from .identity import uSwidIdentity
from .errors import NotSupportedError


class uSwidContainer:
    """Represents a uSWID container"""

    def __init__(self, identities: Optional[List[uSwidIdentity]] = None) -> None:
        """Initializes uSwidContainer"""
        self._identities: List[uSwidIdentity] = []
        if identities:
            for identity in identities:
                self.append(identity)

    def __iter__(self) -> Generator:
        for identity in self._identities:
            yield identity

    def depsolve(self) -> None:
        """Sets Link.identity using internally-resolvable SWID entries"""

        data: Dict[str, uSwidIdentity] = {}
        for identity in self._identities:
            if identity.tag_id:
                data[identity.tag_id] = identity
        for identity in self._identities:
            for link in identity.links:
                if link.href and link.href.startswith("swid:"):
                    link.identity = data.get(link.href[5:])

    def append(self, identity: uSwidIdentity) -> None:
        """Add an identity to the container"""
        self._identities.append(identity)

    def merge(self, identity: uSwidIdentity) -> Optional[uSwidIdentity]:
        """Merges one identity into another, returning None if the ``tag_id`` does not exist"""

        # just patching the default (and only) identity
        if not identity.tag_id:
            identity_default = self.get_default()
            if not identity_default:
                raise NotSupportedError(
                    "cannot merge file without a tag_id and no default identity"
                )
            identity_default.merge(identity)
            return identity_default

        # does this tag ID already exist?
        identity_old = self._get_by_id(identity.tag_id)
        if identity_old:
            identity_old.merge(identity)
            return identity_old

        # new to us
        self.append(identity)
        return None

    def get_default(self) -> Optional[uSwidIdentity]:
        """Returns the existing identity, or creates one if none already exist"""

        if len(self._identities) > 1:
            return None
        if not self._identities:
            self._identities.append(uSwidIdentity())
        return self._identities[0]

    def _get_by_id(self, tag_id: str) -> Optional[uSwidIdentity]:
        """Returns the identity that matches the tag ID"""

        for identity in self._identities:
            if identity.tag_id == tag_id:
                return identity
        return None

    def __repr__(self) -> str:
        return "uSwidContainer({})".format(self._identities)
