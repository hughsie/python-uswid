#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent

import os
import hashlib
from copy import deepcopy
from collections import defaultdict
from typing import Optional

from .component import uSwidComponent, uSwidComponentType
from .container import uSwidContainer
from .entity import uSwidEntity, uSwidEntityRole
from .format import uSwidFormatBase
from .link import uSwidLink, uSwidLinkRel
from .errors import NotSupportedError

# from .payload import uSwidPayload
from .purl import uSwidPurl
from .vcs import uSwidVcs


class uSwidFormatInf(uSwidFormatBase):
    """EDK2 inf file"""

    def __init__(self) -> None:
        """Initializes uSwidFormatInf"""
        uSwidFormatBase.__init__(self, "inf")  # type:ignore[call-arg]
        self._inf_data: dict[str, list[str]] = defaultdict(list)
        self._inf_defines: dict[str, str] = {}
        self._spdx_ids: list[str] = []

    def _add_license(self, spdx_id: str) -> None:

        if spdx_id not in self._spdx_ids:
            self._spdx_ids.append(spdx_id)

    def _get_value_from_data(self, group: str, key: str) -> str:

        for kv in self._inf_data[group]:
            if kv.startswith(key + "="):
                return kv[len(key) + 1 :]
        raise KeyError(f"no {key}")

    def incorporate(self, container: uSwidContainer, component: uSwidComponent) -> None:

        # this is defined with a sbom.cdx.json
        component_parent = container.get_by_id("pkg:edk2", fuzzy=True)
        if not component_parent:
            return

        # use the parent PURL as a template
        if component_parent.purl:
            component.purl = deepcopy(component_parent.purl)
            component.purl.subpath = component.software_name

            # fix up the links too
            for link in component.links:
                if link.rel != uSwidLinkRel.COMPONENT:
                    continue
                purl = uSwidPurl(link.href)
                purl.version = component_parent.purl.version
                component.remove_link(link)
                link.href = str(purl)
                component.add_link(link)

        # add a dep to the main EDK package
        component_parent.add_link(
            uSwidLink(rel=uSwidLinkRel.COMPONENT, href=component.tag_id)
        )

        # use the parent component supplier
        entity_creator = component_parent.get_entity_by_role(
            uSwidEntityRole.SOFTWARE_CREATOR
        )
        if entity_creator:
            component.add_entity(entity_creator)

        # use the parent VCS link if it doesn't already exist
        link_vcs = component.get_link_by_rel(uSwidLinkRel.SEE_ALSO)
        if not link_vcs:
            link_vcs_parent = component_parent.get_link_by_rel(uSwidLinkRel.SEE_ALSO)
            if link_vcs_parent:
                component.add_link(link_vcs_parent)

        # build CPE
        if component_parent.purl:
            component.cpe = f"cpe:2.3:a:tianocore:edk2:{component_parent.purl.version}:*:*:*:*:*:*:{component.software_name}"

    def load(self, blob: bytes, path: Optional[str] = None) -> uSwidContainer:

        component = uSwidComponent()

        group = None
        for cnt, line in enumerate(blob.decode().replace("\r", "").split("\n")):

            # description
            if cnt == 1 and line.startswith("#  "):
                component.summary = line[3:].strip()

            # has license?
            lineidx = line.find("SPDX-License-Identifier: ")
            if lineidx != -1:
                self._add_license(line[lineidx + 25 :])

            # remove comments
            lineidx = line.find("#")
            if lineidx != -1:
                line = line[:lineidx]

            # group
            if line.startswith("[") and line.endswith("]"):
                group = line[1:-1]
                continue

            # empty line
            if not line.strip():
                continue

            # string value
            if group and line.startswith("  "):
                value_new = line[2:].strip()
                if value_new.startswith("DEFINE "):
                    key, value = value_new[7:].split("=", maxsplit=1)
                    self._inf_defines[key.strip()] = value.strip()
                else:
                    self._inf_data[group].append(value_new.replace(" ", ""))

        # all modules should have this
        try:
            component.software_name = self._get_value_from_data("Defines", "BASE_NAME")
        except KeyError as e:
            raise NotSupportedError("no BASE_NAME in [Defines]") from e

        # map from MODULE_TYPE to uSwidComponentType
        try:
            component.type = {
                "BASE": uSwidComponentType.LIBRARY,
                "DXE_CORE": uSwidComponentType.LIBRARY,
                "DXE_DRIVER": uSwidComponentType.LIBRARY,
                "DXE_RUNTIME_DRIVER": uSwidComponentType.LIBRARY,
                "DXE_SMM_DRIVER": uSwidComponentType.LIBRARY,
                "HOST_APPLICATION": uSwidComponentType.APPLICATION,
                "MM_CORE_STANDALONE": uSwidComponentType.LIBRARY,
                "MM_STANDALONE": uSwidComponentType.LIBRARY,
                "PEI_CORE": uSwidComponentType.LIBRARY,
                "PEIM": uSwidComponentType.LIBRARY,
                "SEC": uSwidComponentType.LIBRARY,
                "SMM_CORE": uSwidComponentType.LIBRARY,
                "UEFI_APPLICATION": uSwidComponentType.APPLICATION,
                "UEFI_DRIVER": uSwidComponentType.LIBRARY,
                "USER_DEFINED": uSwidComponentType.LIBRARY,
            }[self._get_value_from_data("Defines", "MODULE_TYPE")]
        except KeyError:
            component.type = uSwidComponentType.FIRMWARE

        # ugh, see SecurityPkg/Tcg/Tcg2Smm/Tcg2MmDependencyDxe.inf
        try:
            component.software_version = self._get_value_from_data(
                "Defines", "VERSION_STRING"
            )
        except KeyError:
            component.software_version = "NOASSERTION"

        # get the source hash and licence from each source file
        colloquial_version = hashlib.sha256()
        for fn in self._inf_data.get("Sources", []):

            # e.g. CryptoPkg/Library/OpensslLib/OpensslLib.inf
            for key, value in self._inf_defines.items():
                fn = fn.replace(f"$({key})", value)

            # e.g. MdePkg/Library/StackCheckLib/StackCheckLibStaticInit.inf
            if fn.endswith("|GCC"):
                fn = fn[:-4]
            if fn.endswith("|MSFT"):
                fn = fn[:-5]

            if not path:
                continue
            with open(os.path.join(os.path.dirname(path), fn), "rb") as f:
                buf = f.read()
            colloquial_version.update(buf)
            for line in buf.decode(errors="ignore").split("\n"):
                lineidx = line.find("SPDX-License-Identifier: ")
                if lineidx != -1:
                    self._add_license(line[lineidx + 25 :].strip())
            # payload: uSwidPayload = uSwidPayload(name=fn)
            # payload.ensure_from_filename(
            #    os.path.join(os.path.dirname(path), fn)
            # )
            # component.add_payload(payload)

        # add all licenses
        for spdx_id in self._spdx_ids:
            component.add_link(uSwidLink(rel=uSwidLinkRel.LICENSE, spdx_id=spdx_id))

        # of all of the sources, in the order specified in the .inf file
        component.colloquial_version = colloquial_version.hexdigest()

        # add each dep -- but without a version defined
        for subpath in self._inf_data.get("LibraryClasses", []):
            purl = uSwidPurl("pkg:github/tianocore/edk2")
            purl.subpath = subpath
            component.add_link(uSwidLink(rel=uSwidLinkRel.COMPONENT, href=str(purl)))

        # GUID, not sure if useful...
        try:
            component.persistent_id = self._get_value_from_data(
                "Defines", "FILE_GUID"
            ).lower()
        except KeyError:
            pass

        # add per-module authors
        if path:
            vcs = uSwidVcs(filepath=path)
            for author in vcs.get_authors(relpath="."):
                component.add_entity(
                    uSwidEntity(roles=[uSwidEntityRole.MAINTAINER], name=author)
                )
            for sbom_author in vcs.get_sbom_authors():
                component.add_entity(
                    uSwidEntity(roles=[uSwidEntityRole.TAG_CREATOR], name=sbom_author)
                )

        # success
        return uSwidContainer([component])
