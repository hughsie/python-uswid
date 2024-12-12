#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2022 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# pylint: disable=too-few-public-methods,protected-access

from typing import List, Dict, Any
from random import choices, randrange
import uuid
import string

from .container import uSwidContainer
from .component import uSwidComponent
from .entity import uSwidEntity, uSwidEntityRole
from .enums import uSwidVersionScheme

from .format_coswid import uSwidFormatCoswid
from .format_ini import uSwidFormatIni
from .format_goswid import uSwidFormatGoswid
from .format_pkgconfig import uSwidFormatPkgconfig
from .format_swid import uSwidFormatSwid
from .format_uswid import uSwidFormatUswid
from .format_cyclonedx import uSwidFormatCycloneDX
from .format_spdx import uSwidFormatSpdx


def container_generate(container: uSwidContainer) -> None:
    """generate 1000 plausible components, each with:
    - unique tag-id GUID
    - unique software-name of size 4-30 chars
    - colloquial-version from a random selection of 10 SHA-1 hashes
    - edition from a random SHA-1 hash
    - semantic version of size 3-8 chars
    - entity from a random selection of 10 entities
    """
    tree_hashes: List[str] = []
    entities: List[uSwidEntity] = []
    for _ in range(10):
        tree_hashes.append("".join(choices("0123456789abcdef", k=40)))
    for i in range(10):
        entity = uSwidEntity()
        entity.name = "Entity#" + str(i)
        entity.regid = "com.entity" + str(i)
        entity.roles = [uSwidEntityRole.TAG_CREATOR]
        entities.append(entity)
    for i in range(1000):
        component = uSwidComponent()
        component.tag_id = str(uuid.uuid4())
        component.software_name = "".join(
            choices(string.ascii_lowercase, k=randrange(4, 30))
        )
        component.software_version = "1." + "".join(
            choices("123456789", k=randrange(1, 6))
        )
        component.edition = tree_hashes[randrange(len(tree_hashes))]
        component.colloquial_version = "".join(choices("0123456789abcdef", k=40))
        component.version_scheme = uSwidVersionScheme.MULTIPARTNUMERIC
        component.add_entity(entities[randrange(len(entities))])
        container.append(component)


def container_roundtrip(container: uSwidContainer, verbose: bool = False) -> None:
    """rountrip the container into a few different SBOM formats"""

    try:
        component: uSwidComponent = container[0]  # type:ignore[index]
    except IndexError:
        print("no default component")
        return

    # convert to each format and back again
    for base in [
        uSwidFormatCoswid(),
        uSwidFormatIni(),
        uSwidFormatCycloneDX(),
        uSwidFormatGoswid(),
        uSwidFormatPkgconfig(),
        uSwidFormatSpdx(),
        uSwidFormatSwid(),
        uSwidFormatUswid(),
    ]:

        # proxy
        base.verbose = verbose

        # save
        try:
            blob: bytes = base.save(container)
        except NotImplementedError:
            continue

        # load
        try:
            container_new = base.load(blob)
        except NotImplementedError:
            continue
        try:
            component_new = container_new[0]  # type:ignore[index]
        except IndexError:
            print(f"no default component for {base.name}")
            continue

        # compare the old and the new
        differences: List[Dict[str, Any]] = []
        for key in [
            "tag_id",
            "tag_version",
            "type",
            "software_name",
            "software_version",
            "version_scheme",
            "summary",
            "product",
            "colloquial_version",
            "edition",
            "revision",
            "edition",
            "persistent_id",
            "activation_status",
            "cpe",
        ]:
            if getattr(component, key) != getattr(component_new, key):
                differences.append(
                    {
                        "class": "uSwidComponent",
                        "property": key,
                        "old": getattr(component, key),
                        "new": getattr(component_new, key),
                    }
                )

        # payloads
        for payload in component.payloads:

            # check still exists
            payload_new = component_new.get_payload_by_name(payload.name)
            if not payload_new:
                differences.append(
                    {
                        "class": "uSwidPayload",
                        "name": payload.name,
                    }
                )
                continue

            # check values
            for key in [
                "name",
                "size",
            ]:
                if getattr(payload, key) != getattr(payload_new, key):
                    differences.append(
                        {
                            "class": "uSwidPayload",
                            "property": key,
                            "old": getattr(payload, key),
                            "new": getattr(payload_new, key),
                        }
                    )

        # entities
        for entity in component.entities:

            # check still exists
            for role in entity.roles:
                entity_new = component_new.get_entity_by_role(role)
                if not entity_new:
                    differences.append(
                        {
                            "class": "uSwidEntity",
                            "name": role,
                        }
                    )
                    continue

                # check values
                for key in [
                    "name",
                    "regid",
                ]:
                    if getattr(entity, key) != getattr(entity_new, key):
                        differences.append(
                            {
                                "class": "uSwidEntity",
                                "property": key,
                                "old": getattr(entity, key),
                                "new": getattr(entity_new, key),
                            }
                        )

        # link
        for link in component.links:
            # check still exists
            link_new = component_new.get_link_by_rel(link.rel)
            if not link_new:
                differences.append(
                    {
                        "class": "uSwidLink",
                        "name": str(link.rel),
                    }
                )
                continue

            # check values
            for key in [
                "href",
                "rel",
            ]:
                if getattr(link, key) != getattr(link_new, key):
                    differences.append(
                        {
                            "class": "uSwidLink",
                            "property": key,
                            "old": getattr(link, key),
                            "new": getattr(link_new, key),
                        }
                    )

        # evidence
        for evidence in component.evidences:
            # check still exists
            evidence_new = component_new.get_evidence_by_rel(evidence.rel)
            if not evidence_new:
                differences.append(
                    {
                        "class": "uSwidEvidence",
                        "name": evidence.rel,
                    }
                )
                continue

            # check values
            for key in [
                "date",
                "device_id",
            ]:
                if getattr(evidence, key) != getattr(evidence_new, key):
                    differences.append(
                        {
                            "class": "uSwidEvidence",
                            "property": key,
                            "old": getattr(evidence, key),
                            "new": getattr(evidence_new, key),
                        }
                    )

        # show differences
        total: float = 22
        print(f"{base.name}: { 100.0 / float(total) * (total - len(differences)):.0f}%")
        for dif in differences:
            try:
                print(
                    f"  - FAILURE {dif['class']}.{dif['property']}: {dif['old']}->{dif['new']}"
                )
            except KeyError:
                print(f"  - FAILURE {dif['class']} [{dif['name']}] -> None")
