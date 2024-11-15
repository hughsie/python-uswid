#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# pylint: disable=protected-access

from typing import Dict, Any, Optional, List

import json
import uuid
from datetime import datetime

from .container import uSwidContainer
from .format import uSwidFormatBase
from .component import uSwidComponent, uSwidComponentType
from .link import uSwidLink
from .payload import uSwidPayload
from .enums import uSwidVersionScheme
from .evidence import uSwidEvidence
from .entity import uSwidEntity, uSwidEntityRole
from .errors import NotSupportedError
from .hash import uSwidHash, uSwidHashAlg


def _spdx_url_to_id(url: str) -> Optional[str]:

    if not url.startswith("https://spdx.org/licenses/"):
        return None
    return url[26:].replace(".html", "")


def _convert_hash_alg_to_str(alg_id: uSwidHashAlg) -> str:
    return {
        uSwidHashAlg.SHA1: "SHA-1",
        uSwidHashAlg.SHA256: "SHA-256",
        uSwidHashAlg.SHA384: "SHA-384",
        uSwidHashAlg.SHA512: "SHA-512",
    }.get(alg_id, "UNKNOWN")


def _convert_str_to_hash_alg(alg_id: str) -> uSwidHashAlg:
    return {
        "SHA-1": uSwidHashAlg.SHA1,
        "SHA-256": uSwidHashAlg.SHA256,
        "SHA-384": uSwidHashAlg.SHA384,
        "SHA-512": uSwidHashAlg.SHA512,
    }.get(alg_id, uSwidHashAlg.UNKNOWN)


def _convert_str_to_version_scheme(version_scheme: str) -> uSwidVersionScheme:
    return {
        "multipartnumeric": uSwidVersionScheme.MULTIPARTNUMERIC,
        "multipartnumeric_suffix": uSwidVersionScheme.MULTIPARTNUMERIC_SUFFIX,
        "alphanumeric": uSwidVersionScheme.ALPHANUMERIC,
        "decimal": uSwidVersionScheme.DECIMAL,
        "semver": uSwidVersionScheme.SEMVER,
    }.get(version_scheme, None)


def _convert_entity_to_dict(entity: uSwidEntity) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    if entity.name:
        data["name"] = entity.name
    if entity.regid:
        data["url"] = [entity.regid]
    return data


def _convert_entity_from_dict(data: Dict[str, Any]) -> uSwidEntity:
    if isinstance(data, list):
        raise NotSupportedError("multiple entities not expected")
    try:
        regid = data.get("url", [])[0]
    except IndexError:
        regid = None
    return uSwidEntity(name=data.get("name"), regid=regid)


class uSwidFormatCycloneDX(uSwidFormatBase):
    """CycloneDX file"""

    def __init__(self) -> None:
        """Initializes uSwidFormatCycloneDX"""
        uSwidFormatBase.__init__(self, "CycloneDX")

    def _load_component_internal(
        self, component: uSwidComponent, data: Dict[str, Any]
    ) -> None:

        component.type = uSwidComponentType.from_str(data.get("type", "firmware"))
        component.persistent_id = data.get("group")
        component.software_name = data.get("name")
        component.software_version = data.get("version")
        component.summary = data.get("description")
        component.tag_id = data.get("bom-ref", str(uuid.uuid4()))

        if "swid" in data:
            if not component.tag_id:
                component.tag_id = data["swid"].get("tagId")
            if not component.software_name:
                component.software_name = data["swid"].get("name")
            if not component.software_version:
                component.software_version = data["swid"].get("version")
            component.tag_version = data["swid"].get("tagVersion")
        for eref_data in data.get("externalReferences", []):
            if eref_data["type"] == "vcs":
                if "hashes" in eref_data:
                    try:
                        component.colloquial_version = eref_data["hashes"][0]["content"]
                    except KeyError:
                        pass

        for meta in data.get("properties", []):
            if meta.get("name") == "edition":
                component.edition = meta.get("value")
            if meta.get("name") == "revision":
                component.revision = meta.get("value")
            if meta.get("name") == "product":
                component.product = meta.get("value")
            if meta.get("name") == "versionScheme":
                component.version_scheme = _convert_str_to_version_scheme(
                    meta.get("value")
                )

        for hash_data in data.get("hashes", []):
            payload = uSwidPayload()
            payload.add_hash(
                uSwidHash(
                    alg_id=_convert_str_to_hash_alg(hash_data.get("alg")),
                    value=hash_data.get("content"),
                )
            )
            component.add_payload(payload)

        for lic in data.get("licenses", []):
            url: Optional[str] = lic["license"].get("url")
            spdx_id: Optional[str] = lic["license"].get("id")
            name: Optional[str] = lic["license"].get("name")
            if url:
                component.add_link(uSwidLink(rel="license", href=url))
            elif spdx_id:
                component.add_link(
                    uSwidLink(
                        rel="license", href=f"https://spdx.org/licenses/{spdx_id}.html"
                    )
                )
            elif name:
                component.add_link(uSwidLink(rel="license", href=name))

        # entities
        if "supplier" in data:
            entity = _convert_entity_from_dict(data["supplier"])
            entity.roles = [uSwidEntityRole.LICENSOR]
            component.add_entity(entity)
        if "publisher" in data:
            entity = _convert_entity_from_dict(data["publisher"])
            entity.roles = [uSwidEntityRole.DISTRIBUTOR]
            component.add_entity(entity)
        if "manufacturer" in data:
            entity = _convert_entity_from_dict(data["manufacturer"])
            entity.roles = [uSwidEntityRole.SOFTWARE_CREATOR]
            component.add_entity(entity)
        for author_data in data.get("authors", []):
            entity = _convert_entity_from_dict(author_data)
            entity.roles = [uSwidEntityRole.TAG_CREATOR]
            component.add_entity(entity)

        # we only have authors
        if len(component.entities) == 1:
            entity = component.entities[0]
            entity.add_role(uSwidEntityRole.SOFTWARE_CREATOR)

    def load(self, blob: bytes, path: Optional[str] = None) -> uSwidContainer:
        try:
            root = json.loads(blob)
        except json.decoder.JSONDecodeError as e:
            raise NotSupportedError(f"invalid GoSWID: {e}") from e

        if root.get("bomFormat") != "CycloneDX":
            raise NotSupportedError("not in CycloneDX format")

        container = uSwidContainer()
        for data in root.get("components", []):
            component = uSwidComponent()
            self._load_component_internal(component, data)
            if not component.tag_version:
                try:
                    component.tag_version = int(root["version"])
                except AttributeError:
                    pass
            container.append(component)

        for dep in root.get("dependencies", []):
            component = container._get_by_id(dep["ref"])
            component_other = container._get_by_id(dep["dependsOn"])
            if not component:
                continue
            if not component_other:
                continue
            if component_other.tag_id == "compiler":
                component.add_link(
                    uSwidLink(rel="compiler", href=component_other.software_name)
                )
            else:
                component.add_link(
                    uSwidLink(rel="component", href=component_other.tag_id)
                )

        for ann in root.get("annotations", []):
            component = container._get_by_id(ann["bom-ref"])
            if not component:
                continue
            try:
                date = datetime.fromisoformat(ann["timestamp"])
            except AttributeError:
                date = None
            component.add_evidence(uSwidEvidence(date=date, device_id=ann["text"]))

        return container

    def save(self, container: uSwidContainer) -> bytes:
        # header
        root: Dict[str, Any] = {}
        root["bomFormat"] = "CycloneDX"
        root["specVersion"] = "1.6"
        root["serialNumber"] = f"urn:uuid:{str(uuid.uuid4())}"

        # MAX() of all the component tag versions
        version: int = 1
        for component in container:
            version = max(version, component.tag_version)
        root["version"] = version

        # metadata
        metadata: Dict[str, Any] = {}
        metadata["timestamp"] = datetime.now().isoformat()
        root["metadata"] = metadata

        # generator
        metadata["tools"] = [
            {"vendor": "uSWID Authors", "name": "uSWID", "version": "0.4.0"}
        ]

        # find components
        components: List[Dict[str, Any]] = []
        dependencies: List[Dict[str, str]] = []
        for component in container:
            components.append(self._save_component(component))
            for link in component.links:
                if link.rel in ["compiler"]:
                    components.append(
                        self._save_component(
                            uSwidComponent(tag_id="compiler", software_name=link.href)
                        )
                    )
                    dependencies.append(
                        {"ref": component.tag_id, "dependsOn": "compiler"}
                    )
                if link.rel in ["component"]:
                    dependencies.append(
                        {"ref": component.tag_id, "dependsOn": link.href}
                    )

        # optional
        if components:
            root["components"] = components
        if dependencies:
            root["dependencies"] = dependencies

        return json.dumps(root, indent=2).encode()

    def _save_component(self, component: uSwidComponent) -> Dict[str, Any]:
        root: Dict[str, Any] = {}
        if component.type:
            root["type"] = str(component.type)
        if component.persistent_id:
            root["group"] = component.persistent_id
        if component.software_name:
            root["name"] = component.software_name
        if component.software_version:
            root["version"] = component.software_version
        if component.summary:
            root["description"] = component.summary
        if component.tag_id:
            root["bom-ref"] = component.tag_id

        swid: Dict[str, Any] = {}
        if component.tag_version and component.tag_version > 1:
            if component.tag_id:
                swid["tagId"] = component.tag_id
            if component.software_name:
                swid["name"] = component.software_name
            if component.software_version:
                swid["version"] = component.software_version
            swid["tagVersion"] = component.tag_version
        if swid:
            root["swid"] = swid

        if component.colloquial_version:
            commit: Dict[str, str] = {"type": "vcs", "url": "https://NOASSERTION/"}

            # set the correct hash algorithm automatically
            hash_tmp = uSwidHash(value=component.colloquial_version)
            commit["hashes"] = [
                {
                    "alg": _convert_hash_alg_to_str(hash_tmp.alg_id),
                    "content": hash_tmp.value,
                }
            ]
            root["externalReferences"] = [commit]

        # additional metadata, not yet standardized in cdx
        metadata: Dict[str, str] = {}
        if component.edition:
            metadata["edition"] = component.edition
        if component.product:
            metadata["product"] = component.product
        if component.revision:
            metadata["revision"] = component.revision
        if component.version_scheme:
            metadata["versionScheme"] = str(component.version_scheme)

        licenses: List[Dict[str, Any]] = []
        for link in component.links:
            if not link.href:
                continue
            if link.rel == "license":
                license_choice: Dict[str, Any] = {}
                spdx_id: Optional[str] = _spdx_url_to_id(link.href)
                if spdx_id:
                    license_choice["license"] = {"url": link.href, "id": spdx_id}
                else:
                    license_choice["license"] = {"name": link.href}
                licenses.append(license_choice)
        if licenses:
            root["licenses"] = licenses

        # supplier and authors
        supplier: Optional[Dict[str, Any]] = None
        publisher: Optional[Dict[str, Any]] = None
        authors: List[Dict[str, Any]] = []
        manufacturer: Optional[Dict[str, Any]] = None
        for entity in component.entities:
            if uSwidEntityRole.LICENSOR in entity.roles:
                supplier = _convert_entity_to_dict(entity)
            if uSwidEntityRole.DISTRIBUTOR in entity.roles:
                publisher = _convert_entity_to_dict(entity)
            if uSwidEntityRole.SOFTWARE_CREATOR in entity.roles:
                manufacturer = _convert_entity_to_dict(entity)
            if uSwidEntityRole.TAG_CREATOR in entity.roles:
                authors.append(_convert_entity_to_dict(entity))
        if supplier:
            # the organization that supplied the component --
            # may often be the manufacturer, but may also be a distributor or repackager
            root["supplier"] = supplier
        if publisher:
            # the person(s) or organization(s) that published the component
            root["publisher"] = publisher
        if authors:
            # the person(s) who created the component --
            # authors are common in components created through manual processes
            root["authors"] = authors
        if manufacturer:
            # the organization that created the component --
            # manufacturer is common in components created through automated processes
            root["manufacturer"] = manufacturer
        hashes: List[Any] = []
        for payload in component.payloads:
            for ihash in payload.hashes:
                if not ihash.alg_id:
                    continue
                hashes.append(
                    {
                        "alg": _convert_hash_alg_to_str(ihash.alg_id),
                        "content": ihash.value,
                    }
                )
        if hashes:
            root["hashes"] = hashes

        # annotations
        annotations: List[Dict[str, Any]] = []
        for evidence in component.evidences:
            annotation = {"subjects": [component.tag_id], "annotator": "component"}
            if evidence.date:
                annotation["timestamp"] = evidence.date.isoformat()
            if evidence.device_id:
                annotation["text"] = evidence.device_id
            annotations.append(annotation)
        if annotations:
            root["annotations"] = annotations

        # properties
        if metadata:
            properties: List[Dict[str, str]] = []
            for name, value in metadata.items():
                properties.append({"name": name, "value": value})
            root["properties"] = properties

        return root
