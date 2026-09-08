#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
# (c) Copyright 2026 HP Development Company, L.P.
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# pylint: disable=wrong-import-position,protected-access

import os
import sys
import unittest
import datetime
from typing import Optional, Any
import shutil
import subprocess
import json

from lxml import etree as ET

# allows us to run this from the project root
sys.path.append(os.path.realpath("."))

from . import __version__ as tool_version
from .container import uSwidContainer
from .errors import NotSupportedError
from .link import uSwidLink, uSwidLinkRel
from .entity import uSwidEntity, uSwidEntityRole
from .enums import uSwidVersionScheme
from .component import uSwidComponent, uSwidComponentType
from .hash import uSwidHash, uSwidHashAlg
from .payload import uSwidPayload
from .evidence import uSwidEvidence
from .patch import uSwidPatch, uSwidPatchType

from .format_ini import uSwidFormatIni
from .format_coswid import uSwidFormatCoswid, uSwidGlobalMap
from .format_swid import uSwidFormatSwid
from .format_cyclonedx import uSwidFormatCycloneDX, _convert_str_to_component_type
from .format_spdx import (
    uSwidFormatSpdx,
    _get_graph_nodes_by_type,
    _detect_spdx_json_version,
)
from .format_inf import uSwidFormatInf
from .vcs import uSwidVcs

from .purl import uSwidPurl

unittest.TestCase.maxDiff = None


class TestSwidEntity(unittest.TestCase):
    """Tescases for components, entities, links, evidence and payloads"""

    def setUp(self):
        self.git_path = "/tmp/uswid-test-git-tree"
        try:
            shutil.rmtree(self.git_path)
        except FileNotFoundError:
            pass

    def tearDown(self):
        try:
            shutil.rmtree(self.git_path)
        except FileNotFoundError:
            pass

    def _build_fake_git_path(self):
        subprocess.run(
            ["git", "init", self.git_path, "--initial-branch", "main"],
            cwd=".",
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.email", "admin@example.com"],
            cwd=self.git_path,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "RH"],
            cwd=self.git_path,
            check=True,
        )
        subprocess.run(
            ["mkdir", "contrib"],
            cwd=self.git_path,
            check=True,
        )
        with open(os.path.join(self.git_path, "contrib", "bom.cdx.json"), "wb") as f:
            f.write(b"hello")
        subprocess.run(
            ["git", "add", "contrib/bom.cdx.json"],
            cwd=self.git_path,
            check=True,
        )
        subprocess.run(
            ["git", "commit", "-a", "-m", "Add SBOM"],
            cwd=self.git_path,
            check=True,
            env={},
        )
        subprocess.run(
            ["mkdir", "edk2"],
            cwd=self.git_path,
            check=True,
        )
        try:
            for basename in ["Shell.inf", "Shell.c", "Shell.h"]:
                shutil.copy(
                    os.path.join(".", "tests", "edk2", basename),
                    os.path.join(self.git_path, "edk2", basename),
                )
            subprocess.run(
                ["git", "add", "edk2/Shell.inf"],
                cwd=self.git_path,
                check=True,
            )
            subprocess.run(
                ["git", "commit", "-a", "-m", "Add EDK Inf"],
                cwd=self.git_path,
                check=True,
                env={},
            )
        except FileNotFoundError:
            pass
        subprocess.run(
            ["git", "tag", "v1.2.3"],
            cwd=self.git_path,
            check=True,
        )
        with open(os.path.join(self.git_path, "contrib", "bom.cdx.json"), "wb") as f:
            f.write(b"hello world")
        subprocess.run(
            ["git", "commit", "-a", "-m", "A SBOM fixup"],
            cwd=self.git_path,
            check=True,
            env={},
        )
        subprocess.run(
            [
                "git",
                "remote",
                "add",
                "origin",
                "git@github.com:hughsie/python-uswid.git",
            ],
            cwd=self.git_path,
            check=True,
        )

    def test_format_inf(self):
        """Unit tests for uSwidFormatInf"""

        # generate something plausible
        self._build_fake_git_path()

        fmt_parent = uSwidFormatCycloneDX()
        try:
            with open("./tests/edk2/sbom.cdx.json", "rb") as f:
                container_parent = fmt_parent.load(f.read())
        except FileNotFoundError:
            return
        print(container_parent)

        fmt = uSwidFormatInf()
        fn = os.path.join(self.git_path, "edk2", "Shell.inf")
        try:
            with open(fn, "rb") as f:
                container = fmt.load(f.read(), path=fn)
        except FileNotFoundError:
            return
        for component in container:
            fmt.incorporate(container_parent, component)
            container_parent.append(component)

        self.assertIsNotNone(
            container_parent.get_by_id("pkg:github/tianocore/edk2@202411")
        )
        self.assertIsNotNone(
            container_parent.get_by_id("pkg:github/tianocore/edk2@202411#Shell")
        )

        fmt_parent.serial_number = "urn:uuid:00000000-0000-0000-0000-000000000000"
        fmt_parent.timestamp = "2024-01-01T00:00:00.000000+00:00"
        self.assertEqual(
            fmt_parent.save(container_parent).decode(),
            """{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000000",
  "version": 1,
  "metadata": {
    "timestamp": "2024-01-01T00:00:00.000000+00:00",
    "tools": [
      {
        "vendor": "uSWID Authors",
        "name": "uSWID",
        "version": "@USWID_VERSION@"
      }
    ],
    "authors": [
      {
        "name": "RH"
      }
    ],
    "lifecycles": [
      {
        "phase": "pre-build"
      }
    ]
  },
  "components": [
    {
      "type": "firmware",
      "cpe": "cpe:2.3:a:tianocore:edk2:202411:*:*:*:*:*:*:*",
      "name": "EDK II",
      "version": "edk2-stable202411-105-gd55d4e22f4",
      "description": "A cross-platform firmware development environment for UEFI and PI specifications",
      "bom-ref": "pkg:github/tianocore/edk2@202411",
      "externalReferences": [
        {
          "type": "vcs",
          "url": "https://github.com/tianocore/edk2"
        }
      ],
      "licenses": [
        {
          "license": {
            "url": "https://spdx.org/licenses/BSD-2-Clause.html",
            "id": "BSD-2-Clause"
          }
        }
      ],
      "supplier": {
        "name": "EDK II developers"
      },
      "authors": [
        {
          "name": "EDK II authors"
        }
      ]
    },
    {
      "type": "application",
      "group": "7c04a583-9e3e-4f1c-ad65-e05268d0b4d1",
      "cpe": "cpe:2.3:a:tianocore:edk2:202411:*:*:*:*:*:*:Shell",
      "name": "Shell",
      "version": "1.0",
      "description": "This is the shell application",
      "bom-ref": "pkg:github/tianocore/edk2@202411#Shell",
      "externalReferences": [
        {
          "type": "vcs",
          "url": "https://github.com/tianocore/edk2"
        }
      ],
      "licenses": [
        {
          "license": {
            "url": "https://spdx.org/licenses/BSD-2-Clause-Patent.html",
            "id": "BSD-2-Clause-Patent"
          }
        }
      ],
      "supplier": {
        "name": "EDK II developers"
      },
      "authors": [
        {
          "name": "RH"
        }
      ],
      "properties": [
        {
          "name": "colloquialVersion",
          "value": "6e434ee13d3fe6f205f93523c7874a666a75aa6e443f6848a1c11af062861359"
        }
      ]
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:github/tianocore/edk2@202411",
      "dependsOn": "pkg:github/tianocore/edk2@202411#Shell"
    },
    {
      "ref": "pkg:github/tianocore/edk2@202411#Shell",
      "dependsOn": "pkg:github/tianocore/edk2@202411#BaseLib"
    }
  ]
}""".replace("@USWID_VERSION@", tool_version),
        )

    def test_vcs_verfmt(self):
        """Unit tests for uSwidVcs, version format conversion"""

        self.assertEqual(
            uSwidVersionScheme.from_version("123"), uSwidVersionScheme.DECIMAL
        )
        self.assertEqual(
            uSwidVersionScheme.from_version("1.2.3"), uSwidVersionScheme.SEMVER
        )
        self.assertEqual(
            uSwidVersionScheme.from_version("1.2.3-4"),
            uSwidVersionScheme.MULTIPARTNUMERIC,
        )
        self.assertEqual(
            uSwidVersionScheme.from_version("1.2.3-4~5"),
            uSwidVersionScheme.ALPHANUMERIC,
        )

    def test_component_type_from_str(self):
        """SWID stringifier stays pure; CycloneDX type mapping lives in the loader"""

        # uSwidComponentType.from_str: only the defined SWID types
        self.assertEqual(
            uSwidComponentType.from_str("firmware"), uSwidComponentType.FIRMWARE
        )
        self.assertEqual(
            uSwidComponentType.from_str("application"), uSwidComponentType.APPLICATION
        )
        self.assertEqual(
            uSwidComponentType.from_str("library"), uSwidComponentType.LIBRARY
        )

        # CycloneDX 1.4+ types are mapped to the nearest SWID type in the
        # CycloneDX loader, and never crash the importer
        self.assertEqual(
            _convert_str_to_component_type("device-driver"), uSwidComponentType.FIRMWARE
        )
        self.assertEqual(
            _convert_str_to_component_type("framework"), uSwidComponentType.LIBRARY
        )
        self.assertEqual(
            _convert_str_to_component_type("operating-system"),
            uSwidComponentType.APPLICATION,
        )
        self.assertEqual(
            _convert_str_to_component_type("cryptographic-asset"),
            uSwidComponentType.LIBRARY,
        )
        # native SWID types still resolve through the loader
        self.assertEqual(
            _convert_str_to_component_type("firmware"), uSwidComponentType.FIRMWARE
        )
        # matching is case-insensitive
        self.assertEqual(
            _convert_str_to_component_type("Device-Driver"), uSwidComponentType.FIRMWARE
        )
        # empty / unknown values fall back to FIRMWARE instead of raising
        self.assertEqual(
            _convert_str_to_component_type(""), uSwidComponentType.FIRMWARE
        )
        self.assertEqual(
            _convert_str_to_component_type("totally-unknown"),
            uSwidComponentType.FIRMWARE,
        )

    def test_container(self):
        """Unit tests for uSwidContainer"""

        container = uSwidContainer()

        self.assertIsNone(container.get_by_id("pkg:github/tianocore/edk2@202411"))

        # exact match
        container.append(uSwidComponent(tag_id="pkg:github/tianocore/edk2@202411"))
        self.assertIsNotNone(container.get_by_id("pkg:github/tianocore/edk2@202411"))
        self.assertIsNone(container.get_by_id("pkg:github/tianocore/edk2"))

        # incomplete PURL match
        self.assertIsNone(
            container.get_by_id("pkg:github/tianocore/something@202411", fuzzy=True)
        )
        self.assertIsNone(
            container.get_by_id("pkg:github/tianocore/edk2@12345678", fuzzy=True)
        )
        self.assertIsNone(
            container.get_by_id("pkg:github/intel/edk2@202411", fuzzy=True)
        )
        self.assertIsNotNone(
            container.get_by_id("pkg:github/tianocore/edk2", fuzzy=True)
        )
        self.assertIsNotNone(container.get_by_id("pkg:edk2", fuzzy=True))

    def test_vcs(self):
        """Unit tests for uSwidVcs"""

        # generate something plausible
        self._build_fake_git_path()

        vcs = uSwidVcs(filepath=os.path.join(self.git_path, "contrib", "bom.cdx.json"))

        # 0.5.0
        self.assertEqual(vcs.get_tag(), "1.2.3")

        # 0.5.0-25-g26af980
        self.assertEqual(vcs.get_version().rsplit("-", maxsplit=1)[0], "v1.2.3-1")

        # main
        self.assertEqual(vcs.get_branch(), "main")

        # 26af9806ef407b171481ff234d2fe16386dc75eb
        self.assertEqual(len(vcs.get_commit()), 40)

        # /home/hughsie/Code/uswid
        value: Optional[str] = vcs.get_toplevel()
        self.assertEqual(value, self.git_path)

        # https://github.com/hughsie/python-uswid
        value = vcs.get_remote_url()
        self.assertEqual(value, "https://github.com/hughsie/python-uswid")

        # me!
        self.assertEqual(vcs.get_sbom_authors(), ["RH"])
        self.assertEqual(vcs.get_authors(), ["RH"])

    def test_entity(self):
        """Unit tests for uSwidEntity"""
        entity = uSwidEntity(
            name="test", regid="example.com", roles=[uSwidEntityRole.MAINTAINER]
        )
        self.assertEqual(
            str(entity),
            'uSwidEntity(regid="example.com",name="test",roles=[MAINTAINER])',
        )
        self.assertEqual(
            str(uSwidFormatCoswid()._save_entity(entity)),  # type: ignore
            "{<uSwidGlobalMap.ENTITY_NAME: 31>: 'test', "
            + "<uSwidGlobalMap.REG_ID: 32>: 'example.com', "
            + "<uSwidGlobalMap.ROLE: 33>: <uSwidEntityRole.MAINTAINER: 6>}",
        )

        entity.roles.append(uSwidEntityRole.SOFTWARE_CREATOR)
        self.assertEqual(
            str(uSwidFormatCoswid()._save_entity(entity)),  # type: ignore
            "{<uSwidGlobalMap.ENTITY_NAME: 31>: 'test', "
            + "<uSwidGlobalMap.REG_ID: 32>: 'example.com', "
            + "<uSwidGlobalMap.ROLE: 33>: [<uSwidEntityRole.MAINTAINER: 6>, "
            + "<uSwidEntityRole.SOFTWARE_CREATOR: 2>]}",
        )

        # SWID XML import
        entity = uSwidEntity()
        uSwidFormatSwid()._load_entity(  # type: ignore
            entity,
            ET.Element(
                "Entity",
                attrib={"name": "foo", "regid": "bar", "role": "tagCreator maintainer"},
            ),
        )
        self.assertEqual(
            str(entity),
            'uSwidEntity(regid="bar",name="foo",roles=[TAG_CREATOR,MAINTAINER])',
        )
        with self.assertRaises(NotSupportedError):
            uSwidFormatSwid()._load_entity(  # type: ignore
                entity,
                ET.Element(
                    "Entity", attrib={"name": "foo", "regid": "bar", "role": "baz"}
                ),
            )

        # INI import
        entity = uSwidEntity()
        uSwidFormatIni()._load_entity(  # type: ignore
            entity,
            {"name": "foo", "regid": "bar", "extra-roles": "TagCreator,Maintainer"},
            role_hint="Distributor",
        )
        self.assertEqual(
            str(entity),
            'uSwidEntity(regid="bar",name="foo",roles=[TAG_CREATOR,MAINTAINER])',
        )
        with self.assertRaises(NotSupportedError):
            uSwidFormatIni()._load_entity(  # type: ignore
                entity, {"name": "foo", "regid": "bar", "extra-roles": "baz"}
            )

        # SWID XML export
        root = ET.Element("SoftwareIdentity")
        uSwidFormatSwid()._save_entity(entity, root)  # type: ignore
        self.assertEqual(
            ET.tostring(root, encoding="utf-8"),
            b"<SoftwareIdentity>"
            b'<Entity name="foo" regid="bar" role="tagCreator maintainer"/>'
            b"</SoftwareIdentity>",
        )

    def test_link(self):
        """Unit tests for uSwidLink"""
        # enumerated type
        link = uSwidLink(href="http://test.com/", rel=uSwidLinkRel.SEE_ALSO)
        self.assertEqual(str(link), 'uSwidLink(rel="see-also",href="http://test.com/")')
        self.assertEqual(
            str(uSwidFormatCoswid()._save_link(link)),  # type: ignore
            "{<uSwidGlobalMap.HREF: 38>: 'http://test.com/', "
            + "<uSwidGlobalMap.REL: 40>: <uSwidLinkRel.SEE_ALSO: 9>}",
        )

        # rel from IANA "Software Tag Link Relationship Values" registry
        link = uSwidLink(href="http://test.com/", rel=uSwidLinkRel.LICENSE)
        self.assertEqual(str(link), 'uSwidLink(rel="license",href="http://test.com/")')
        self.assertEqual(
            str(uSwidFormatCoswid()._save_link(link)),  # type: ignore
            "{<uSwidGlobalMap.HREF: 38>: 'http://test.com/', "
            + "<uSwidGlobalMap.REL: 40>: <uSwidLinkRel.LICENSE: -2>}",
        )

        # SWID XML import
        link = uSwidLink()
        uSwidFormatSwid()._load_link(  # type: ignore
            link,
            ET.Element(
                "Url",
                attrib={"href": "http://test.com/", "rel": "seeAlso"},
            ),
        )
        self.assertEqual(str(link), 'uSwidLink(rel="see-also",href="http://test.com/")')

        # INI import
        link = uSwidLink()
        uSwidFormatIni()._load_link(  # type: ignore
            link,
            {"href": "http://test.com/", "rel": "see-also"},
        )
        self.assertEqual(str(link), 'uSwidLink(rel="see-also",href="http://test.com/")')

        # SWID XML export
        root = ET.Element("SoftwareIdentity")
        uSwidFormatSwid()._save_link(link, root)  # type: ignore
        self.assertEqual(
            ET.tostring(root, encoding="utf-8"),
            b"<SoftwareIdentity>"
            b'<Link href="http://test.com/" rel="see-also"/>'
            b"</SoftwareIdentity>",
        )

    def test_payload(self):
        """Unit tests for uSwidPayload"""
        self.maxDiff = None

        # enumerated type
        payload = uSwidPayload(name="foo", size=123)
        payload.add_hash(
            uSwidHash(
                alg_id=uSwidHashAlg.SHA256,
                value="067cb8292dc062eabbe05734ef7987eb1333b6b6",
            )
        )
        self.assertEqual(
            str(payload),
            'uSwidPayload(name="foo",size=123)\n'
            ' - uSwidHash(alg_id=SHA256,value="067cb8292dc062eabbe05734ef7987eb1333b6b6")',
        )
        payload.remove_hash(uSwidHashAlg.SHA256)
        self.assertEqual(
            str(uSwidFormatCoswid()._save_payload(payload)),  # type: ignore
            "{<uSwidGlobalMap.FILE: 17>: {<uSwidGlobalMap.FS_NAME: 24>: 'foo', <uSwidGlobalMap.SIZE: 20>: 123}}",
        )

        # SWID XML import
        payload = uSwidPayload()
        uSwidFormatSwid()._load_payload(  # type: ignore
            payload,
            ET.Element(
                "File",
                attrib={
                    "name": "foo",
                    "size": "123",
                    "{http://www.w3.org/2001/04/xmlenc#sha256}hash": "067cb8292dc062eabbe05734ef7987eb1333b6b6",
                },
            ),
        )
        self.assertEqual(
            str(payload),
            'uSwidPayload(name="foo",size=123)\n'
            ' - uSwidHash(alg_id=SHA256,value="067cb8292dc062eabbe05734ef7987eb1333b6b6")',
        )

        # INI import
        payload = uSwidPayload()
        uSwidFormatIni()._load_payload(  # type: ignore
            payload,
            {
                "name": "foo",
                "size": "123",
                "hash": "8cab6b2125c2b561351b4e02ee531f26dde05c3c6a2be8ff942975fbdef6823c",
            },
        )
        self.assertEqual(
            str(payload),
            'uSwidPayload(name="foo",size=123)\n'
            ' - uSwidHash(alg_id=SHA256,value="8cab6b2125c2b561351b4e02ee531f26dde05c3c6a2be8ff942975fbdef6823c")',
        )

        # SWID XML export
        root = ET.Element("SoftwareIdentity")
        uSwidFormatSwid()._save_payload(payload, root)  # type: ignore
        self.assertEqual(
            ET.tostring(root, encoding="utf-8"),
            b"<SoftwareIdentity>"
            b'<File xmlns:SHA256="http://www.w3.org/2001/04/xmlenc#sha256" '
            b'xmlns:SHA512="http://www.w3.org/2001/04/xmlenc#sha512" name="foo" size="123" '
            b'SHA256:hash="8cab6b2125c2b561351b4e02ee531f26dde05c3c6a2be8ff942975fbdef6823c"/>'
            b"</SoftwareIdentity>",
        )

    def test_patch(self):
        """Unit tests for uSwidPatch"""
        self.maxDiff = None

        # enumerated type
        patch = uSwidPatch(
            type=uSwidPatchType.BACKPORT,
            url="http://foo",
            description="foo",
            references=["foo", "bar", "baz"],
        )
        self.assertEqual(
            str(patch),
            'uSwidPatch(type="backport", description="foo")',
        )

        # CycloneDX export
        jsonstr: str = json.dumps(uSwidFormatCycloneDX()._save_patch(patch))  # type: ignore
        self.assertEqual(
            jsonstr,
            '{"type": "backport", '
            '"diff": {"url": "http://foo"}, '
            '"resolves": {"description": "foo", "references": ["foo", "bar", "baz"]}}',
        )

        # CycloneDX import
        patch2 = uSwidFormatCycloneDX()._load_patch(json.loads(jsonstr))
        self.assertEqual(patch.type, patch2.type)
        self.assertEqual(patch.url, patch2.url)
        self.assertEqual(patch.description, patch2.description)
        self.assertEqual(patch.references, patch2.references)

        # INI export
        ini_save_patch = uSwidFormatIni()._save_patch(patch)
        self.assertEqual(
            ini_save_patch,
            {
                "type": "backport",
                "url": "http://foo",
                "description": "foo",
                "references": "foo,bar,baz",
            },
        )

        # INI import
        ini_load_patch = uSwidPatch()
        uSwidFormatIni()._load_patch(ini_load_patch, ini_save_patch)
        self.assertEqual(ini_load_patch.type, patch.type)
        self.assertEqual(ini_load_patch.url, patch.url)
        self.assertEqual(ini_load_patch.description, patch.description)
        self.assertEqual(ini_load_patch.references, patch.references)

    def test_evidence(self):
        """Unit tests for uSwidEvidence, including the optional measured hash"""
        self.maxDiff = None

        # an evidence entry can now carry a measured hash (RFC 9393 records the
        # measured hash on the evidence branch, inside a file-entry)
        evidence = uSwidEvidence(
            date=datetime.datetime.fromtimestamp(1600000000, tz=datetime.timezone.utc),
            device_id="localhost",
        )
        evidence.add_hash(
            uSwidHash(
                alg_id=uSwidHashAlg.SHA256,
                value="8cab6b2125c2b561351b4e02ee531f26dde05c3c6a2be8ff942975fbdef6823c",
            )
        )
        self.assertIn("SHA256", str(evidence))
        self.assertIn("8cab6b21", str(evidence))

        # CoSWID export nests the measured hash under a FILE entry — RFC 9393 puts a
        # hash-entry inside a file-entry, NOT at the evidence-map top level.
        data = uSwidFormatCoswid()._save_evidence(evidence)  # type: ignore
        self.assertNotIn(uSwidGlobalMap.HASH, data)  # not a bare hash at the map top
        self.assertIn(uSwidGlobalMap.FILE, data)
        self.assertIn(uSwidGlobalMap.HASH, data[uSwidGlobalMap.FILE])

        # full CBOR save() -> load() round-trip on a real component, with TWO distinct
        # algorithms, proves cross-tool interop (not just the in-memory helpers).
        component = uSwidComponent(tag_id="test", software_version="1.2.3")
        component.add_entity(
            uSwidEntity(name="test", roles=[uSwidEntityRole.TAG_CREATOR])
        )
        ev = uSwidEvidence(
            date=datetime.datetime.fromtimestamp(1600000000, tz=datetime.timezone.utc),
            device_id="localhost",
        )
        ev.add_hash(
            uSwidHash(
                alg_id=uSwidHashAlg.SHA256,
                value="8cab6b2125c2b561351b4e02ee531f26dde05c3c6a2be8ff942975fbdef6823c",
            )
        )
        ev.add_hash(uSwidHash(alg_id=uSwidHashAlg.SHA384, value="a" * 96))
        component.add_evidence(ev)
        blob = uSwidFormatCoswid().save(uSwidContainer([component]))
        component2 = uSwidFormatCoswid().load(blob)[0]
        self.assertEqual(len(component2.evidences), 1)
        got = {h.alg_id: h.value for h in component2.evidences[0].hashes}
        self.assertEqual(
            got[uSwidHashAlg.SHA256],
            "8cab6b2125c2b561351b4e02ee531f26dde05c3c6a2be8ff942975fbdef6823c",
        )
        self.assertEqual(got[uSwidHashAlg.SHA384], "a" * 96)

        # a second hash with the same algorithm is deduplicated by algorithm ID
        ev.add_hash(
            uSwidHash(
                alg_id=uSwidHashAlg.SHA256,
                value="067cb8292dc062eabbe05734ef7987eb1333b6b6067cb8292dc062eabbe05734",
            )
        )
        self.assertEqual(len(ev.hashes), 2)  # SHA256 (replaced) + SHA384
        replaced = {h.alg_id: h.value for h in ev.hashes}
        self.assertEqual(
            replaced[uSwidHashAlg.SHA256],
            "067cb8292dc062eabbe05734ef7987eb1333b6b6067cb8292dc062eabbe05734",
        )

    def test_component_purl(self):
        """Unit tests for uSwidComponent, PURL specific"""

        component = uSwidComponent(
            tag_id="pkg:github/tianocore/edk2@202411",
        )
        self.assertEqual(
            component.tag_id,
            "pkg:github/tianocore/edk2@202411",
        )
        self.assertEqual(
            str(component.purl),
            "pkg:github/tianocore/edk2@202411",
        )

    def test_ancestor(self):
        """Unit tests for uSwidComponent ancestors"""
        self.maxDiff = None
        component = uSwidComponent(tag_id="parent")
        component.ancestors.append(uSwidComponent(tag_id="child1"))
        component.ancestors.append(uSwidComponent(tag_id="child2"))

        # CycloneDX export
        jsonstr = uSwidFormatCycloneDX().save(uSwidContainer([component])).decode()
        assert "parent" in jsonstr
        assert "child1" in jsonstr
        assert "child2" in jsonstr

        # CycloneDX import
        component1 = uSwidFormatCycloneDX().load(jsonstr.encode())[0]
        self.assertEqual(component1.tag_id, "parent")
        self.assertEqual(component1.ancestors[0].tag_id, "child1")
        self.assertEqual(component1.ancestors[1].tag_id, "child2")

    def test_component(self):
        """Unit tests for uSwidComponent"""
        self.maxDiff = None
        component = uSwidComponent(
            tag_id="foobarbaz",
            tag_version=5,
            software_name="foo",
            software_version="1.2.3",
        )
        component.version_scheme = uSwidVersionScheme.MULTIPARTNUMERIC
        self.assertEqual(
            str(component),
            'uSwidComponent(tag_id="foobarbaz",tag_version="5",software_name="foo",software_version="1.2.3")',
        )
        entity = uSwidEntity(
            name="test", regid="example.com", roles=[uSwidEntityRole.MAINTAINER]
        )
        component.add_entity(entity)
        self.assertEqual(
            str(component),
            'uSwidComponent(tag_id="foobarbaz",tag_version="5",software_name="foo",software_version="1.2.3"):\n'
            ' - uSwidEntity(regid="example.com",name="test",roles=[MAINTAINER])',
        )

        # SWID XML import
        xml = b"""<?xml version='1.0' encoding='UTF-8'?>
<SoftwareIdentity name="DellBiosConnectNetwork"
tagId="acbd84ff-9898-4922-8ade-dd4bbe2e40ba" tagVersion="1" version="1.5.2"
versionScheme="unknown" xml:lang="en-us"
xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd"
xmlns:SHA256="http://www.w3.org/2001/04/xmlenc#sha256"
xmlns:SHA512="http://www.w3.org/2001/04/xmlenc#sha512"
xmlns:n8060="http://csrc.nist.gov/ns/swid/2015-extensions/1.0">
<Entity name="Dell Technologies" regid="dell.com" role="softwareCreator tagCreator" />
<Link rel="seeAlso" href="http://hughsie.com"/>
<Link rel="license" href="www.gnu.org/licenses/gpl.txt"/>
<Meta product="Fedora" colloquialVersion="29" persistentId="org.hughski.colorhug"
  summary="Linux distribution developed by the community-supported Fedora Project" />
</SoftwareIdentity>"""
        component = uSwidFormatSwid().load(xml).get_default()  # type: ignore
        self.assertEqual(
            str(component),
            'uSwidComponent(tag_id="acbd84ff-9898-4922-8ade-dd4bbe2e40ba",tag_version="1",'
            'software_name="DellBiosConnectNetwork",software_version="1.5.2"):\n'
            ' - uSwidLink(rel="see-also",href="http://hughsie.com")\n'
            ' - uSwidLink(rel="license",href="www.gnu.org/licenses/gpl.txt")\n'
            ' - uSwidEntity(regid="dell.com",name="Dell Technologies",roles=[SOFTWARE_CREATOR,TAG_CREATOR])',
        )
        self.assertEqual(
            component.summary,
            "Linux distribution developed by the community-supported Fedora Project",
        )
        self.assertEqual(component.product, "Fedora")
        self.assertEqual(component.colloquial_version, "29")
        self.assertEqual(component.persistent_id, "org.hughski.colorhug")

        # INI import
        ini = """[uSWID]
tag-id = acbd84ff-9898-4922-8ade-dd4bbe2e40ba
tag-version = 1
software-name = HughskiColorHug.efi
software-version = 1.0.0
persistent-id = org.hughski.colorhug

[uSWID-Entity:TagCreator]
name = Richard Hughes
regid = hughsie.com
extra-roles = Licensor

[uSWID-Entity:ANYTHING_CAN_GO_HERE]
name = Hughski Limited
regid = hughski.com
extra-roles = Aggregator

[uSWID-Link:ANYTHING]
href = https://hughski.com/
rel = see-also
"""
        component = uSwidFormatIni().load(ini.encode()).get_default()  # type: ignore
        self.assertIsNotNone(component)
        self.assertEqual(
            str(component),
            'uSwidComponent(tag_id="acbd84ff-9898-4922-8ade-dd4bbe2e40ba",tag_version="1",'
            'software_name="HughskiColorHug.efi",software_version="1.0.0"):\n'
            ' - uSwidLink(rel="see-also",href="https://hughski.com/")\n'
            ' - uSwidEntity(regid="hughsie.com",name="Richard Hughes",roles=[TAG_CREATOR,LICENSOR])\n'
            ' - uSwidEntity(regid="hughski.com",name="Hughski Limited",roles=[AGGREGATOR])',
        )

        # INI export
        tmp = uSwidFormatIni().save(uSwidContainer([component])).decode()
        assert "uSWID" in tmp
        assert "uSWID-Entity" in tmp
        assert "uSWID-Link" in tmp

        # SWID XML export
        component.colloquial_version = "22905301d08e69473393d94c3e787e4bf0453268"
        self.assertEqual(
            uSwidFormatSwid().save(uSwidContainer([component])),
            b"<?xml version='1.0' encoding='utf-8'?>\n"
            b"<SoftwareIdentity "
            b'xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" '
            b'xmlns:SHA256="http://www.w3.org/2001/04/xmlenc#sha256" '
            b'xmlns:SHA512="http://www.w3.org/2001/04/xmlenc#sha512" '
            b'xmlns:n8060="http://csrc.nist.gov/ns/swid/2015-extensions/1.0" '
            b'xml:lang="en-US" name="HughskiColorHug.efi" tagId="acbd84ff-9898-4922-8ade-dd4bbe2e40ba" '
            b'tagVersion="1" version="1.0.0">\n'
            b'  <Entity name="Richard Hughes" regid="hughsie.com" role="tagCreator licensor"/>\n'
            b'  <Entity name="Hughski Limited" regid="hughski.com" role="aggregator"/>\n'
            b'  <Link href="https://hughski.com/" rel="see-also"/>\n'
            b'  <Meta colloquialVersion="22905301d08e69473393d94c3e787e4bf0453268" '
            b'persistentId="org.hughski.colorhug" '
            b'type="firmware"/>\n'
            b"</SoftwareIdentity>\n",
        )

        # CycloneDX export
        tmp = uSwidFormatCycloneDX().save(uSwidContainer([component])).decode()
        assert "CycloneDX" in tmp
        assert "uSWID" in tmp
        assert "org.hughski.colorhug" in tmp
        assert "22905301d08e69473393d94c3e787e4bf0453268" in tmp
        assert "manufacturer" in tmp

        # SPDX export
        tmp = uSwidFormatSpdx().save(uSwidContainer([component])).decode()
        assert "SPDX" in tmp
        assert "uSWID" in tmp
        assert "supplier" in tmp

    def test_cyclonedx_metadata_component_no_duplicate(self):
        """CycloneDX metadata.component should not duplicate components list"""

        jsonstr = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {
                "component": {
                    "type": "application",
                    "name": "MyApp",
                    "version": "1.0",
                    "bom-ref": "myapp",
                },
                "authors": [{"name": "TagCreator"}],
            },
            "components": [
                {
                    "type": "application",
                    "name": "MyApp",
                    "version": "1.0",
                    "bom-ref": "myapp",
                }
            ],
        }
        container = uSwidFormatCycloneDX().load(json.dumps(jsonstr).encode())
        self.assertEqual(len(container), 1)
        component = container[0]
        self.assertEqual(component.tag_id, "myapp")
        self.assertEqual(component.software_name, "MyApp")
        self.assertTrue(
            any(
                e.name == "TagCreator" and uSwidEntityRole.TAG_CREATOR in e.roles
                for e in component.entities
            )
        )

    def test_cyclonedx_metadata_component_only(self):
        """CycloneDX metadata.component should load when components absent"""

        jsonstr = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {
                "component": {
                    "type": "application",
                    "name": "MyApp",
                    "version": "1.0",
                    "bom-ref": "myapp",
                },
                "authors": [{"name": "TagCreator"}],
            },
        }
        container = uSwidFormatCycloneDX().load(json.dumps(jsonstr).encode())
        self.assertEqual(len(container), 1)
        component = container[0]
        self.assertEqual(component.tag_id, "myapp")
        self.assertEqual(component.software_name, "MyApp")
        self.assertTrue(
            any(
                e.name == "TagCreator" and uSwidEntityRole.TAG_CREATOR in e.roles
                for e in component.entities
            )
        )

    def test_cyclonedx_metadata_component_with_components(self):
        """CycloneDX metadata.component with extra components yields two entries"""

        jsonstr = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {
                "component": {
                    "type": "application",
                    "name": "MyApp",
                    "version": "1.0",
                    "bom-ref": "myapp",
                },
                "authors": [{"name": "TagCreator"}],
            },
            "components": [
                {
                    "type": "library",
                    "name": "MyLib",
                    "version": "2.0",
                    "bom-ref": "mylib",
                }
            ],
        }
        container = uSwidFormatCycloneDX().load(json.dumps(jsonstr).encode())
        self.assertEqual(len(container), 2)
        self.assertIsNotNone(container.get_by_id("myapp"))
        self.assertIsNotNone(container.get_by_id("mylib"))

    def test_parse(self):
        """Unit tests for parsing PURL text"""
        purl = uSwidPurl("pkg:protocol/namespace/name@version?qualifiers#subpath")
        self.assertEqual(purl.scheme, "pkg")
        self.assertEqual(purl.protocol, "protocol")
        self.assertEqual(purl.namespace, "namespace")
        self.assertEqual(purl.name, "name")
        self.assertEqual(purl.version, "version")
        self.assertEqual(purl.qualifiers, "qualifiers")
        self.assertEqual(purl.subpath, "subpath")

        purl = uSwidPurl("pkg:protocol/name")
        self.assertEqual(purl.scheme, "pkg")
        self.assertEqual(purl.protocol, "protocol")
        self.assertEqual(purl.name, "name")

        purl = uSwidPurl("pkg:protocol/name@version")
        self.assertEqual(purl.scheme, "pkg")
        self.assertEqual(purl.protocol, "protocol")
        self.assertEqual(purl.namespace, None)
        self.assertEqual(purl.name, "name")
        self.assertEqual(purl.version, "version")
        self.assertEqual(purl.qualifiers, None)
        self.assertEqual(purl.subpath, None)

        purl = uSwidPurl("pkg:bcbd84ff-9898-4922-8ade-dd4bbe2e40ba@20230808")
        self.assertEqual(purl.scheme, "pkg")
        self.assertEqual(purl.protocol, None)
        self.assertEqual(purl.namespace, None)
        self.assertEqual(purl.name, "bcbd84ff-9898-4922-8ade-dd4bbe2e40ba")
        self.assertEqual(purl.version, "20230808")
        self.assertEqual(purl.qualifiers, None)
        self.assertEqual(purl.subpath, None)

    def test_spdx_single_package(self):
        """Unit tests for SPDX single package import"""
        jsonstr = {
            "spdxVersion": "SPDX-2.3",
            "creationInfo": {"creators": ["Organization: TagCo"]},
            "packages": [
                {
                    "SPDXID": "SPDXRef-pkgA",
                    "name": "pkgA",
                    "versionInfo": "1.2.3",
                    "summary": "Test package A",
                    "licenseDeclared": "BSD-2-Clause",
                    "originator": "Organization: OriginCorp",
                    "supplier": "Organization: SupplyCorp",
                }
            ],
        }
        container = uSwidFormatSpdx().load(json.dumps(jsonstr).encode())
        self.assertEqual(len(container), 1)
        comp = container[0]
        self.assertEqual(comp.tag_id, "pkgA")
        self.assertEqual(comp.software_name, "pkgA")
        self.assertEqual(comp.software_version, "1.2.3")
        # licenses extracted
        lic_ids = sorted(
            {l.spdx_id for l in comp.links if l.rel == uSwidLinkRel.LICENSE}
        )
        self.assertEqual(lic_ids, ["BSD-2-Clause"])
        # entity roles
        licensor_names = [
            e.name for e in comp.entities if uSwidEntityRole.LICENSOR in e.roles
        ]
        creator_names = [
            e.name for e in comp.entities if uSwidEntityRole.SOFTWARE_CREATOR in e.roles
        ]
        tag_creator_names = [
            e.name for e in comp.entities if uSwidEntityRole.TAG_CREATOR in e.roles
        ]
        self.assertEqual(licensor_names, ["SupplyCorp"])
        self.assertEqual(creator_names, ["OriginCorp"])
        self.assertEqual(tag_creator_names, ["TagCo"])

    def test_spdx_get_graph_nodes_by_type_graph_not_present(self):
        """SPDX 3.0 graph helper should handle missing graph"""
        self.assertIsNone(_get_graph_nodes_by_type({}, "CreationInfo"))


    def test_spdx_get_graph_nodes_by_type_graph_is_empty(self):
        """SPDX 3.0 graph helper should handle empty graph"""
        data = {"@graph": []}
        nodes = _get_graph_nodes_by_type(data, "CreationInfo")
        self.assertEqual(nodes, [])

    def test_spdx_get_graph_nodes_by_type(self):
        """SPDX 3.0 graph helper should filter nodes by type"""

        jsonstr = {
            "@graph": [
                {"type": "CreationInfo", "specVersion": "SPDX-3.0.1"},
                {"type": "software_Package", "spdxId": "http://spdx.example.com/Package1"},
                {"type": "software_Package", "spdxId": "http://spdx.example.com/Package2"},
                {"type": ["CreationInfo"]}, # ignore non-string type fields
                "not-a-dict",   # ignore non-dict entries
                {"name": "no-type"},    # ignore dicts without a type field
            ]
        }
        nodes = _get_graph_nodes_by_type(jsonstr, "software_Package")
        self.assertEqual(len(nodes), 2)
        self.assertEqual(_get_graph_nodes_by_type(jsonstr, "nonexistent_Node"), [])

    def test_spdx_detect_json_version_invalid_version(self):
        """SPDX JSON version detection should raise for invalid version"""
        with self.assertRaises(NotSupportedError):
            _detect_spdx_json_version({"invalid": "version"})

    def test_spdx_detect_json_version_2_3(self):
        """SPDX JSON version detection supports 2.3 format"""
        jsonstr = {
            "spdxVersion": "SPDX-2.3",
            "creationInfo": {"creators": ["Organization: TagCo"]},
            "packages": [
                {
                    "SPDXID": "SPDXRef-pkgA",
                    "name": "pkgA",
                    "versionInfo": "1.2.3",
                    "summary": "Test package A",
                    "licenseDeclared": "BSD-2-Clause",
                    "originator": "Organization: OriginCorp",
                    "supplier": "Organization: SupplyCorp",
                }
            ],
        }
        self.assertEqual(_detect_spdx_json_version(jsonstr), "2.3")

    def test_spdx_detect_json_version_3_0_specVersion(self):
        """SPDX JSON version detection supports 3.0 format"""
        # explicit SPDX 3.0 through CreationInfo node
        jsonstr = {
            "@graph": [
                {"type": "CreationInfo", "specVersion": "SPDX-3.0.1"},
                {"type": "software_Package", "spdxId": "http://spdx.example.com/Package1"},
                {"type": "software_Package", "spdxId": "http://spdx.example.com/Package2"},
            ]
        }
        self.assertEqual(_detect_spdx_json_version(jsonstr), "3.0")

    def test_spdx_detect_json_version_3_0_fallback(self):
        """SPDX JSON version detection supports 3.0 format fallback"""
        # fallback SPDX 3.0 if @graph exists but specVersion is absent/malformed
        self.assertEqual(_detect_spdx_json_version({"@graph": []}), "3.0")

    def test_spdx_load_2_3(self):
        """load() should route data to the right SPDX loader by detected version"""

        class _TestFormatSpdx(uSwidFormatSpdx):
            def _load_spdx23(self, data: dict[str, Any]) -> uSwidContainer:
                self._called = "2.3"  # type: ignore[attr-defined]
                return uSwidContainer([uSwidComponent(tag_id="from23")])

            def _load_spdx30(self, data: dict[str, Any]) -> uSwidContainer:
                self._called = "3.0"  # type: ignore[attr-defined]
                return uSwidContainer([uSwidComponent(tag_id="from30")])

        jsonstr = {
            "spdxVersion": "SPDX-2.3",
            "creationInfo": {"creators": ["Organization: TagCo"]},
            "packages": [
                {
                    "SPDXID": "SPDXRef-pkgA",
                    "name": "pkgA",
                    "versionInfo": "1.2.3",
                    "summary": "Test package A",
                    "licenseDeclared": "BSD-2-Clause",
                    "originator": "Organization: OriginCorp",
                    "supplier": "Organization: SupplyCorp",
                }
            ],
        }

        # SPDX 2.3 document uses _load_spdx23
        fmt_23 = _TestFormatSpdx()
        container_23 = fmt_23.load(json.dumps(jsonstr).encode())
        self.assertEqual(fmt_23.version, "2.3")
        self.assertEqual(fmt_23._called, "2.3")  # type: ignore[attr-defined]
        self.assertEqual(container_23[0].tag_id, "from23")

    def test_spdx_load_3_0(self):
        """load() should route data to the right SPDX loader by detected version"""

        class _TestFormatSpdx(uSwidFormatSpdx):
            def _load_spdx23(self, data: dict[str, Any]) -> uSwidContainer:
                self._called = "2.3"  # type: ignore[attr-defined]
                return uSwidContainer([uSwidComponent(tag_id="from23")])

            def _load_spdx30(self, data: dict[str, Any]) -> uSwidContainer:
                self._called = "3.0"  # type: ignore[attr-defined]
                return uSwidContainer([uSwidComponent(tag_id="from30")])

        jsonstr = {
            "@graph": [
                {"type": "CreationInfo", "specVersion": "SPDX-3.0.1"},
                {"type": "software_Package", "spdxId": "http://spdx.example.com/Package1"},
                {"type": "software_Package", "spdxId": "http://spdx.example.com/Package2"},
            ]
        }

        # SPDX 3.0 document uses _load_spdx30
        fmt_30 = _TestFormatSpdx()
        container_30 = fmt_30.load(json.dumps(jsonstr).encode())
        self.assertEqual(fmt_30.version, "3.0")
        self.assertEqual(fmt_30._called, "3.0")  # type: ignore[attr-defined]
        self.assertEqual(container_30[0].tag_id, "from30")

    def test_spdx30_load_single_node(self):
        """SPDX 3.0 single node loader should map fields and entity refs"""
        fmt = uSwidFormatSpdx()

        data = {
            "@graph": [
                {
                    "type": "CreationInfo",
                    "@id": "_:creationinfo",
                    "createdBy": "http://spdx.example.com/agents/person",
                    "specVersion": "3.0.1",
                },
                {
                    "type": "Person",
                    "spdxId": "http://spdx.example.com/agents/person",
                    "name": "FirstName LastName",
                    "creationInfo": "_:creationinfo",
                },
                {
                    "type": "software_Package",
                    "spdxId": "http://spdx.example.com/pkg/A",
                    "name": "pkgA",
                    "software_packageVersion": "1.0.0",
                    "originatedBy": "http://spdx.example.com/agents/person",
                    "suppliedBy": "http://spdx.example.com/agents/person",
                    "creationInfo": "_:creationinfo",
                },
                {
                    "type": "software_Package",
                    "spdxId": "http://spdx.example.com/pkg/B",
                    "name": "pkgB",
                    "software_packageVersion": "2.0.0",
                    "originatedBy": "http://spdx.example.com/agents/person",
                    "creationInfo": "_:creationinfo",
                },
                {
                    "type": "software_File",
                    "spdxId": "http://spdx.example.com/file/C",
                    "name": "fileC",
                    "originatedBy": "http://spdx.example.com/agents/person",
                    "creationInfo": "_:creationinfo",
                },
            ]
        }
        nodes_by_id: dict[str, dict[str, Any]] = {}
        for node in data["@graph"]:
            node_id = node.get("spdxId") or node.get("@id")
            if node_id:
                nodes_by_id[node_id] = node

        # select arbitrary package node to test _load_single_node
        package_node = data["@graph"][2]

        comp = fmt._load_single_node(package_node, nodes_by_id)

        # assert that the component fields are mapped correctly from the SPDX node
        self.assertEqual(comp.tag_id, package_node["spdxId"])
        self.assertEqual(comp.software_name, package_node["name"])
        self.assertEqual(comp.software_version, package_node["software_packageVersion"])

        # suppliedBy
        licensor_names = [
            e.name for e in comp.entities if uSwidEntityRole.LICENSOR in e.roles
        ]
        # originatedBy
        creator_names = [
            e.name for e in comp.entities if uSwidEntityRole.SOFTWARE_CREATOR in e.roles
        ]
        # createdBy
        tag_creator_names = [
            e.name for e in comp.entities if uSwidEntityRole.TAG_CREATOR in e.roles
        ]
        self.assertEqual(licensor_names, ["FirstName LastName"])
        self.assertEqual(creator_names, ["FirstName LastName"])
        self.assertEqual(tag_creator_names, ["FirstName LastName"])

    def test_spdx30_load_requires_graph_list(self):
        """SPDX 3.0 loader should reject documents without a graph list"""
        fmt = uSwidFormatSpdx()
        data = {
            "@graph": {"type": "software_Package"}
        }
        with self.assertRaises(NotSupportedError):
            fmt._load_spdx30(data)

    def test_spdx30_load_graph_packages(self):
        """SPDX 3.0 loader should import software_Package nodes only"""
        fmt = uSwidFormatSpdx()
        data = {
            "@graph": [
                {
                    "type": "CreationInfo",
                    "@id": "_:creationinfo",
                    "createdBy": "http://spdx.example.com/agents/person",
                    "specVersion": "3.0.1",
                },
                {
                    "type": "Person",
                    "spdxId": "http://spdx.example.com/agents/person",
                    "name": "FirstName LastName",
                    "creationInfo": "_:creationinfo",
                },
                {
                    "type": "software_Package",
                    "spdxId": "http://spdx.example.com/pkg/A",
                    "name": "pkgA",
                    "software_packageVersion": "1.0.0",
                    "originatedBy": "http://spdx.example.com/agents/person",
                    "suppliedBy": "http://spdx.example.com/agents/person",
                    "creationInfo": "_:creationinfo",
                },
                {
                    "type": "software_Package",
                    "spdxId": "http://spdx.example.com/pkg/B",
                    "name": "pkgB",
                    "software_packageVersion": "2.0.0",
                    "originatedBy": "http://spdx.example.com/agents/person",
                    "creationInfo": "_:creationinfo",
                },
                {
                    "type": "software_File",
                    "spdxId": "http://spdx.example.com/file/C",
                    "name": "fileC",
                    "originatedBy": "http://spdx.example.com/agents/person",
                    "creationInfo": "_:creationinfo",
                },
                {
                    "type": "Element", "spdxId": "http://spdx.example.com/notpkg"
                },
                "not-a-dict",
            ]
        }
        container = fmt._load_spdx30(data)
        self.assertEqual(len(container), 2)

    def test_spdx_multiple_packages_with_dep(self):
        """Unit tests for SPDX multiple packages with dependencies"""
        jsonstr: dict[str, Any] = {
            "spdxVersion": "SPDX-2.3",
            "creationInfo": {"creators": ["Organization: TagCo"]},
            "packages": [
                {
                    "SPDXID": "SPDXRef-libX",
                    "name": "libX",
                    "versionInfo": "2.0.0",
                    "licenseDeclared": "BSD-2-Clause",
                },
                {
                    "SPDXID": "SPDXRef-appY",
                    "name": "appY",
                    "versionInfo": "5.1",
                    "licenseDeclared": "GPL-3.0-only",
                },
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-appY",
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": "SPDXRef-libX",
                }
            ],
        }
        container = uSwidFormatSpdx().load(json.dumps(jsonstr).encode())
        self.assertEqual(len(container), 2)
        lib = next(c for c in container if c.tag_id == "libX")
        app = next(c for c in container if c.tag_id == "appY")
        # dependency represented as COMPONENT link to libX (per current implementation fallback)
        self.assertTrue(
            any(l.rel == uSwidLinkRel.COMPONENT and l.href == "libX" for l in app.links)
        )
        # license links exist
        app_lic = [l.spdx_id for l in app.links if l.rel == uSwidLinkRel.LICENSE]
        lib_lic = [l.spdx_id for l in lib.links if l.rel == uSwidLinkRel.LICENSE]
        self.assertEqual(app_lic, ["GPL-3.0-only"])
        self.assertEqual(lib_lic, ["BSD-2-Clause"])
        # TAG_CREATOR added from creationInfo
        self.assertTrue(
            any(
                e.name == "TagCo" and uSwidEntityRole.TAG_CREATOR in e.roles
                for e in app.entities
            )
        )

    def test_spdx_duplicate_spdxid_unique_namespace(self):
        """Duplicate SPDXIDs should be unique when documentNamespace differs"""
        json_a = {
            "spdxVersion": "SPDX-2.3",
            "documentNamespace": "urn:uuid:11111111-1111-1111-1111-111111111111",
            "creationInfo": {"creators": ["Organization: TagCo"]},
            "packages": [
                {
                    "SPDXID": "SPDXRef-dupPkg",
                    "name": "dupPkg",
                    "versionInfo": "1.0",
                }
            ],
        }
        json_b = {
            "spdxVersion": "SPDX-2.3",
            "documentNamespace": "urn:uuid:22222222-2222-2222-2222-222222222222",
            "creationInfo": {"creators": ["Organization: TagCo"]},
            "packages": [
                {
                    "SPDXID": "SPDXRef-dupPkg",
                    "name": "dupPkg",
                    "versionInfo": "2.0",
                }
            ],
        }

        fmt = uSwidFormatSpdx()
        container_a = fmt.load(json.dumps(json_a))
        container_b = fmt.load(json.dumps(json_b))

        # consolidate into one container to simulate merged SBOMs
        merged = uSwidContainer()
        for comp in list(container_a) + list(container_b):
            if comp.tag_id and not merged.get_by_id(comp.tag_id):
                merged.append(comp)

        self.assertEqual(len(merged), 2)
        self.assertIsNotNone(
            merged.get_by_id("11111111-1111-1111-1111-111111111111:dupPkg")
        )
        self.assertIsNotNone(
            merged.get_by_id("22222222-2222-2222-2222-222222222222:dupPkg")
        )


if __name__ == "__main__":
    unittest.main()
