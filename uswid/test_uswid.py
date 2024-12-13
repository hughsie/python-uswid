#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# pylint: disable=wrong-import-position,protected-access

import os
import sys
import unittest
from typing import Optional
import shutil
import subprocess

from lxml import etree as ET

# allows us to run this from the project root
sys.path.append(os.path.realpath("."))

from .container import uSwidContainer
from .errors import NotSupportedError
from .link import uSwidLink, uSwidLinkRel
from .entity import uSwidEntity, uSwidEntityRole
from .enums import uSwidVersionScheme
from .component import uSwidComponent
from .hash import uSwidHash, uSwidHashAlg
from .payload import uSwidPayload

from .format_ini import uSwidFormatIni
from .format_coswid import uSwidFormatCoswid
from .format_swid import uSwidFormatSwid
from .format_cyclonedx import uSwidFormatCycloneDX
from .format_spdx import uSwidFormatSpdx
from .vcs import uSwidVcs

from .purl import uSwidPurl


class TestSwidEntity(unittest.TestCase):
    """Tescases for components, entities, links, evidence and payloads"""

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

    def test_vcs(self):
        """Unit tests for uSwidVcs"""

        tmp_remote = "/tmp/remote"
        try:
            shutil.rmtree(tmp_remote)
        except FileNotFoundError:
            pass
        subprocess.run(
            ["git", "init", tmp_remote, "--initial-branch", "main"],
            cwd=".",
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.email", "admin@example.com"],
            cwd=tmp_remote,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "RH"],
            cwd=tmp_remote,
            check=True,
        )
        subprocess.run(
            ["mkdir", "contrib"],
            cwd=tmp_remote,
            check=True,
        )
        with open("/tmp/remote/contrib/bom.cdx.json", "wb") as f:
            f.write(b"hello")
        subprocess.run(
            ["git", "add", "contrib/bom.cdx.json"],
            cwd=tmp_remote,
            check=True,
        )
        subprocess.run(
            ["git", "commit", "-a", "-m", "Add SBOM"],
            cwd=tmp_remote,
            check=True,
            env={},
        )
        subprocess.run(
            ["git", "tag", "v1.2.3"],
            cwd=tmp_remote,
            check=True,
        )
        with open("/tmp/remote/contrib/bom.cdx.json", "wb") as f:
            f.write(b"hello world")
        subprocess.run(
            ["git", "commit", "-a", "-m", "A SBOM fixup"],
            cwd=tmp_remote,
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
            cwd=tmp_remote,
            check=True,
        )

        vcs = uSwidVcs(filepath=os.path.join(tmp_remote, "contrib", "bom.cdx.json"))

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
        self.assertEqual(value, "/tmp/remote")

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
            ' - uSwidEntity(regid="hughsie.com",name="Richard Hughes",roles=[TAG_CREATOR])\n'
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
            b'  <Entity name="Richard Hughes" regid="hughsie.com" role="tagCreator"/>\n'
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

        # SPDX export
        tmp = uSwidFormatSpdx().save(uSwidContainer([component])).decode()
        assert "SPDX" in tmp
        assert "uSWID" in tmp

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


if __name__ == "__main__":
    unittest.main()
