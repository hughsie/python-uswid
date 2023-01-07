#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=wrong-import-position,protected-access

import os
import sys
import unittest
from lxml import etree as ET

# allows us to run this from the project root
sys.path.append(os.path.realpath("."))

from .container import uSwidContainer
from .errors import NotSupportedError
from .link import uSwidLink
from .entity import uSwidEntity, uSwidEntityRole
from .enums import uSwidVersionScheme
from .identity import uSwidIdentity

from .format_ini import uSwidFormatIni
from .format_coswid import uSwidFormatCoswid
from .format_swid import uSwidFormatSwid
from .format_cyclonedx import uSwidFormatCycloneDX


class TestSwidEntity(unittest.TestCase):
    def test_entity(self):

        entity = uSwidEntity(
            name="test", regid="example.com", roles=[uSwidEntityRole.MAINTAINER]
        )
        self.assertEqual(str(entity), "uSwidEntity(test,example.com->MAINTAINER)")
        self.assertEqual(
            str(uSwidFormatCoswid()._save_entity(entity)),
            "{<uSwidGlobalMap.ENTITY_NAME: 31>: 'test', "
            + "<uSwidGlobalMap.REG_ID: 32>: 'example.com', "
            + "<uSwidGlobalMap.ROLE: 33>: <uSwidEntityRole.MAINTAINER: 6>}",
        )

        entity.roles.append(uSwidEntityRole.SOFTWARE_CREATOR)
        self.assertEqual(
            str(uSwidFormatCoswid()._save_entity(entity)),
            "{<uSwidGlobalMap.ENTITY_NAME: 31>: 'test', "
            + "<uSwidGlobalMap.REG_ID: 32>: 'example.com', "
            + "<uSwidGlobalMap.ROLE: 33>: [<uSwidEntityRole.MAINTAINER: 6>, "
            + "<uSwidEntityRole.SOFTWARE_CREATOR: 2>]}",
        )

        # SWID XML import
        entity = uSwidEntity()
        uSwidFormatSwid()._load_entity(
            entity,
            ET.Element(
                "Entity",
                attrib={"name": "foo", "regid": "bar", "role": "tagCreator maintainer"},
            ),
        )
        self.assertEqual(str(entity), "uSwidEntity(foo,bar->TAG_CREATOR,MAINTAINER)")
        with self.assertRaises(NotSupportedError):
            uSwidFormatSwid()._load_entity(
                entity,
                ET.Element(
                    "Entity", attrib={"name": "foo", "regid": "bar", "role": "baz"}
                ),
            )

        # INI import
        entity = uSwidEntity()
        uSwidFormatIni()._load_entity(
            entity,
            {"name": "foo", "regid": "bar", "extra-roles": "TagCreator,Maintainer"},
            role_hint="Distributor",
        )
        self.assertEqual(str(entity), "uSwidEntity(foo,bar->TAG_CREATOR,MAINTAINER)")
        with self.assertRaises(NotSupportedError):
            uSwidFormatIni()._load_entity(
                entity, {"name": "foo", "regid": "bar", "extra-roles": "baz"}
            )

        # SWID XML export
        root = ET.Element("SoftwareIdentity")
        uSwidFormatSwid()._save_entity(entity, root)
        self.assertEqual(
            ET.tostring(root, encoding="utf-8"),
            b"<SoftwareIdentity>"
            b'<Entity name="foo" regid="bar" role="tagCreator maintainer"/>'
            b"</SoftwareIdentity>",
        )

    def test_link(self):

        # enumerated type
        link = uSwidLink(href="http://test.com/", rel="see-also")
        self.assertEqual(str(link), "uSwidLink(http://test.com/,see-also)")
        self.assertEqual(
            str(uSwidFormatCoswid()._save_link(link)),
            "{<uSwidGlobalMap.HREF: 38>: 'http://test.com/', "
            + "<uSwidGlobalMap.REL: 40>: <uSwidLinkRel.SEE_ALSO: 9>}",
        )

        # rel from IANA "Software Tag Link Relationship Values" registry
        link = uSwidLink(href="http://test.com/", rel="license")
        self.assertEqual(str(link), "uSwidLink(http://test.com/,license)")
        self.assertEqual(
            str(uSwidFormatCoswid()._save_link(link)),
            "{<uSwidGlobalMap.HREF: 38>: 'http://test.com/', "
            + "<uSwidGlobalMap.REL: 40>: <uSwidLinkRel.LICENSE: -2>}",
        )

        # SWID XML import
        link = uSwidLink()
        uSwidFormatSwid()._load_link(
            link,
            ET.Element(
                "Url",
                attrib={"href": "http://test.com/", "rel": "seeAlso"},
            ),
        )
        self.assertEqual(str(link), "uSwidLink(http://test.com/,see-also)")

        # INI import
        link = uSwidLink()
        uSwidFormatIni()._load_link(
            link,
            {"href": "http://test.com/", "rel": "see-also"},
        )
        self.assertEqual(str(link), "uSwidLink(http://test.com/,see-also)")

        # SWID XML export
        root = ET.Element("SoftwareIdentity")
        uSwidFormatSwid()._save_link(link, root)
        self.assertEqual(
            ET.tostring(root, encoding="utf-8"),
            b"<SoftwareIdentity>"
            b'<Link href="http://test.com/" rel="see-also"/>'
            b"</SoftwareIdentity>",
        )

    def test_identity(self):

        identity = uSwidIdentity(
            tag_id="foobarbaz",
            tag_version=5,
            software_name="foo",
            software_version="1.2.3",
        )
        identity.version_scheme = uSwidVersionScheme.MULTIPARTNUMERIC
        self.assertEqual(str(identity), "uSwidIdentity(foobarbaz,5,foo,1.2.3)")
        entity = uSwidEntity(
            name="test", regid="example.com", roles=[uSwidEntityRole.MAINTAINER]
        )
        identity.add_entity(entity)
        self.assertEqual(
            str(identity),
            "uSwidIdentity(foobarbaz,5,foo,1.2.3):\nuSwidEntity(test,example.com->MAINTAINER)",
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
        identity = uSwidFormatSwid().load(xml).get_default()  # type: ignore
        self.assertEqual(
            str(identity),
            "uSwidIdentity(acbd84ff-9898-4922-8ade-dd4bbe2e40ba,1,DellBiosConnectNetwork,1.5.2):\n"
            "uSwidLink(http://hughsie.com,see-also)\n"
            "uSwidLink(www.gnu.org/licenses/gpl.txt,license)\n"
            "uSwidEntity(Dell Technologies,dell.com->SOFTWARE_CREATOR,TAG_CREATOR)",
        )
        self.assertEqual(
            identity.summary,
            "Linux distribution developed by the community-supported Fedora Project",
        )
        self.assertEqual(identity.product, "Fedora")
        self.assertEqual(identity.colloquial_version, "29")
        self.assertEqual(identity.persistent_id, "org.hughski.colorhug")

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
        identity = uSwidFormatIni().load(ini.encode()).get_default()  # type: ignore
        self.assertIsNotNone(identity)
        self.assertEqual(
            str(identity),
            "uSwidIdentity(acbd84ff-9898-4922-8ade-dd4bbe2e40ba,1,HughskiColorHug.efi,1.0.0):\n"
            "uSwidLink(https://hughski.com/,see-also)\n"
            "uSwidEntity(Richard Hughes,hughsie.com->TAG_CREATOR)\n"
            "uSwidEntity(Hughski Limited,hughski.com->AGGREGATOR)",
        )

        # INI export
        tmp = uSwidFormatIni().save(uSwidContainer([identity])).decode()
        assert "uSWID" in tmp
        assert "uSWID-Entity" in tmp
        assert "uSWID-Link" in tmp

        # SWID XML export
        identity.colloquial_version = "22905301d08e69473393d94c3e787e4bf0453268"
        self.assertEqual(
            uSwidFormatSwid().save(uSwidContainer([identity])),
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
            b'persistentId="org.hughski.colorhug"/>\n'
            b"</SoftwareIdentity>\n",
        )

        # CycloneDX export
        tmp = uSwidFormatCycloneDX().save(uSwidContainer([identity])).decode()
        assert "CycloneDX" in tmp
        assert "uSWID" in tmp
        assert "org.hughski.colorhug" in tmp
        assert "22905301d08e69473393d94c3e787e4bf0453268" in tmp


if __name__ == "__main__":
    unittest.main()
