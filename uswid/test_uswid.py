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

from .errors import NotSupportedError
from .link import uSwidLink
from .entity import uSwidEntity, uSwidEntityRole
from .identity import uSwidIdentity


class TestSwidEntity(unittest.TestCase):
    def test_entity(self):

        entity = uSwidEntity(
            name="test", regid="example.com", roles=[uSwidEntityRole.MAINTAINER]
        )
        self.assertEqual(str(entity), "uSwidEntity(test,example.com->MAINTAINER)")
        self.assertEqual(
            str(entity._export_bytes()),
            "{<uSwidGlobalMap.SOFTWARE_NAME: 1>: 'test', "
            + "<uSwidGlobalMap.REG_ID: 32>: 'example.com', "
            + "<uSwidGlobalMap.ROLE: 33>: [<uSwidEntityRole.MAINTAINER: 6>]}",
        )

        # XML import
        entity = uSwidEntity()
        entity._import_xml(
            ET.Element(
                "Entity",
                attrib={"name": "foo", "regid": "bar", "role": "tagCreator maintainer"},
            )
        )
        self.assertEqual(str(entity), "uSwidEntity(foo,bar->TAG_CREATOR,MAINTAINER)")
        with self.assertRaises(NotSupportedError):
            entity._import_xml(
                ET.Element(
                    "Entity", attrib={"name": "foo", "regid": "bar", "role": "baz"}
                )
            )

        # INI import
        entity = uSwidEntity()
        entity._import_ini(
            {"name": "foo", "regid": "bar", "extra-roles": "TagCreator,Maintainer"},
            role_hint="Distributor",
        )
        self.assertEqual(str(entity), "uSwidEntity(foo,bar->TAG_CREATOR,MAINTAINER)")
        with self.assertRaises(NotSupportedError):
            entity._import_ini({"name": "foo", "regid": "bar", "extra-roles": "baz"})

        # XML export
        root = ET.Element("SoftwareIdentity")
        entity._export_xml(root)
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
            str(link._export_bytes()),
            "{<uSwidGlobalMap.HREF: 38>: 'http://test.com/', "
            + "<uSwidGlobalMap.REL: 40>: <uSwidLinkRel.SEE_ALSO: 9>}",
        )

        # rel from IANA "Software Tag Link Relationship Values" registry
        link = uSwidLink(href="http://test.com/", rel="license")
        self.assertEqual(str(link), "uSwidLink(http://test.com/,license)")
        self.assertEqual(
            str(link._export_bytes()),
            "{<uSwidGlobalMap.HREF: 38>: 'http://test.com/', "
            + "<uSwidGlobalMap.REL: 40>: 'license'}",
        )

        # XML import
        link = uSwidLink()
        link._import_xml(
            ET.Element(
                "Url",
                attrib={"href": "http://test.com/", "rel": "seeAlso"},
            )
        )
        self.assertEqual(str(link), "uSwidLink(http://test.com/,see-also)")

        # INI import
        link = uSwidLink()
        link._import_ini(
            {"href": "http://test.com/", "rel": "see-also"},
        )
        self.assertEqual(str(link), "uSwidLink(http://test.com/,see-also)")

        # XML export
        root = ET.Element("SoftwareIdentity")
        link._export_xml(root)
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
        self.assertEqual(str(identity), "uSwidIdentity(foobarbaz,5,foo,1.2.3)")
        entity = uSwidEntity(
            name="test", regid="example.com", roles=[uSwidEntityRole.MAINTAINER]
        )
        identity.add_entity(entity)
        self.assertEqual(
            str(identity),
            "uSwidIdentity(foobarbaz,5,foo,1.2.3):\nuSwidEntity(test,example.com->MAINTAINER)",
        )

        # XML import
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
<Meta product="Fedora" colloquialVersion="29"
  summary="Linux distribution developed by the community-supported Fedora Project" />
</SoftwareIdentity>"""
        identity = uSwidIdentity()
        identity.import_xml(xml)
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

        # INI import
        ini = """[uSWID]
tag-id = acbd84ff-9898-4922-8ade-dd4bbe2e40ba
tag-version = 1
software-name = HughskiColorHug.efi
software-version = 1.0.0

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
        identity = uSwidIdentity()
        identity.import_ini(ini)
        self.assertEqual(
            str(identity),
            "uSwidIdentity(acbd84ff-9898-4922-8ade-dd4bbe2e40ba,1,HughskiColorHug.efi,1.0.0):\n"
            "uSwidLink(https://hughski.com/,see-also)\n"
            "uSwidEntity(Richard Hughes,hughsie.com->TAG_CREATOR)\n"
            "uSwidEntity(Hughski Limited,hughski.com->AGGREGATOR)",
        )

        # INI export
        tmp = identity.export_ini()
        assert "uSWID" in tmp
        assert "uSWID-Entity" in tmp
        assert "uSWID-Link" in tmp

        # XML export
        identity.colloquial_version = "22905301d08e69473393d94c3e787e4bf0453268"
        self.assertEqual(
            identity.export_xml(),
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
            b'  <Meta colloquialVersion="22905301d08e69473393d94c3e787e4bf0453268"/>\n'
            b"</SoftwareIdentity>\n",
        )


if __name__ == "__main__":
    unittest.main()
