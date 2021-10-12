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

from uswid import uSwidEntity, uSwidIdentity, uSwidRole, NotSupportedError


class TestSwidEntity(unittest.TestCase):
    def test_entity(self):

        entity = uSwidEntity(
            name="test", regid="example.com", roles=[uSwidRole.MAINTAINER]
        )
        self.assertEqual(str(entity), "uSwidEntity(test,example.com->MAINTAINER)")
        self.assertEqual(
            str(entity._export_bytes()),
            "{<uSwidGlobalMap.SOFTWARE_NAME: 1>: 'test', "
            + "<uSwidGlobalMap.REG_ID: 32>: 'example.com', "
            + "<uSwidGlobalMap.ROLE: 33>: [<uSwidRole.MAINTAINER: 6>]}",
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

    def test_identity(self):

        identity = uSwidIdentity(
            tag_id="foobarbaz",
            tag_version=5,
            software_name="foo",
            software_version="1.2.3",
        )
        self.assertEqual(str(identity), "uSwidIdentity(foobarbaz,5,foo,1.2.3)")
        entity = uSwidEntity(
            name="test", regid="example.com", roles=[uSwidRole.MAINTAINER]
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
</SoftwareIdentity>"""
        identity = uSwidIdentity()
        identity.import_xml(xml)
        self.assertEqual(
            str(identity),
            "uSwidIdentity(acbd84ff-9898-4922-8ade-dd4bbe2e40ba,1,DellBiosConnectNetwork,1.5.2):\n"
            "uSwidEntity(Dell Technologies,dell.com->SOFTWARE_CREATOR,TAG_CREATOR)",
        )

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
extra-roles = Aggregator"""
        identity = uSwidIdentity()
        identity.import_ini(ini)
        self.assertEqual(
            str(identity),
            "uSwidIdentity(acbd84ff-9898-4922-8ade-dd4bbe2e40ba,1,HughskiColorHug.efi,1.0.0):\n"
            "uSwidEntity(Richard Hughes,hughsie.com->TAG_CREATOR)\n"
            "uSwidEntity(Hughski Limited,hughski.com->AGGREGATOR)",
        )


if __name__ == "__main__":
    unittest.main()
