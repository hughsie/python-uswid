python-uswid
============

Introduction
------------

Software Identification (SWID) tags provide an extensible XML-based structure to
identify and describe individual software components, patches, and installation
bundles. SWID tag representations can be too large for devices with network and
storage constraints.

CoSWID supports a similar set of semantics and features as SWID tags, as well
as new semantics that allow us to describe additional types of information, all
in a more memory efficient format.

We wanted to write up some text recommending a particular tool to be integrated
into the tianocore build process, but they all are not exactly awesome:

 * The [official tool from NIST](https://github.com/usnistgov/swid-tools) is a
   huge Java codebase that hasn't been updated for some time and doesn't work
   with any versions than Java 9 and that's been end-of-support since 2018.

 * A [go implementation](https://github.com/veraison/swid) exists, but it
   requires the BIOS engineer to write actual code.

Installing
----------

This library and helper binary can be installed using `pip`. Simply do:

    pip install uswid

This will download any required dependancies and also install the `uswid` tool
into your bindir.

Use Cases
---------

This tooling is provided so that OEMs, ODMs and IBVs can add uswid tags to
existing EFI binaries, typically bundled up into UEFI firmware.
The example program supports loading from either:

 * The `.sbom` section that already exists in the binary
 * A SWID XML document
 * A ini-file override document

The data sources are loaded in this order, and all are optional. In general
values overwrite each other, with the exception of entities, which are appended.

A common use-case might be to add the data to a vendor-supplied binary file,
lets use the `HughskiColorHug.efi` as our example here. Let's create some
example data, using the compact ini-file format rather than a full-blown SWID
XML document:

    [uSWID]
    tag-id = acbd84ff-9898-4922-8ade-dd4bbe2e40ba
    software-name = HughskiColorHug.efi
    software-version = 1.2.3
    product = ColorHug
    summary = Open Source Display Colorimeter
    colloquial-version = b2ed6f1ed8587bf01a2951d74512a70f1a512d38
    edition = v2021+
    revision = 2

This can then be saved as `uswid.ini` and applied to the binary using:

    uswid --inifile uswid.ini --binfile ./HughskiColorHug.efi

The `tag-id` value has to be unique, but for UEFI firmware this is typically
the ESRT GUID value. The `product`, `summary`, `colloquial-version`, `revision`
and `edition` values are optional but at least the first two are highly
recommended.

Of course, we want to include in the uswid blob which vendor actually created
the tag, and for this we can define an entity in `uswid.ini`:

    [uSWID-Entity:TagCreator]
    name = Hughski Limited
    regid = hughski.com

and we also want to say who the distributor of the project is, so we also add:

    [uSWID-Entity:Distributor]
    name = Richard Hughes
    regid = hughsie.com
    extra-roles = Licensor,Maintainer,SoftwareCreator

Did you notice the `extra-roles` tag? That's useful when one entity performs
multiple roles.

You can also just append one entity to an existing CoSWID tag. This might be
done by the ODM or OEM on firmware built by the IBV. Just create a `oem.ini`
file with these contents:

    [uSWID-Entity:Distributor]
    name = OEM Vendor
    regid = oem.homepage.com

...and then use:

    uswid --inifile oem.ini --binfile ./HughskiColorHug.efi

This will add the `Distributor` entity to the binary, or overwrite an existing
entity with that role.

Usefully, if you load a uswid blob from an existing binary, the tag version is
incremented when you save it again. If you don't want that, set an explicit
`tag-version` in the `[uSWID]` section.

RAW Blobs
---------

uSWID can also export a raw blob that can be embedded in a unspecified data
section. This allows coSWID metadata to be easily embedded in non-free tools.

    uswid --inifile oem.ini --rawfile ./raw.bin

The `raw.bin` file also includes a 16 byte *random* GUID prefixing a simple
header.
This allows a program to aggregate multiple coSWID sources from a composite
image into a single SBOM.

License Information
-------------------

If the binary content is licensed in a permissive or open-source way it
should be identified as such.
To do this, you can either use the SWID XML format:

    <SoftwareIdentity …>
    <Entity … />
    <Link rel="license" href="https://spdx.org/licenses/LGPL-2.1-or-later.html"/>
    </SoftwareIdentity>

Or the `ini` override format:

    [uSWID-Link]
    rel = license
    href = https://spdx.org/licenses/LGPL-2.1-or-later.html

Testing
-------

You can use `objdump -s -j .sbom` to verify that the tag has been written
correctly to the EFI binary.

Contributing
------------

I wrote this tool for my use case (hence why it only supports a tiny subset of
the CoSWID spec), but I'm accepting patches to add missing functionality or to
make the code more robust.

# Release Process

    update setup.py
    make pkg
    ./env/bin/twine upload dist/*
