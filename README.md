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
 * A JSON version of the same XML schema
 * A ini-file override document
 * A pkg-config library definition

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
    version-scheme = multipartnumeric
    product = ColorHug
    summary = Open Source Display Colorimeter
    colloquial-version = b2ed6f1ed8587bf01a2951d74512a70f1a512d38
    edition = v2021+
    revision = 2
    persistent-id = com.hughski.colorhug

This can then be saved as `uswid.ini` and applied to the binary using:

    uswid --load uswid.ini --save ./HughskiColorHug.efi

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

    uswid --load ./HughskiColorHug.efi --load oem.ini --save ./HughskiColorHug.efi

This will add the `Distributor` entity to the binary, or overwrite an existing
entity with that role.

Usefully, if you load a uswid blob from an existing binary, the tag version is
incremented when you save it again. If you don't want that, set an explicit
`tag-version` in the `[uSWID]` section.

If there are multiple loaded identities (for instance, using a `uswid` file, or
using `--load` multiple times) then you can specify the correct identity using:

    [uSWID]
    tag-id = acbd84ff-9898-4922-8ade-dd4bbe2e40ba

    [uSWID-Entity:Distributor]
    name = OEM Vendor
    regid = oem.homepage.com

Adding Deps
-----------

Dependancies like compilers or other security-relevant libraries can be done using:

    uswid --load uswid.ini --load compiler.ini --save ./example.uswid

Where we've added an extra link section in `uswid.ini`:

    [uSWID-Link:gcc]
    rel = see-also
    href = swid:077b4576-92f7-52fd-94eb-af9fc3d52c58

Where `compiler.ini` looks something like:

    [uSWID]
    tag-id = 077b4576-92f7-52fd-94eb-af9fc3d52c58
    software-name = gcc
    software-version = 12.1.1
    version-scheme = multipartnumeric

    [uSWID-Entity:TagCreator]
    name = Hughski Limited
    regid = hughski.com

...or for several dependencies that have been included into the firmware:

    [uSWID-Link:libpng]
    rel = requires
    href = swid:077b4576-92f7-52fd-94eb-af9fc3d52c58

    [uSWID-Link:libjpeg]
    rel = requires
    href = swid:3aab57c3-5661-5731-800d-db5a7f0886c1

NOTE: The GUID can be constructed from the tool or library name combined with
the version, e.g using `appstream-util generate-guid gcc-12.1.1` or the
[online tool hosted by the LVFS](https://fwupd.org/lvfs/guid).

RAW Blobs
---------

uSWID can also export a raw blob that can be embedded in a unspecified data
section. This allows coSWID metadata to be easily embedded in non-free tools.

If we know how to parse the firmware and can lookup the offset the coSWID blob
starts and ends (e.g. the PE COFF header says *data is stored at 0x123, length
is 0x234*) then we don't need anything else to read the embedded coSWID data.
The LVFS extracts the PE files from the UEFI capsule and know exactly where the
coSWID can be found thanks to the COFF header, so we store raw coSWID in PE files.

If we are asked to process lots of different kinds of firmware, we cannot always
parse the secret vendor-specific header, e.g.

    VENDOR_HEADER
    ARC32_IMAGE1
    ARC32_IMAGE2
    FREE_SPACE
    coSWID
    FREE_SPACE

With this the SBoM aggregator tool does not know *where* the coSWID data starts in
the blob, or *how many* coSWID sections there might be.
If we include a small header with a 16 byte magic GUID then we can search the image
to discover the offsets to read the coSWID blobs, e.g.

    VENDOR_HEADER
    ARC32_IMAGE1
    ARC32_IMAGE2
    FREE_SPACE
    uSWID_HEADER
    coSWID
    FREE_SPACE

For space reasons, if we wanted to just include the "raw" coSWID blob in the file
then we'd need to teach the LVFS how to process that specific kind of firmware blob.
Which might actually be fine, but you'd be volunteering to do that work. :)

    uswid --load oem.ini --save ./blob.uswid

The `blob.uswid` file then includes a 16 byte *random* GUID prefixing a simple 7-byte
little-endian header:

    uint8_t[16]   magic string, "\x53\x42\x4F\x4D\xD6\xBA\x2E\xAC\xA3\xE6\x7A\x52\xAA\xEE\x3B\xAF"
    uint8_t       header version, typically 0x02
    uint16_t      header length, typically 0x17
    uint32_t      payload length
    uint8_t       flags
                    0x01: zlib compressed payload

This allows an aggregator tool to easily aggregate multiple coSWID sources from a
composite image into a single SBoM.

Multiple coSWIDs in one uSWID
-----------------------------

You can merge multiple uSWID files into one uSWID, and compress the result to
dramatically reduce the amount of space used for multiple SWID blobs -- while
still being compatible with any tools using uswid like the LVFS.

To merge multiple uSWID files into a compressed single file, simply do:

    uswid --load ucode.uswid --load acm.uswid--save ./combined.uswid --compress

Reading and writing to PE files
-------------------------------

By default, the uswid command line uses `pefile` to read and write the `.sbom`
section in the COFF header. Although reading is well supported and tested,
support for writing modified files has only been lightly tested.

If `pefile` doesn't do a very good job of adding the SWID metadata to the PE
file, you can use the older more-trusted method of using `objcopy`, either
available by default on Linux or installable using WSL on Windows.

To use the tried-and-trusted objcopy method this you can use:

    uswid --load oem.ini --save ./blob.uswid --objcopy /usr/bin/objcopy

Please let us know if writing PE files does not work for you using the default
`pefile` method as we'll be deprecating the `objcopy` method longer term.

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

    export release_ver="0.3.4"
    git commit -a -m "Release ${release_ver}"
    git tag -s -f -m "Release ${release_ver}" "${release_ver}"
    make pkg
    ./env/bin/twine upload dist/uswid-${release_ver}*
    # edit setup.py
    git commit -a -m "trivial: post release version bump"
    git push
    git push --tags
