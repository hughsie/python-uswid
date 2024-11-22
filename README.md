python-uswid
------------

# Introduction

A Software Bill of Materials (SBOM) is a manifest of what components are included inside your software.
It helps vendors and consumers keep track of software components for better software supply chain security.

When building or creating a SBOM there are lots of formats to choose from:

- [SWID](https://csrc.nist.gov/Projects/Software-Identification-SWID/guidelines)
- [coSWID](https://datatracker.ietf.org/doc/rfc9393/)
- [CycloneDX](https://cyclonedx.org/)
- [SPDX](https://spdx.dev/)
- [goSWID](https://github.com/veraison/swid)

Using the uSWID tool allows you to **create**, **convert** and **merge** SBOM metadata to and from most of those formats, with the initial focus being functionality useful for firmware files.

Additionally, uSWID supports importing SBOM metadata from a few additional file formats:

- `.ini` files -- designed to be easier for humans to write
- `pkgconfig` -- `.pc` files that are shipped with most open source libraries
- [PE binaries](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) -- coSWID metadata can be inserted in a `.sbom` section at link time
- unspecified firmware files -- using a 24 byte header to locate the coSWID CBOR SBOM entry

There are three elements of an SBOM that uswid supports. These are:

- Identities -- the *what*, describing the software subcomponents
- Entities -- the *who*, describing the company or person responsible for the component in some way
- Payloads (optional) -- the *file* that we are referring to, for when the SBOM is not embedded
- Evidence (optional) -- the *proof*, typically the date and time the SBOM was built

One of the core features of uswid is that you can import multiple files to build a single component at construction time.

For instance, you could combine the pkgconfig `.pc` file, a `.exe` binary and `.ini` override to build one SBOM component. In most cases SBOM metadata is merged, but it can also be replaced.

There is also a [web-generator on the LVFS](https://fwupd.org/lvfs/uswid) that uses uSWID to easily build INI, coSWID and coSWID with uSWID header.

![LVFS Web Generator](docs/lvfs-uswid.png)

Some of the formats in further detail:

## SWID

Software Identification (SWID) tags provide an extensible XML-based structure to identify and describe individual software components, patches, and installation bundles.
SWID tag representations are too large for firmware with storage constraints, but is useful when importing the data into other programs and frameworks.

## coSWID

CoSWID supports a similar set of semantics and features as SWID tags, all in a more space efficient format known as [CBOR](https://cbor.io/).
This format is suitable for embedding into binary files, although the client then needs to be aware of the offset and length of the CBOR binary block of metadata.

If we know how to parse the firmware and can lookup the offset the coSWID blob starts and ends (e.g. the PE COFF header says *data is stored at 0x123, length is 0x234*) then embedding coSWID as CBOR data is appropriate.

## coSWID with uSWID header

If we are asked to process lots of different kinds of firmware, we do not always know how to parse the secret vendor-specific header, e.g.

| VENDOR_HDR | ARC_IMAGE | FREE_SPACE | coSWID | FREE_SPACE |
|------------|-----------|------------|--------|------------|

With this the SBOM builder tool does not know *where* the coSWID data starts in the blob, or *how many* coSWID sections there might be.
If we include a small header with a 16 byte *magic* identifier then we can search the image to discover the offsets to read the coSWID blobs.

The 25 byte uSWID header in full:

    uint8_t[16]   magic, "\x53\x42\x4F\x4D\xD6\xBA\x2E\xAC\xA3\xE6\x7A\x52\xAA\xEE\x3B\xAF"
    uint8_t       header version, typically 0x03
    uint16_t      little-endian header length, typically 0x19
    uint32_t      little-endian payload length
    uint8_t       flags
                    0x00: no flags set
                    0x01: compressed payload
    uint8_t       payload compression type
                    0x00: none
                    0x01: zlib
                    0x02: lzma

The uSWID header is automatically added when the file extension is `.uswid`, e.g.

    uswid --load payload.efi --load oem.ini --save ./blob.uswid

## INI File

It's sometimes much easier to use the simple key=vaue INI format when creating component SBOMs, or overriding specific values compared to building a new SWID XML document:

Let's create an example component SBOM, using the INI-file format:

    [uSWID]
    tag-id = acbd84ff-9898-4922-8ade-dd4bbe2e40ba
    software-name = HughskiColorHug
    software-version = 1.2.3
    version-scheme = multipartnumeric
    product = ColorHug
    summary = Open Source Display Colorimeter
    colloquial-version = b2ed6f1ed8587bf01a2951d74512a70f1a512d38 # of all the source files
    edition = v2021+ # identifier of the project tree, e.g. the output of 'git describe'
    revision = 2
    persistent-id = com.hughski.colorhug

    [uSWID-Entity:Distributor]
    name = Richard Hughes
    regid = hughsie.com
    extra-roles = Licensor,Maintainer,SoftwareCreator

The `tag-id` value has to be unique, but for UEFI firmware this is typically the ESRT GUID value.
The `product`, `summary`, `colloquial-version`, `revision` and `edition` values are optional but at least the first two are highly recommended.

If we are not including the SBOM into the binary, and instead building a *detached* component SBOM, we need to make sure that we can verify the blob is valid. To do this we can also add a file hash:

    [uSWID-Payload]
    name = HughskiColorHug.efi
    size = 20480
    hash = 5525fbd0911b8dcbdc6f0c081ac27fd55b75d6d261c62fa05b9bdc0b72b481f6

Or we can populate all the payload fields automatically:

    [uSWID-Payload]
    path = ../../build/src/ColorHug1/HughskiColorHug.efi

This can then be saved as `uswid.ini` and be built into **compressed** (and deduplicated) coSWID CBOR blob with a uSWID header:

    uswid --load uswid.ini --save ./HughskiColorHug.uswid --compress

You can also just append one entity to an existing CoSWID tag. This might be done by the ODM or OEM on firmware built by the IBV. Just create a `oem.ini` file with these contents:

    [uSWID-Entity:Distributor]
    name = OEM Vendor
    regid = oem.homepage.com

Which can be appended using:

    uswid --load HughskiColorHug.uswid --load oem.ini --save ./HughskiColorHug.uswid --compress

Usefully, if you load a uswid blob from an existing binary, the tag version is incremented when it is saved it again.
If that behaviour is wrong, set an explicit `tag-version` in the `[uSWID]` section.

# Adding Evidence

An evidence section can be added using:

    [uSWID-Evidence]
    date = 2023-09-15T12:34:56
    device-id = this-machine-hostname

This can also be auto-generated by uSWID using an empty `[uSWID-Evidence]` section.

# Adding Links

Dependancies like compilers or other security-relevant libraries can be added using:

    uswid --load uswid.ini compiler.ini --save ./example.uswid

Where we have added an extra link section in `uswid.ini`:

    [uSWID-Link:gcc]
    rel = compiler
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

NOTE: The GUID can be constructed from the tool or library name combined with the version, e.g. using the [web tool on the LVFS](https://fwupd.org/lvfs/guid).

...or, if a component has been previously defined, you can use the name to contruct the SWID automatically:

    [uSWID-Link:image_loading_lib]
    rel = requires
    href = swid:libjpeg

Alternatively, we can tell the user where to find the installation package:

    [uSWID-Link:src]
    rel = installationmedia
    href = https://github.com/intel/FSP/AmberLakeFspBinPkg

If the binary content is licensed in a permissive or open-source way it should be identified as such.
To do this, you can either use the SWID XML format:

    <SoftwareIdentity …>
    <Entity … />
    <Link rel="license" href="https://spdx.org/licenses/LGPL-2.1-or-later.html"/>
    </SoftwareIdentity>

Or the INI override format:

    [uSWID-Link]
    rel = license
    href = https://spdx.org/licenses/LGPL-2.1-or-later.html

# Substituted Values

All text SBOM formats (e.g. CycloneDX, SPDX, SWID, but *not* coSWID) can use substitute values anywhere in the file.
For instance, `@VCS_TAG@` can be used to signify the last tagged version from git rather than hardcoding during the release process.

The supported values are given below:

## @VCS_TAG@

The semantic version of the last version control tag, for example `1.2.3`.

NOTE: Any prefixed or suffixed non-semantic version contents are also removed, so `v1.2.3->1.2.3` and `krb5-1.21.3-final->1.21.3`.

For git, generated using: `git describe --tags --abbrev=0`

## @VCS_VERSION@

The version control identifier that includes information about how far we are from the last commit.

For example `1.2.3-250-gfa2371946` when there have been 250 additional commits since the last tag or `1.2.3` in the case of no additional commits since the last tag.

For git, generated using: `git describe --tags`

## @VCS_BRANCH@

The version control branch in use, for example `staging`, `master` or `main`.

For git, generated using: `git rev-parse --abbrev-ref HEAD`

## @VCS_COMMIT@

The version control full commit, typically a SHA-1 or SHA-256 hash. For example `3090e61ee3452c0478860747de057c0269bfb7b6`.

For git, generated using: `git rev-parse HEAD`

## @VCS_SBOM_AUTHORS@

The authors of the SBOM file itself, for example `Example User, Another User`.

NOTE: Only authors contributing more than 10% of the file commits (or more than 10 commits) are included by default.

For git, generated using: `git shortlog HEAD -n -s -- bom.json`

## @VCS_SBOM_AUTHOR@

The first listed `@VCS_SBOM_AUTHORS@`, for example `Example User`.

## @VCS_AUTHORS@

The authors of the project as registed in version control, for example `Example User, Another User`.

NOTE: Only authors contributing more than 5% of the project commits (or more than 5 commits) are included by default.

For git, generated using: `git shortlog HEAD -n -s`

## @VCS_AUTHOR@

The first listed `@VCS_AUTHORS@`, for example `Example User`.

Patches are very welcome for other source control systems, e.g. `svn` or `hg`.

# Reading and writing to PE files

By default, the uswid command line uses `pefile` to read and write the `.sbom` section in the COFF header.
Although reading is well supported and tested, support for writing modified files has only been lightly tested as most `.sbom` sections are added automatically at link time by the compiler.

If `pefile` doesn't add the SWID metadata to the PE file correctly, you can use the alternate method of using `objcopy`, either available by default on Linux or installable using WSL on Windows. e.g.

    uswid --load sbom.ini --save ./payload.efi --objcopy /usr/bin/objcopy

You can use `objdump -s -j .sbom payload.efi` to verify that the tag has been written correctly to the binary.

# Generating Test Data

The `uswid` CLI can generate a complete "worst case" platform SBOM, with 1000 plausible (but random) components. This is generates a ~140kB file, or ~60kB when compressed with LZMA.

You can use the uswid command line to generate a plausible UEFI platform SBOM:

    uswid --generate --save test.uswid --compression lzma

Each generated component includes:

 * A unique tag-id GUID
 * A unique software-name of size 4-30 chars
 * A colloquial-version from a random selection of 10 SHA-1 hashes
 * An edition from a random SHA-1 hash
 * A semantic version of size 3-8 chars
 * An entity from a random selection of 10 entities

# Building Composite SBOMs

The `uswid` CLI can scan a target directory and locate component SBOMs in various formats.
To do this, it uses specific hardcoded filenames for different SBOM formats, for example:

 * `bom.coswid` → CoSWID
 * `sbom.cdx.json` → CycloneDX
 * `sbom.ini` → INI
 * `sbom.spdx.json` → SPDX
 * `swid.xml` → SWID

To use this functionality, use something like `uswid --find ~/Code/edk2 --save sbom.uswid`

# VEX

The `uswid` binary can load VEX data from [OpenVEX](https://github.com/openvex) and [CSAF-2.0](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html) files, and will generate a report for the end-user.

For example:

    uswid --load examples/intel-ucode.ini examples/intel-ucode.vex --verbose
    Loaded:
    uSwidComponent(tag_id="bcbd84ff-9898-4922-8ade-dd4bbe2e40ba",tag_version="0",software_name="MCU 06-03-02",software_version="20230808"):
     - uSwidEntity(regid="com.intel",name="Intel Corporation",roles=TAG_CREATOR,SOFTWARE_CREATOR)
     - uSwidPayload(name="intel-ucode-06-03-02",size=12)
     - uSwidHash(alg_id=SHA256,value="a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447")
     - uSwidEvidence(date="2023-09-15 12:34:56",device_id=None)
     - uSwidVexStatement(vulnerability_name="CVE-2022-40982",status="uSwidVexStatementStatus.NOT_AFFECTED",justification="uSwidVexStatementJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH",impact_statement="These processors do not use GDS and are not vulnerable to this CVE."):
       - uSwidVexProduct(tag_ids="[uSwidPurl("pkg:swid/bcbd84ff-9898-4922-8ade-dd4bbe2e40ba")]"):
         - uSwidHash(alg_id=SHA256,value="a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447")

# Installing

This library and helper binary can be installed using `pip`:

    pip install --user uswid

This will download any required dependancies and also install the `uswid` tool into your bindir.

To use the latest in-development code:

    pip install --user git+https://github.com/hughsie/python-uswid.git

## Using uswid as an API

uSWID can also be used programmatically via the Python API, please consult the [API documentation](https://uswid.readthedocs.io/en/latest/) for more details.

# Contributing

I'm accepting merge requests to add missing functionality or to make the code more robust.

# See Also

- [UEFI Buildsystem Example](https://github.com/hughsie/uswid-uefi-example)
- [fwupd  coSWID builder](https://github.com/fwupd/fwupd/blob/main/libfwupdplugin/tests/coswid.builder.xml)
