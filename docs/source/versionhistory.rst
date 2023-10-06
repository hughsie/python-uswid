Version history
===============

.. currentmodule:: uswid

This library adheres to `Semantic Versioning <http://semver.org/>`_.

**0.4.4** (2023-10-06)

 - Add RTD generated docs (Richard Hughes)
 - Add support for SWID evidence to support the CISA SBOM Tooling guide (Richard Hughes)
 - Ensure that payload.size is always an integer (Richard Hughes)
 - Optionally provide the identity on each swid:-prefixed link (Richard Hughes)

**0.4.3** (2023-10-02)

 - Accept ``cbor`` file extensions as coSWID (Richard Hughes)
 - Add cflags argument (Callum Farmer)
 - Add support for SWID payload sections (Richard Hughes)
 - Add support for hashes in the CycloneDX export (Richard Hughes)
 - Allow loading the coSWID ``tag_id`` as a string (Richard Hughes)
 - Allow loading the payload from an explicit path (Richard Hughes)
 - Automatically calculate the INI payload hash and size (Richard Hughes)
 - Do not allow two payload hashes of the same type (Richard Hughes)
 - Do not assume that goSWID files have a ``software-meta`` section (Richard Hughes)
 - Do not require an ``edition`` to set the ``product`` (Richard Hughes)
 - Load the GoSWID identity correctly (Richard Hughes)
 - Make the goSWID importer cope with one-or-more in all cases (Richard Hughes)

**0.4.2** (2023-09-18)

 - Allow generating 1000 plausible identities for testing (Richard Hughes)
 - Allow specifying the SWID link hrefs by name as well as UUID (Richard Hughes)
 - Autocreate the identity ID from the software-name if required (Richard Hughes)
 - Fix exporting and importing goSWID XML when there is more than one identity (Richard Hughes)
 - Make ``--load`` use multiple files (Martin Fernandez)

**0.4.1** (2023-01-31)

 - Switch to cbor2 for coSWID files (Richard Hughes)

**0.4.0** (2023-01-07)

 - Add support for CycloneDX export (Richard Hughes)
 - Split out the import and exporters into different source files (Richard Hughes)

**0.3.4** (2023-01-04)

 - Add a convenience property for the href to display (Richard Hughes)
 - Don't show a fallback warning when loading .uswid files (Richard Hughes)
 - Fix up incomplete link data during import (Richard Hughes)
 - Load multiple identities from the JSON file (Richard Hughes)
 - Save all identities when exporting to JSON (Richard Hughes)
 - Store the entity role as a single string if only one item (Richard Hughes)

**0.3.3** (2022-10-06)

 - Add CoSWID as an export file type (Richard Hughes)
 - Add Compiler Link type (CodingVoid)
 - Add License link type (Maximilian Brune)

**0.3.2** (2022-07-17)

 - Add support for the ``persistent-id`` (Richard Hughes)
 - Allow adding deps such as the compiler version (Richard Hughes)
 - Allow importing SWID data from pkg-config files (Richard Hughes)
 - Change ``fn`` -> ``filepath`` for clarity/readability (Maximilian Brune)
 - Read compressed uSWID flags correctly (Richard Hughes)

**0.3.1** (2022-05-10)

 - Add a lang and version_scheme attributes to uSwidIdentity (Richard Hughes)
 - Add binary/CBOR representation for version-scheme (CodingVoid)
 - Add compliance to one-or-more CDDL rule in CoSWID (CodingVoid)
 - Add lang to CBOR export (CodingVoid)
 - Allow exporting SWID to JSON format (Richard Hughes)
 - Change ``SOFTWARE_NAME`` to ``ENTITY_NAME`` (Maximilian Brune)
 - Import ``LINK`` objects from the CBOR data (Richard Hughes)
 - Load the CBOR tag as GUID if required (Richard Hughes)

**0.3.0** (2022-04-19)

 - Add import from arbitrary binary blobs (CodingVoid)
 - Add some text describing the uSWID header (Richard Hughes)
 - Find and load multiple external data sections (Richard Hughes)
 - Make uSWID a container that can hold multiple compressed coSWID blobs (Richard Hughes)
 - Make uSwidContainer iterable (Richard Hughes)
 - Never add a ``.sbom`` section using pefile (Richard Hughes)
 - Replace manual search with str.find() (CodingVoid)

**0.2.0** (2022-03-18)

- Initial release
