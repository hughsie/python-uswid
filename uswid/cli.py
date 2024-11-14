#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# pylint: disable=wrong-import-position,too-many-locals,too-many-statements

from enum import IntEnum
from collections import defaultdict
from random import choices, randrange
from datetime import datetime
from typing import Optional, Any, List, Dict, Tuple
import argparse
import tempfile
import subprocess
import socket
import json

import os
import sys
import shutil
import uuid
import string

from importlib import metadata as importlib_metadata
from importlib.metadata import PackageNotFoundError

import pefile

sys.path.append(os.path.realpath("."))

from uswid import (
    NotSupportedError,
    uSwidContainer,
    uSwidEntity,
    uSwidEntityRole,
    uSwidComponent,
    uSwidProblem,
    uSwidVersionScheme,
    uSwidPayloadCompression,
    uSwidLink,
    uSwidLinkRel,
    uSwidLinkUse,
)
from uswid.format import uSwidFormatBase
from uswid.format_coswid import uSwidFormatCoswid
from uswid.format_ini import uSwidFormatIni
from uswid.format_goswid import uSwidFormatGoswid
from uswid.format_pkgconfig import uSwidFormatPkgconfig
from uswid.format_swid import uSwidFormatSwid
from uswid.format_uswid import uSwidFormatUswid
from uswid.format_cyclonedx import uSwidFormatCycloneDX
from uswid.format_spdx import uSwidFormatSpdx
from uswid.vex_document import uSwidVexDocument


def _adjust_SectionSize(sz, align):
    if sz % align:
        sz = ((sz + align) // align) * align
    return sz


def _pe_get_section_by_name(pe: pefile.PE, name: str) -> pefile.SectionStructure:
    for sect in pe.sections:
        if sect.Name == name.encode().ljust(8, b"\0"):
            return sect
    return None


def _load_efi_pefile(filepath: str) -> uSwidContainer:
    """read EFI file using pefile"""
    pe = pefile.PE(filepath)
    sect = _pe_get_section_by_name(pe, ".sbom")
    if not sect:
        raise NotSupportedError("PE files have to have an linker-defined .sbom section")
    return uSwidFormatCoswid().load(sect.get_data())


def _load_efi_objcopy(filepath: str, objcopy: str) -> uSwidContainer:
    """read EFI file using objcopy"""
    objcopy_full = shutil.which(objcopy)
    if not objcopy_full:
        print(f"executable {objcopy} not found")
        sys.exit(1)
    with tempfile.NamedTemporaryFile(
        mode="w+b", prefix="objcopy_", suffix=".bin", delete=True
    ) as dst:
        try:
            # pylint: disable=unexpected-keyword-arg
            subprocess.check_output(
                [
                    objcopy_full,
                    "-O",
                    "binary",
                    "--only-section=.sbom",
                    filepath,
                    dst.name,
                ],
                stderr=subprocess.PIPE,
            )
        except subprocess.CalledProcessError as e:
            print(e)
            sys.exit(1)
        return uSwidFormatCoswid().load(dst.read())


def _save_efi_pefile(component: uSwidComponent, filepath: str) -> None:
    """modify EFI file using pefile"""

    blob = uSwidFormatCoswid().save(uSwidContainer([component]))
    pe = pefile.PE(filepath)
    sect = _pe_get_section_by_name(pe, ".sbom")
    if not sect:
        raise NotSupportedError("PE files have to have an linker-defined .sbom section")

    # can we squeeze the new uSWID blob into the existing space
    sect.Misc = len(blob)
    if len(blob) <= sect.SizeOfRawData:
        pe.set_bytes_at_offset(sect.PointerToRawData, blob)

    # save
    pe.write(filepath)


def _save_efi_objcopy(
    component: uSwidComponent,
    filepath: str,
    cc: Optional[str],
    cflags: str,
    objcopy: str,
) -> None:
    """modify EFI file using objcopy"""
    objcopy_full = shutil.which(objcopy)
    if not objcopy_full:
        print(f"executable {objcopy} not found")
        sys.exit(1)
    if not os.path.exists(filepath):
        if not cc:
            raise NotSupportedError("compiler is required for missing section")
        subprocess.run(
            [cc, "-x", "c", "-c", "-o", filepath, "/dev/null"] + cflags.split(" "),
            check=True,
        )

    # save to file?
    try:
        blob = uSwidFormatIni().save(uSwidContainer([component]))
    except NotSupportedError as e:
        print(e)
        sys.exit(1)

    with tempfile.NamedTemporaryFile(
        mode="wb", prefix="objcopy_", suffix=".bin", delete=True
    ) as src:
        src.write(blob)
        src.flush()
        try:
            # pylint: disable=unexpected-keyword-arg
            subprocess.check_output(
                [
                    objcopy_full,
                    "--remove-section=.sbom",
                    "--add-section",
                    f".sbom={src.name}",
                    "--set-section-flags",
                    ".sbom=contents,alloc,load,readonly,data",
                    filepath,
                ]
            )
        except subprocess.CalledProcessError as e:
            print(e)
            sys.exit(1)


class SwidFormat(IntEnum):
    """Detected file format"""

    UNKNOWN = 0
    INI = 1
    XML = 2
    USWID = 3
    PE = 4
    JSON = 5
    PKG_CONFIG = 6
    COSWID = 7
    CYCLONE_DX = 8
    SPDX = 9
    VEX = 10


def _detect_format(filepath: str) -> SwidFormat:
    if os.path.basename(filepath).endswith("bom.json"):
        return SwidFormat.CYCLONE_DX
    if os.path.basename(filepath).endswith("spdx.json"):
        return SwidFormat.SPDX
    ext = filepath.rsplit(".", maxsplit=1)[-1].lower()
    if ext in ["exe", "efi", "o"]:
        return SwidFormat.PE
    if ext in ["uswid", "raw", "bin"]:
        return SwidFormat.USWID
    if ext in ["coswid", "cbor"]:
        return SwidFormat.COSWID
    if ext == "ini":
        return SwidFormat.INI
    if ext == "xml":
        return SwidFormat.XML
    if ext == "json":
        return SwidFormat.JSON
    if ext == "pc":
        return SwidFormat.PKG_CONFIG
    if ext == "vex":
        return SwidFormat.VEX
    return SwidFormat.UNKNOWN


def _type_for_fmt(
    fmt: SwidFormat, args: Any, filepath: Optional[str] = None
) -> Optional[Any]:
    if fmt == SwidFormat.INI:
        return uSwidFormatIni()
    if fmt == SwidFormat.COSWID:
        return uSwidFormatCoswid()
    if fmt == SwidFormat.JSON:
        return uSwidFormatGoswid()
    if fmt == SwidFormat.XML:
        return uSwidFormatSwid()
    if fmt == SwidFormat.CYCLONE_DX:
        return uSwidFormatCycloneDX()
    if fmt == SwidFormat.SPDX:
        return uSwidFormatSpdx()
    if fmt == SwidFormat.PKG_CONFIG:
        return uSwidFormatPkgconfig(filepath=filepath)
    if fmt == SwidFormat.USWID:
        return uSwidFormatUswid(compression=args.compression)  # type: ignore
    return None


def _get_vcs_tag(filepath: str) -> Optional[str]:

    try:
        p = subprocess.run(
            ["git", "describe", "--tags", "--abbrev=0"],
            capture_output=True,
            cwd=os.path.dirname(filepath),
            check=True,
        )
        return p.stdout.decode().strip()
    except subprocess.CalledProcessError:
        return "NOASSERTION"


def _get_vcs_version(filepath: str) -> str:

    try:
        p = subprocess.run(
            ["git", "describe", "--tags"],
            capture_output=True,
            cwd=os.path.dirname(filepath),
            check=True,
        )
        return p.stdout.decode().strip()
    except subprocess.CalledProcessError:
        return "NOASSERTION"


def _get_vcs_branch(filepath: str) -> str:

    try:
        p = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            cwd=os.path.dirname(filepath),
            check=True,
        )
        return p.stdout.decode().strip()
    except subprocess.CalledProcessError:
        return "NOASSERTION"


def _get_vcs_commit(filepath: str) -> str:

    try:
        p = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            cwd=os.path.dirname(filepath),
            check=True,
        )
        return p.stdout.decode().strip()
    except subprocess.CalledProcessError:
        return "NOASSERTION"


def _get_vcs_toplevel(filepath: str) -> Optional[str]:

    try:
        p = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            cwd=os.path.dirname(filepath),
            check=True,
        )
        return p.stdout.decode().strip()
    except subprocess.CalledProcessError:
        return None


def _get_vcs_file_authors(filepath: str, theshold: int = 10) -> List[str]:

    authors: List[str] = []
    try:
        p = subprocess.run(
            ["git", "shortlog", "HEAD", "-n", "-s", os.path.basename(filepath)],
            capture_output=True,
            cwd=os.path.dirname(filepath),
            check=True,
        )
        authors_tmp: List[Tuple[int, str]] = []
        for line in p.stdout.decode().split("\n"):
            sections = line.split("\t")
            try:
                authors_tmp.append((int(sections[0]), sections[1]))
            except ValueError:
                pass
        total: int = 0
        for cnt, author in authors_tmp:
            total += cnt
        for cnt, author in authors_tmp:
            if (100 / total) * cnt > theshold:
                authors.append(author)
    except subprocess.CalledProcessError:
        pass
    if not authors:
        authors.append("NOASSERTION")
    return authors


def _container_merge_from_filepath(
    container: uSwidContainer,
    base: uSwidFormatBase,
    filepath: str,
    fixup: bool = False,
) -> None:
    with open(filepath, "rb") as f:
        blob: bytes = f.read()
    try:
        text: str = blob.decode()
        replacements: Dict[str, str] = {}

        # substitute some keys with the discovered values
        for key in [
            "@VCS_TAG@",
            "@VCS_VERSION@",
            "@VCS_BRANCH@",
            "@VCS_BRANCH@",
            "@VCS_COMMIT@",
            "@VCS_SBOM_AUTHORS@",
            "@VCS_SBOM_AUTHOR@",
        ]:
            if text.find(key) != -1:
                replacements[key] = "NOASSERTION"
        if "@VCS_TAG@" in replacements:
            replacements["@VCS_TAG@"] = _get_vcs_tag(filepath)
        if "@VCS_VERSION@" in replacements:
            replacements["@VCS_VERSION@"] = _get_vcs_version(filepath)
        if "@VCS_BRANCH@" in replacements:
            replacements["@VCS_BRANCH@"] = _get_vcs_branch(filepath)
        if "@VCS_COMMIT@" in replacements:
            replacements["@VCS_COMMIT@"] = _get_vcs_commit(filepath)
        if "@VCS_SBOM_AUTHORS@" in replacements:
            replacements["@VCS_SBOM_AUTHORS@"] = ", ".join(
                _get_vcs_file_authors(filepath)
            )
        if "@VCS_SBOM_AUTHOR@" in replacements:
            replacements["@VCS_SBOM_AUTHOR@"] = _get_vcs_file_authors(filepath)[0]

        # do substitutions
        if replacements:
            if base.verbose:
                print(f"Substitution required in {filepath}:")
            for key, value in replacements.items():
                if base.verbose:
                    print(f" - {key} → {value}")
                text = text.replace(key, value)
            blob = text.encode()
    except UnicodeDecodeError:
        pass
    for component in base.load(blob, path=os.path.dirname(filepath)):

        # guess something sane
        if fixup:
            fixup_strs: List[str] = []
            if not component.software_version:
                component.version_scheme = uSwidVersionScheme.ALPHANUMERIC
                component.software_version = _get_vcs_version(filepath)
                if base.verbose:
                    fixup_strs.append(f"Add VCS version → {component.software_version}")
            if not component.colloquial_version:
                component.colloquial_version = _get_vcs_commit(filepath)
                if base.verbose:
                    fixup_strs.append(
                        f"Add VCS commit → {component.colloquial_version}"
                    )
            if not component.get_entity_by_role(uSwidEntityRole.TAG_CREATOR):
                entity: uSwidEntity = uSwidEntity(
                    name=", ".join(_get_vcs_file_authors(filepath)),
                    roles=[uSwidEntityRole.TAG_CREATOR],
                )
                component.add_entity(entity)
                if base.verbose:
                    fixup_strs.append(f"Add VCS author → {entity.name}")
            if fixup_strs:
                print(f"Fixup required in {filepath}:")
                for fixup_str in fixup_strs:
                    print(f" - {fixup_str}")

            # get the toplevel so that we can auto-add deps
            component.source_dir = _get_vcs_toplevel(filepath)

        component_new = container.merge(component)
        if component_new:
            print(
                "{} was merged into existing component {}".format(
                    filepath, component_new.tag_id
                )
            )


def _roundtrip(container: uSwidContainer, verbose: bool = False) -> None:

    # collect for analysis
    try:
        component: uSwidComponent = container[0]
    except IndexError:
        print("no default component")
        return

    # convert to each format and back again
    for base in [
        uSwidFormatCoswid(),
        uSwidFormatIni(),
        uSwidFormatCycloneDX(),
        uSwidFormatGoswid(),
        uSwidFormatPkgconfig(),
        uSwidFormatSpdx(),
        uSwidFormatSwid(),
        uSwidFormatUswid(),
    ]:

        # proxy
        base.verbose = verbose

        # save
        try:
            blob: bytes = base.save(container)
        except NotImplementedError:
            continue

        # load
        try:
            container_new = base.load(blob)
        except NotImplementedError:
            continue
        try:
            component_new = container_new[0]
        except IndexError:
            print(f"no default component for {base.name}")
            continue

        # compare the old and the new
        differences: List[Dict[str, Any]] = []
        for key in [
            "tag_id",
            "tag_version",
            "type",
            "software_name",
            "software_version",
            "version_scheme",
            "summary",
            "product",
            "colloquial_version",
            "revision",
            "edition",
            "persistent_id",
            "cpe",
        ]:
            if getattr(component, key) != getattr(component_new, key):
                differences.append(
                    {
                        "class": "uSwidComponent",
                        "property": key,
                        "old": getattr(component, key),
                        "new": getattr(component_new, key),
                    }
                )

        # payloads
        for payload in component.payloads:

            # check still exists
            payload_new = component_new.get_payload_by_name(payload.name)
            if not payload_new:
                differences.append(
                    {
                        "class": "uSwidPayload",
                        "name": payload.name,
                    }
                )
                continue

            # check values
            for key in [
                "name",
                "size",
            ]:
                if getattr(payload, key) != getattr(payload_new, key):
                    differences.append(
                        {
                            "class": "uSwidPayload",
                            "property": key,
                            "old": getattr(payload, key),
                            "new": getattr(payload_new, key),
                        }
                    )

        # entities
        for entity in component.entities:

            # check still exists
            for role in entity.roles:
                entity_new = component_new.get_entity_by_role(role)
                if not entity_new:
                    differences.append(
                        {
                            "class": "uSwidEntity",
                            "name": role,
                        }
                    )
                    continue

                # check values
                for key in [
                    "name",
                    "regid",
                ]:
                    if getattr(entity, key) != getattr(entity_new, key):
                        differences.append(
                            {
                                "class": "uSwidEntity",
                                "property": key,
                                "old": getattr(entity, key),
                                "new": getattr(entity_new, key),
                            }
                        )

        # link
        for link in component.links:
            # check still exists
            link_new = component_new.get_link_by_rel(link.rel)
            if not link_new:
                differences.append(
                    {
                        "class": "uSwidLink",
                        "name": link.rel,
                    }
                )
                continue

            # check values
            for key in [
                "href",
                "rel",
            ]:
                if getattr(link, key) != getattr(link_new, key):
                    differences.append(
                        {
                            "class": "uSwidLink",
                            "property": key,
                            "old": getattr(link, key),
                            "new": getattr(link_new, key),
                        }
                    )

        # evidence
        for evidence in component.evidences:
            # check still exists
            evidence_new = component_new.get_evidence_by_rel(evidence.rel)
            if not evidence_new:
                differences.append(
                    {
                        "class": "uSwidEvidence",
                        "name": evidence.rel,
                    }
                )
                continue

            # check values
            for key in [
                "date",
                "device_id",
            ]:
                if getattr(evidence, key) != getattr(evidence_new, key):
                    differences.append(
                        {
                            "class": "uSwidEvidence",
                            "property": key,
                            "old": getattr(evidence, key),
                            "new": getattr(evidence_new, key),
                        }
                    )

        # show differences
        total: float = 22
        print(f"{base.name}: { 100.0 / float(total) * (total - len(differences)):.0f}%")
        for dif in differences:
            try:
                print(
                    f"  - FAILURE {dif['class']}.{dif['property']}: {dif['old']}->{dif['new']}"
                )
            except KeyError:
                print(f"  - FAILURE {dif['class']} [{dif['name']}] -> None")


def main():
    """Main entrypoint"""
    parser = argparse.ArgumentParser(
        prog="uswid", description="Generate CoSWID metadata"
    )
    try:
        parser.add_argument(
            "--version",
            action="version",
            version="%(prog)s " + importlib_metadata.version("uswid"),
        )
    except PackageNotFoundError:
        pass
    parser.add_argument("--cc", default="gcc", help="Compiler to use for empty object")
    parser.add_argument(
        "--cflags", default="", help="C compiler flags to be used by CC"
    )
    parser.add_argument("--binfile", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--rawfile", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--inifile", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--xmlfile", default=None, help=argparse.SUPPRESS)
    parser.add_argument(
        "--objcopy", default=None, help="Binary file to use for objcopy"
    )
    parser.add_argument(
        "--find",
        nargs="+",
        help="directory to scan, e.g. ~/Code/firmware",
    )
    parser.add_argument(
        "--load",
        nargs="+",
        help="file to import, .efi,.ini,.uswid,.xml,.json",
    )
    parser.add_argument(
        "--save",
        default=None,
        action="append",
        help="file to export, .efi,.ini,.uswid,.xml,.json",
    )
    parser.add_argument(
        "--compress",
        dest="compress",
        default=False,
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--compression",
        type=uSwidPayloadCompression.argparse,
        choices=list(uSwidPayloadCompression),
        dest="compression",
        default=uSwidPayloadCompression.NONE,
        help="Compress uSWID containers",
    )
    parser.add_argument(
        "--generate",
        dest="generate",
        default=False,
        action="store_true",
        help="Generate plausible SWID entries",
    )
    parser.add_argument(
        "--roundtrip",
        dest="roundtrip",
        default=False,
        action="store_true",
        help="Test various different formats from loaded data",
    )
    parser.add_argument(
        "--fixup",
        dest="fixup",
        default=False,
        action="store_true",
        help="Fix components with missing VCS data",
    )
    parser.add_argument(
        "--validate",
        dest="validate",
        default=False,
        action="store_true",
        help="Validate SWID entries",
    )
    parser.add_argument(
        "--verbose",
        dest="verbose",
        default=False,
        action="store_true",
        help="Show verbose operation",
    )
    args = parser.parse_args()
    load_filepaths = args.load
    if not load_filepaths:
        load_filepaths = []
    save_filepaths = args.save if args.save else []

    # search recursively
    if args.find:
        sbom_filenames = ["spdx.json", "swid.xml", "bom.json", "bom.coswid", "sbom.ini"]
        for path in args.find:
            for dirpath, _, fns in os.walk(path):
                for fn in fns:
                    if fn in sbom_filenames:
                        load_filepaths.append(os.path.join(dirpath, fn))
        if args.verbose and load_filepaths:
            print("Found:")
            for filepath in load_filepaths:
                print(f" - {filepath}")

    # handle deprecated --compress
    if args.compress:
        print("WARNING: --compress is deprecated, please use --compression instead")
        args.compression = uSwidPayloadCompression.ZLIB

    # deprecated arguments
    if args.binfile:
        load_filepaths.append(args.binfile)
        save_filepaths.append(args.binfile)
    if args.rawfile:
        save_filepaths.append(args.rawfile)
    if args.xmlfile:
        load_filepaths.append(args.xmlfile)

    # sanity check
    if not load_filepaths and not save_filepaths:
        print("Use uswid --help for command line arguments")
        sys.exit(1)

    # always load into a temporary component so that we can query the tag_id
    container = uSwidContainer()

    # generate 1000 plausible components, each with:
    # - unique tag-id GUID
    # - unique software-name of size 4-30 chars
    # - colloquial-version from a random selection of 10 SHA-1 hashes
    # - edition from a random SHA-1 hash
    # - semantic version of size 3-8 chars
    # - entity from a random selection of 10 entities
    if args.generate:
        tree_hashes: List[str] = []
        entities: List[uSwidEntity] = []
        for _ in range(10):
            tree_hashes.append("".join(choices("0123456789abcdef", k=40)))
        for i in range(10):
            entity = uSwidEntity()
            entity.name = "Entity#" + str(i)
            entity.regid = "com.entity" + str(i)
            entity.roles = [uSwidEntityRole.TAG_CREATOR]
            entities.append(entity)
        for i in range(1000):
            component = uSwidComponent()
            component.tag_id = str(uuid.uuid4())
            component.software_name = "".join(
                choices(string.ascii_lowercase, k=randrange(4, 30))
            )
            component.software_version = "1." + "".join(
                choices("123456789", k=randrange(1, 6))
            )
            component.colloquial_version = tree_hashes[randrange(len(tree_hashes))]
            component.edition = "".join(choices("0123456789abcdef", k=40))
            component.version_scheme = uSwidVersionScheme.MULTIPARTNUMERIC
            component.add_entity(entities[randrange(len(entities))])
            container.append(component)

    # collect data here
    for filepath in load_filepaths:
        try:
            fmt = _detect_format(filepath)
            if fmt == SwidFormat.UNKNOWN:
                print(f"{filepath} has unknown extension, using uSWID")
                fmt = SwidFormat.USWID
            if fmt == SwidFormat.PE:
                if args.objcopy:
                    container_tmp = _load_efi_objcopy(filepath, objcopy=args.objcopy)
                else:
                    container_tmp = _load_efi_pefile(filepath)
                for component in container_tmp:
                    component_new = container.merge(component)
                    if component_new:
                        print(
                            "{} was merged into existing component {}".format(
                                filepath, component_new.tag_id
                            )
                        )
            elif fmt == SwidFormat.VEX:
                with open(filepath, "rb") as f:
                    container.add_vex_document(
                        uSwidVexDocument(json.loads(f.read().decode()))
                    )
            elif fmt in [
                SwidFormat.INI,
                SwidFormat.JSON,
                SwidFormat.COSWID,
                SwidFormat.USWID,
                SwidFormat.XML,
                SwidFormat.SPDX,
                SwidFormat.CYCLONE_DX,
                SwidFormat.PKG_CONFIG,
            ]:
                base = _type_for_fmt(fmt, args, filepath=filepath)
                base.verbose = args.verbose
                if not base:
                    print(f"{fmt} no type for format")
                    sys.exit(1)
                _container_merge_from_filepath(
                    container, base, filepath, fixup=args.fixup
                )
            else:
                print(f"{filepath} has unknown format, ignoring")
        except FileNotFoundError:
            print(f"{filepath} does not exist")
            sys.exit(1)
        except NotSupportedError as e:
            print(e)
            sys.exit(1)

    # auto-add deps using the top-level project paths
    if args.fixup:

        fixup_strs: List[str] = []

        # order by length
        components = list(container)
        components.sort(key=lambda s: -len(s.source_dir))
        for component in components:
            if component.get_link_by_rel(uSwidLinkRel.COMPONENT):
                continue
            for component2 in components:
                if component.source_dir == component2.source_dir:
                    continue
                if component.source_dir.find(component2.source_dir) != -1:
                    fixup_strs.append(f"{component2.tag_id} → {component.tag_id}")
                    component2.add_link(
                        uSwidLink(
                            rel="component",
                            href=component.tag_id,
                            use=uSwidLinkUse.REQUIRED,
                        )
                    )
                    break
        if fixup_strs:
            print("Additional dependencies added:")
            for fixup_str in fixup_strs:
                print(f" - {fixup_str}")

    # depsolve any internal SWID links
    container.depsolve()

    # validate
    rc: int = 0
    if args.validate:
        problems_dict: dict[Optional[uSwidComponent], List[uSwidProblem]] = defaultdict(
            list
        )
        if len(container) == 0:
            problems_dict[None] += [
                uSwidProblem("all", "There are no defined components", since="0.4.7")
            ]
        for component in container:
            problems = component.problems()
            if problems:
                problems_dict[component].extend(problems)
        if problems_dict:
            rc = 2
            print("Validation problems:")
            for opt_component, problems in problems_dict.items():
                for problem in problems:
                    key: str = "*"
                    if opt_component and opt_component.tag_id:
                        key = opt_component.tag_id
                    print(
                        f"{key.ljust(40)} {problem.kind.rjust(10)}: "
                        f"{problem.description} (uSWID >= v{problem.since})"
                    )

    # test the container with different SBOM formats
    if args.roundtrip:
        _roundtrip(container, verbose=args.verbose)

    # add any missing evidence
    for component in container:
        for evidence in component.evidences:
            if not evidence.date and not evidence.device_id:
                evidence.date = datetime.now()
                evidence.device_id = socket.getfqdn()

    # debug
    if load_filepaths and args.verbose:
        print("Loaded:")
        for component in container:
            print(f"{component}")

    # optional save
    if save_filepaths and args.verbose:
        print("Saving:")
        for component in container:
            print(f"{component}")
    for filepath in save_filepaths:
        try:
            fmt = _detect_format(filepath)
            if fmt == SwidFormat.PE:
                component_pe: Optional[uSwidComponent] = container.get_default()
                if not component_pe:
                    print("cannot save PE when no default component")
                    sys.exit(1)
                if args.objcopy:
                    _save_efi_objcopy(
                        component_pe, filepath, args.cc, args.cflags, args.objcopy
                    )
                else:
                    _save_efi_pefile(component_pe, filepath)
            elif fmt in [
                SwidFormat.INI,
                SwidFormat.COSWID,
                SwidFormat.JSON,
                SwidFormat.XML,
                SwidFormat.USWID,
                SwidFormat.CYCLONE_DX,
                SwidFormat.SPDX,
            ]:
                base = _type_for_fmt(fmt, args)
                base.verbose = args.verbose
                if not base:
                    print(f"{fmt} no type for format")
                    sys.exit(1)
                blob = base.save(container)
                with open(filepath, "wb") as f:
                    f.write(blob)
            else:
                print(f"{filepath} extension is not supported")
                sys.exit(1)
        except NotSupportedError as e:
            print(e)
            sys.exit(1)

    # success
    sys.exit(rc)


if __name__ == "__main__":
    main()
