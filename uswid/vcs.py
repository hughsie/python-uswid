#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent

import os
import sys
import subprocess
from typing import Optional, List, Tuple

from .enums import uSwidVersionScheme


def _is_valid_author(author: str) -> bool:

    for token in ["@", "dependabot", "[bot]", "\\"]:
        if author.find(token) != -1:
            return False
    return True


def _filter_lines(lines: str, threshold: int) -> List[str]:

    authors: List[str] = []
    authors_tmp: List[Tuple[int, str]] = []
    for line in lines.split("\n"):
        try:
            cnt_as_str, author = line.split("\t")
            for extra in [" via groups.io"]:
                author = author.replace(extra, "")
            authors_tmp.append((int(cnt_as_str), author))
        except ValueError:
            pass
    total: int = 0
    for cnt, author in authors_tmp:
        total += cnt
    for cnt, author in authors_tmp:
        if not _is_valid_author(author):
            continue
        if cnt > threshold or (100 / total) * cnt > threshold:
            authors.append(author)
    return authors


def _part_to_semver(part: str) -> str:

    semver: str = ""
    for char in part:
        if char in [".", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]:
            semver += char
    return semver


def _convert_to_semver(version: str) -> str:

    semver_best: str = ""
    for part in version.split("-"):
        semver: str = _part_to_semver(part)
        if len(semver) > len(semver_best):
            semver_best = semver
    return semver_best


class uSwidVcs:
    """Version control system"""

    def __init__(self, filepath: str, dirpath: Optional[str] = None) -> None:
        """Initializes the VCS object"""
        self.filepath: str = filepath
        self.dirpath: str = dirpath if dirpath else os.path.dirname(self.filepath)

    def get_tag(self) -> str:

        """Gets the last tag, e.g. `3.6.0`"""
        try:
            p = subprocess.run(
                ["git", "describe", "--tags", "--abbrev=0"],
                capture_output=True,
                cwd=self.dirpath,
                check=True,
            )
            return _convert_to_semver(p.stdout.decode().strip())
        except subprocess.CalledProcessError:
            return "NOASSERTION"

    def get_version(self) -> str:

        """Gets the detailed version, e.g. `v3.6.0-1672-gfe4b02cc69`"""
        try:
            p = subprocess.run(
                ["git", "describe", "--tags"],
                capture_output=True,
                cwd=self.dirpath,
                check=True,
            )

            # remove the very common v${semver} prefix
            version = p.stdout.decode().strip()
            if version.startswith("v") and uSwidVersionScheme.from_version(
                version[1:]
            ) in [uSwidVersionScheme.SEMVER, uSwidVersionScheme.DECIMAL]:
                version = version[1:]

            return version
        except subprocess.CalledProcessError:
            return "NOASSERTION"

    def get_branch(self) -> str:

        """Gets the branch, e.g. `main`"""
        try:
            p = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                capture_output=True,
                cwd=self.dirpath,
                check=True,
            )
            return p.stdout.decode().strip()
        except subprocess.CalledProcessError:
            return "NOASSERTION"

    def get_commit(self) -> str:

        """Gets the last commit, e.g. `5e76fed40ad3e3081bd90e0da4a27e3463a4aee7`"""
        try:
            p = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                capture_output=True,
                cwd=self.dirpath,
                check=True,
            )
            return p.stdout.decode().strip()
        except subprocess.CalledProcessError:
            return "NOASSERTION"

    def get_toplevel(self) -> Optional[str]:

        """Gets the toplevel for the project"""
        try:
            p = subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                capture_output=True,
                cwd=self.dirpath,
                check=True,
            )
            return p.stdout.decode().strip()
        except subprocess.CalledProcessError:
            return None

    def get_remote_url(self) -> Optional[str]:

        """Gets the remote URL, e.g. `https://github.com/fwupd/fwupd.git`"""
        try:
            p = subprocess.run(
                ["git", "remote", "get-url", "origin"],
                capture_output=True,
                cwd=self.dirpath,
                check=True,
            )
            url: str = p.stdout.decode().strip()

            # remove the suffix
            if url.endswith(".git"):
                url = url[:-4]

            # convert ssh to http: git@github.com:fwupd/fwupd.git -> https://github.com/fwupd/fwupd.git
            if url.startswith("git@"):
                split: List[str] = url[4:].split(":", maxsplit=1)
                url = f"https://{split[0]}/{split[1]}"
            return url
        except subprocess.CalledProcessError:
            return None

    def get_sbom_authors(self, threshold: int = 10) -> List[str]:

        """Gets the list of SBOM authors"""
        authors: List[str] = []
        try:
            p = subprocess.run(
                [
                    "git",
                    "shortlog",
                    "HEAD",
                    "-n",
                    "-s",
                    os.path.basename(self.filepath),
                ],
                capture_output=True,
                cwd=os.path.dirname(self.filepath),
                check=True,
            )
            authors = _filter_lines(p.stdout.decode(errors="ignore"), threshold)
        except subprocess.CalledProcessError:
            pass
        if not authors:
            authors.append("NOASSERTION")
        return authors

    def get_authors(
        self, threshold: int = 5, relpath: Optional[str] = None
    ) -> List[str]:

        """Gets the list of project authors"""
        authors: List[str] = []
        try:
            argv = ["git", "shortlog", "HEAD", "-n", "-s"]
            if relpath:
                argv.append(relpath)
            p = subprocess.run(
                argv,
                capture_output=True,
                cwd=self.dirpath,
                check=True,
            )
            authors = _filter_lines(p.stdout.decode(errors="ignore"), threshold)
        except subprocess.CalledProcessError:
            pass
        if not authors:
            authors.append("NOASSERTION")
        return authors


if __name__ == "__main__":

    for _filepath in sys.argv[1:]:
        vcs = uSwidVcs(filepath=_filepath)
        print(f"VCS_TAG: {vcs.get_tag()}")
        print(f"VCS_VERSION: {vcs.get_version()}")
        print(f"VCS_BRANCH: {vcs.get_branch()}")
        print(f"VCS_COMMIT: {vcs.get_commit()}")
        print(f"VCS_SBOM_AUTHORS: {vcs.get_sbom_authors()}")
        print(f"VCS_AUTHORS: {vcs.get_authors()}")
