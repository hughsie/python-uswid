#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent

import os
import subprocess
from typing import Optional, List, Tuple


def _filter_lines(lines: str, threshold: int) -> List[str]:

    authors: List[str] = []
    authors_tmp: List[Tuple[int, str]] = []
    for line in lines.split("\n"):
        sections = line.split("\t")
        try:
            authors_tmp.append((int(sections[0]), sections[1]))
        except ValueError:
            pass
    total: int = 0
    for cnt, author in authors_tmp:
        total += cnt
    for cnt, author in authors_tmp:
        if (100 / total) * cnt > threshold:
            authors.append(author)
    return authors


class uSwidVcs:
    """Version control system"""

    def __init__(self, filepath: str, dirpath: Optional[str] = None) -> None:
        """Initializes the VCS object"""
        self.filepath: str = filepath
        self.dirpath: str = dirpath if dirpath else os.path.dirname(self.filepath)

    def get_tag(self) -> str:

        """Gets the last tag, e.g. `v3.6.0`"""
        try:
            p = subprocess.run(
                ["git", "describe", "--tags", "--abbrev=0"],
                capture_output=True,
                cwd=self.dirpath,
                check=True,
            )
            return p.stdout.decode().strip()
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
            return p.stdout.decode().strip()
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

    def get_authors(self, threshold: int = 5) -> List[str]:

        """Gets the list of project authors"""
        authors: List[str] = []
        try:
            p = subprocess.run(
                [
                    "git",
                    "shortlog",
                    "HEAD",
                    "-n",
                    "-s",
                ],
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
