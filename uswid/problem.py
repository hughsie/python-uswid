#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2023 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# pylint: disable=too-few-public-methods

from typing import Optional


def _is_redacted(value: Optional[str]) -> bool:
    if not value:
        return False
    if value.find("REDACTED") != -1:
        return True
    if value.find("redacted") != -1:
        return True
    if value.find("NOVALUE") != -1:
        return True
    if value.find("no value") != -1:
        return True
    return False


class uSwidProblem:
    """Represents a SWID component problem"""

    def __init__(
        self,
        kind: str,
        description: str,
        since: str,
    ):
        self.kind = kind
        self.description = description
        self.since = since

    def __repr__(self) -> str:
        return (
            "uSwidProblem("
            + ", ".join(
                [
                    f"kind={self.kind}",
                    f'description="{self.description}"',
                    f'since="{self.since}")',
                ]
            )
            + ")"
        )
