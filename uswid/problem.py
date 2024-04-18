#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2023 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# pylint: disable=too-few-public-methods


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
