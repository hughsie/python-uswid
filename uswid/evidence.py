#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2023 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=too-few-public-methods

from typing import Optional

from datetime import datetime


class uSwidEvidence:
    """Represents some SWID Evidence"""

    def __init__(
        self,
        date: Optional[datetime] = None,
        device_id: Optional[str] = None,
    ):
        """Initializes uSwidEvidence"""
        self.date: Optional[datetime] = date
        """Date and time when this evidence was collected """
        self.device_id: Optional[str] = device_id
        """Device ID, typically a machine hostname"""

    def __repr__(self) -> str:
        return f'uSwidEvidence(date="{self.date}",device_id={self.device_id})'
