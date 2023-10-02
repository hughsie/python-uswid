#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: GPL-2.0+


class NotSupportedError(NotImplementedError):
    """Error for when an operation is not supported by the format"""
