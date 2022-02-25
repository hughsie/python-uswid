#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+

from enum import IntEnum


class uSwidGlobalMap(IntEnum):
    TAG_ID = 0
    SOFTWARE_NAME = 1
    ENTITY = 2
    EVIDENCE = 3
    LINK = 4
    SOFTWARE_META = 5
    PAYLOAD = 6
    HASH = 7
    CORPUS = 8
    PATCH = 9
    MEDIA = 10
    SUPPLEMENTAL = 11
    TAG_VERSION = 12
    SOFTWARE_VERSION = 13
    VERSION_SCHEME = 14
    LANG = 15
    DIRECTORY = 16
    FILE = 17
    PROCESS = 18
    RESOURCE = 19
    SIZE = 20
    FILE_VERSION = 21
    KEY = 22
    LOCATION = 23
    FS_NAME = 24
    ROOT = 25
    PATH_ELEMENTS = 26
    PROCESS_NAME = 27
    PID = 28
    TYPE = 29
    ENTITY_NAME = 31
    REG_ID = 32
    ROLE = 33
    THUMBPRINT = 34
    DATE = 35
    DEVICE_ID = 36
    ARTIFACT = 37
    HREF = 38
    OWNERSHIP = 39
    REL = 40
    MEDIA_TYPE = 41
    USE = 42
    ACTIVATION_STATUS = 43
    CHANNEL_TYPE = 44
    COLLOQUIAL_VERSION = 45
    DESCRIPTION = 46
    EDITION = 47
    ENTITLEMENT_DATA_REQUIRED = 48
    ENTITLEMENT_KEY = 49
    GENERATOR = 50
    PERSISTENT_ID = 51
    PRODUCT = 52
    PRODUCT_FAMILY = 53
    REVISION = 54
    SUMMARY = 55
    UNSPSC_CODE = 56
    UNSPSC_VERSION = 57


USWID_HEADER_MAGIC = b"\x53\x42\x4F\x4D\xD6\xBA\x2E\xAC\xA3\xE6\x7A\x52\xAA\xEE\x3B\xAF"
USWID_HEADER_VERSION = 1
USWID_HEADER_SIZE = 23
