#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+

from uswid.link import uSwidLink, uSwidLinkRel
from uswid.identity import uSwidIdentity
from uswid.entity import uSwidEntity, uSwidEntityRole
from uswid.enums import uSwidGlobalMap, USWID_HEADER_MAGIC
from uswid.errors import NotSupportedError
