# ------------------------------------------------------------------------
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# This file incorporates work covered by the following copyright:
#
# Copyright (c) 2024 Agency for Science, Technology and Research (A*STAR).
#   All rights reserved.
# Copyright (c) 2024 Government Technology Agency (GovTech).
#   All rights reserved.
# ------------------------------------------------------------------------
from django.core.exceptions import ValidationError

from .modules.helper import get_current_request


def xcg_file_validator(value):
    request = get_current_request()

    if request.block_upload:
        raise ValidationError(
            request.upload_errmsg,
            code="dmf",
        )
