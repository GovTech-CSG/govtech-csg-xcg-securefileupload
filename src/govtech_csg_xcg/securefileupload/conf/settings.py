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
import os
from pathlib import Path

from django.conf import settings

from ..utils import fill_missing_configs

DEFAULT_UPLOAD_CONFIG = {
    "quicksand": False,
    "file_size_limit": None,
    "filename_length_limit": None,
    "whitelist_name": "RESTRICTIVE",
    "whitelist": [],
    "sanitization": True,
    "keep_original_filename": False,
    "clamav": False,
    "yara_file_location": os.path.join(
        Path(os.path.realpath(__file__)).parent.parent.absolute(), "vendor/yara"
    ),
}

GLOBAL_UPLOAD_CONFIG = getattr(
    settings, "XCG_SECUREFILEUPLOAD_CONFIG", DEFAULT_UPLOAD_CONFIG
)
GLOBAL_UPLOAD_CONFIG = fill_missing_configs(GLOBAL_UPLOAD_CONFIG, DEFAULT_UPLOAD_CONFIG)
