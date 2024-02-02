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
from govtech_csg_xcg.securefileupload import logger

from . import basic, pdf


def sanitize(file, request):
    """apply all sanitization"""
    logger.debug("[Sanitizer module] - Starting sanitization")

    # Perform basic file sanitization
    basic.sanitize_file(file, request)

    # Get guessed file type
    file_type = file.detection_results.guessed_mime

    # Perform file type specific sanitization
    if file_type == "application/pdf":
        pdf.sanitize_file(file)
    else:
        pass
