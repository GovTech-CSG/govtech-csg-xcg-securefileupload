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

from . import antivirus, basic, image, quicksand


def validate(file, upload_config):
    logger.debug("[Validation module] - Starting validation")

    # Perform basic file validation
    basic.validate_file(file, upload_config)

    if not file.block:
        file_type = file.detection_results.guessed_mime

        # Perform file type specific validation
        if file_type.startswith("image"):
            image.validate_file(file)

    if not file.block and upload_config["quicksand"]:
        # Perform quicksand scan
        quicksand.validate_file(file)
    if not file.block and upload_config["clamav"]:
        antivirus.validate_file(file)

    logger.debug(
        f"[Validation module] - Current block status: {file.block} => {file.block_reasons}"
    )
