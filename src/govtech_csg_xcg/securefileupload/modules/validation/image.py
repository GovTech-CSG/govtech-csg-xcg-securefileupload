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
import io

from PIL import Image as ImageP

from govtech_csg_xcg.securefileupload import logger


def check_integrity(file):
    logger.debug("[Validation module] - Starting image integrity check")

    try:
        image = ImageP.open(io.BytesIO(file.content))
        image.verify()
        image.close()
    except Exception as e:
        logger.error(f"[Validation module] - CHECK: Image integrity (1) - FAILED: {e}")
        return False

    try:
        image = ImageP.open(io.BytesIO(file.content))
        image.transpose(ImageP.FLIP_LEFT_RIGHT)
        image.close()
    except Exception as e:
        logger.error(f"[Validation module] - CHECK: Image integrity (2) - FAILED: {e}")
        return False

    logger.debug("[Validation module] - CHECK: Image integrity - PASSED")
    return True


def validate_file(file):
    logger.debug("[Validation module] - Starting image validation")

    file.validation_results.file_integrity_ok = check_integrity(file)
    file.validation_results.file_integrity_check_done = True

    logger.debug("[Validation module] - Validation: Image - DONE")
