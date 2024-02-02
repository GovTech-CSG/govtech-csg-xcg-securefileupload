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

try:
    import yara  # noqa: F401
    from quicksand.quicksand import quicksand

except ImportError:
    quicksand = None


def perform_quicksand_scan(file):
    if quicksand is not None:
        logger.debug("[Validation module] - Running Quicksand")

        qs = quicksand(file.content, timeout=18, strings=True)
        qs.process()

        if qs.results["rating"] > 1:
            file.block = True
            file.validation_results.quicksand_result_ok = False
            file.append_block_reason("QS_detection")
            file.validation_results.quicksand_result_detail = qs.results["risk"]
            logger.warning(
                f"{file.basic_information.name} [Validation module] - Blocking file: Quicksand detection"
            )

    else:
        logger.info(
            "[Validation module] - Skipping Quicksand analysis as Quicksand library is not installed"
        )


def validate_file(file):
    logger.debug("[Validation module] - Starting Quicksand")

    perform_quicksand_scan(file)
