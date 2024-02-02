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
from io import BytesIO

import clamd

from govtech_csg_xcg.securefileupload import logger


def get_clamAV_results(file_object):
    logger.debug("[Validation module] - Running clamAV check")

    try:
        # Connects to UNIX socket on /var/run/clamav/clamd.ctl
        clam_daemon = clamd.ClamdUnixSocket()

        clamd_res = clam_daemon.instream(BytesIO(file_object.content))
        if clamd_res["stream"][0] == "FOUND":
            file_object.block = True
            file_object.validation_results.clamav_result_ok = False
            file_object.validation_results.clamav_result_detail = clamd_res["stream"][1]
    except Exception:
        logger.error("[Validation module] - clamAV: Cannot connect to clamAV service")


def validate_file(file):
    logger.debug("[Validation module] - Running antivirus check")
    get_clamAV_results(file)
