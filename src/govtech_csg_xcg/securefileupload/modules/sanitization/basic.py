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
import mimetypes
import uuid

from govtech_csg_xcg.securefileupload import logger


def create_random_filename_with_guessed_extension(file):
    """change the file's name to an `uuid4` string"""
    logger.debug("[Sanitizer module] - Creating random file name")
    file_extension = mimetypes.guess_extension(file.detection_results.guessed_mime)
    unique_file_name = str(uuid.uuid4()) + file_extension
    file.name = unique_file_name


def sanitize_file(file, request):
    """apply basic sanitization"""
    logger.debug("[Sanitizer module] - Starting basic sanitization")

    if not request.upload_config["keep_original_filename"]:
        create_random_filename_with_guessed_extension(file)
        file.sanitization_results.created_random_filename_with_guessed_extension = True
